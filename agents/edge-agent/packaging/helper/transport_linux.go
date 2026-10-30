//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
	"golang.org/x/sys/unix"
)

const ancillaryBufferBytes = 256

type Listener struct {
	fd     int
	policy socketPolicy
}

type Exchange struct {
	Packet   []byte
	Request  protocol.Request
	Artifact *os.File
	Peer     PeerIdentity
	Context  context.Context

	fd     int
	cancel context.CancelFunc
}

type requestProtocolError struct {
	version int
	code    protocol.ErrorCode
}

func (err *requestProtocolError) Error() string {
	return string(err.code)
}

func (err *requestProtocolError) Unwrap() error {
	return &ProtocolError{Code: err.code}
}

func ListenerFromSystemd() (*Listener, error) {
	policy, err := productionPolicy()
	if err != nil {
		return nil, err
	}
	return listenerFromFD(SystemdListenerFD, policy)
}

func listenerFromFD(fd int, policy socketPolicy) (*Listener, error) {
	if err := validateSocketPath(policy); err != nil {
		return nil, err
	}
	typeValue, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeValue != unix.SOCK_SEQPACKET {
		return nil, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	accepting, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || accepting != 1 {
		return nil, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	address, err := unix.Getsockname(fd)
	unixAddress, ok := address.(*unix.SockaddrUnix)
	if err != nil || !ok || unixAddress.Name != policy.path {
		return nil, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	ownedFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, &ProtocolError{Code: protocol.ErrorInternal}
	}
	if err := unix.SetNonblock(ownedFD, true); err != nil {
		_ = unix.Close(ownedFD)
		return nil, &ProtocolError{Code: protocol.ErrorInternal}
	}
	return &Listener{fd: ownedFD, policy: policy}, nil
}

func (l *Listener) Close() error {
	if l == nil || l.fd < 0 {
		return nil
	}
	err := unix.Close(l.fd)
	l.fd = -1
	return err
}

func (l *Listener) Accept(ctx context.Context) (*Exchange, error) {
	if l == nil || l.fd < 0 {
		return nil, ErrTransportUnavailable
	}
	if err := waitFD(ctx, l.fd, unix.POLLIN); err != nil {
		return nil, err
	}
	fd, _, err := unix.Accept4(l.fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	if err != nil {
		return nil, err
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || !authorizedPeer(PeerIdentity{PID: peer.Pid, UID: peer.Uid, GID: peer.Gid}, l.policy) {
		_ = rejectAndClose(fd, protocol.ErrorUnauthorized)
		return nil, &ProtocolError{Code: protocol.ErrorUnauthorized}
	}
	exchange, err := receiveExchange(ctx, fd, PeerIdentity{PID: peer.Pid, UID: peer.Uid, GID: peer.Gid})
	if err != nil {
		code := protocol.ErrorProtocol
		version := protocol.Version
		if value, ok := ErrorCode(err); ok {
			code = value
		}
		var requestErr *requestProtocolError
		if errors.As(err, &requestErr) {
			version = requestErr.version
		}
		_ = rejectAndCloseVersion(fd, version, code)
		return nil, err
	}
	return exchange, nil
}

func (e *Exchange) Respond(ctx context.Context, response protocol.Response) error {
	if e == nil || e.fd < 0 {
		return ErrTransportUnavailable
	}
	packet, err := protocol.MarshalResponse(response)
	if err != nil {
		return err
	}
	deadlineCtx, cancel := boundedContext(ctx, protocol.OperationTimeout(e.Request.Operation))
	defer cancel()
	return sendPacket(deadlineCtx, e.fd, packet, nil)
}

func (e *Exchange) Close() error {
	if e == nil {
		return nil
	}
	var first error
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	if e.Artifact != nil {
		first = e.Artifact.Close()
		e.Artifact = nil
	}
	if e.fd >= 0 {
		if err := unix.Close(e.fd); first == nil {
			first = err
		}
		e.fd = -1
	}
	return first
}

func roundTrip(ctx context.Context, policy socketPolicy, request protocol.Request, artifact *os.File) (protocol.Response, error) {
	packet, err := protocol.MarshalRequest(request)
	if err != nil {
		return protocol.Response{}, err
	}
	if operationRequiresArtifact(request.Operation) && artifact == nil {
		return protocol.Response{}, &ProtocolError{Code: protocol.ErrorFDRequired}
	}
	if !operationRequiresArtifact(request.Operation) && artifact != nil {
		return protocol.Response{}, &ProtocolError{Code: protocol.ErrorFDForbidden}
	}
	if err := validateSocketPath(policy); err != nil {
		return protocol.Response{}, err
	}
	deadlineCtx, cancel := boundedContext(ctx, protocol.OperationTimeout(request.Operation))
	defer cancel()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return protocol.Response{}, err
	}
	defer unix.Close(fd)
	if err := connect(deadlineCtx, fd, policy.path); err != nil {
		return protocol.Response{}, err
	}
	var rights []byte
	if artifact != nil {
		rights = unix.UnixRights(int(artifact.Fd()))
	}
	if err := sendPacket(deadlineCtx, fd, packet, rights); err != nil {
		return protocol.Response{}, err
	}
	if err := unix.Shutdown(fd, unix.SHUT_WR); err != nil {
		return protocol.Response{}, err
	}
	responsePacket, control, flags, err := receivePacket(deadlineCtx, fd)
	if err != nil {
		return protocol.Response{}, err
	}
	if len(control) != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeRights(control)
		return protocol.Response{}, &ProtocolError{Code: protocol.ErrorProtocol}
	}
	response, err := protocol.ParseResponse(responsePacket)
	if err != nil {
		return protocol.Response{}, &ProtocolError{Code: protocol.ErrorProtocol}
	}
	if response.ProtocolVersion != request.ProtocolVersion {
		if response.ProtocolVersion == protocol.Version && !response.OK && response.ErrorCode == protocol.ErrorBadRequest {
			return protocol.Response{}, &LegacyNegotiationError{
				RequestVersion: request.ProtocolVersion, PeerVersion: response.ProtocolVersion, Code: response.ErrorCode,
			}
		}
		return protocol.Response{}, &ProtocolError{Code: protocol.ErrorProtocol}
	}
	if err := requirePeerClose(deadlineCtx, fd); err != nil {
		return protocol.Response{}, err
	}
	return response, nil
}

func receiveExchange(ctx context.Context, fd int, peer PeerIdentity) (*Exchange, error) {
	initialCtx, cancel := boundedContext(ctx, 5*time.Second)
	defer cancel()
	packet, control, flags, err := receivePacket(initialCtx, fd)
	if err != nil {
		return nil, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeRights(control)
		return nil, &ProtocolError{Code: protocol.ErrorProtocol}
	}
	descriptors, err := parseRights(control)
	if err != nil {
		closeRights(control)
		return nil, &ProtocolError{Code: protocol.ErrorProtocol}
	}
	request, err := protocol.ParseRequest(packet)
	if err != nil {
		closeDescriptors(descriptors)
		code := protocol.ErrorBadRequest
		if requestVersionFromPacket(packet) == protocol.JournalV4Version {
			code = protocol.ErrorProtocol
		}
		return nil, &ProtocolError{Code: code}
	}
	framingCtx, framingCancel := boundedContext(ctx, time.Second)
	defer framingCancel()
	if err := requireRequestEnd(framingCtx, fd); err != nil {
		closeDescriptors(descriptors)
		return nil, requestError(request.ProtocolVersion, protocol.ErrorProtocol)
	}
	if operationRequiresArtifact(request.Operation) {
		if len(descriptors) == 0 {
			return nil, requestError(request.ProtocolVersion, protocol.ErrorFDRequired)
		}
		if len(descriptors) != 1 {
			closeDescriptors(descriptors)
			return nil, requestError(request.ProtocolVersion, protocol.ErrorFDUnsafe)
		}
		artifact, code := validateArtifact(descriptors[0], request)
		if code != "" {
			return nil, requestError(request.ProtocolVersion, code)
		}
		operationCtx, cancel := boundedContext(ctx, protocol.OperationTimeout(request.Operation))
		return &Exchange{Packet: append([]byte(nil), packet...), Request: request, Artifact: artifact, Peer: peer, Context: operationCtx, fd: fd, cancel: cancel}, nil
	}
	if len(descriptors) != 0 {
		closeDescriptors(descriptors)
		return nil, requestError(request.ProtocolVersion, protocol.ErrorFDForbidden)
	}
	operationCtx, cancel := boundedContext(ctx, protocol.OperationTimeout(request.Operation))
	return &Exchange{Packet: append([]byte(nil), packet...), Request: request, Peer: peer, Context: operationCtx, fd: fd, cancel: cancel}, nil
}

func requestVersionFromPacket(packet []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(packet))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return 0
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return 0
		}
		if key == "protocol_version" {
			var version int
			if err := decoder.Decode(&version); err != nil {
				return 0
			}
			return version
		}
		if err := decoder.Decode(new(json.RawMessage)); err != nil {
			return 0
		}
	}
	return 0
}

func operationRequiresArtifact(operation protocol.Operation) bool {
	return operation == protocol.OperationInstall || operation == protocol.OperationPrepareInstall
}

func requestError(version int, code protocol.ErrorCode) error {
	return &requestProtocolError{version: version, code: code}
}

func validateArtifact(fd int, request protocol.Request) (result *os.File, code protocol.ErrorCode) {
	var file *os.File
	defer func() {
		if code == "" {
			return
		}
		if file != nil {
			runtime.SetFinalizer(file, nil)
			_ = file.Close()
			file = nil
			return
		}
		_ = unix.Close(fd)
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o222 != 0 || stat.Nlink != 1 {
		return nil, protocol.ErrorFDUnsafe
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return nil, protocol.ErrorFDUnsafe
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || uint64(fs.Type) == uint64(unix.PROC_SUPER_MAGIC) {
		return nil, protocol.ErrorFDUnsafe
	}
	if stat.Size <= 0 || stat.Size != request.ArtifactSize {
		return nil, protocol.ErrorArtifactMismatch
	}
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return nil, protocol.ErrorFDUnsafe
	}
	file = os.NewFile(uintptr(fd), "artifact")
	if file == nil {
		return nil, protocol.ErrorFDUnsafe
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size != request.ArtifactSize || hex.EncodeToString(hash.Sum(nil)) != request.ArtifactSHA256 {
		return nil, protocol.ErrorArtifactMismatch
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, protocol.ErrorFDUnsafe
	}
	return file, ""
}

func connect(ctx context.Context, fd int, path string) error {
	err := unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	if err == nil || errors.Is(err, unix.EISCONN) {
		return nil
	}
	if !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EAGAIN) {
		return err
	}
	if err := waitFD(ctx, fd, unix.POLLOUT); err != nil {
		return err
	}
	value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return err
	}
	if value != 0 {
		return unix.Errno(value)
	}
	return nil
}

func sendPacket(ctx context.Context, fd int, packet, control []byte) error {
	for {
		written, err := unix.SendmsgN(fd, packet, control, nil, unix.MSG_NOSIGNAL)
		if err == nil {
			if written != len(packet) {
				return &ProtocolError{Code: protocol.ErrorProtocol}
			}
			return nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if err := waitFD(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
	}
}

func receivePacket(ctx context.Context, fd int) ([]byte, []byte, int, error) {
	buffer := make([]byte, protocol.MaxPacketBytes)
	control := make([]byte, ancillaryBufferBytes)
	for {
		if err := waitFD(ctx, fd, unix.POLLIN); err != nil {
			return nil, nil, 0, err
		}
		count, controlCount, flags, _, err := unix.Recvmsg(fd, buffer, control, unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, nil, 0, err
		}
		if count == 0 {
			closeRights(control[:controlCount])
			return nil, nil, 0, &ProtocolError{Code: protocol.ErrorProtocol}
		}
		return buffer[:count], control[:controlCount], flags, nil
	}
}

func requireRequestEnd(ctx context.Context, fd int) error {
	if err := waitFD(ctx, fd, unix.POLLIN); err != nil {
		return &ProtocolError{Code: protocol.ErrorProtocol}
	}
	buffer := make([]byte, 1)
	control := make([]byte, ancillaryBufferBytes)
	count, controlCount, flags, _, err := unix.Recvmsg(fd, buffer, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil || count != 0 || controlCount != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeRights(control[:controlCount])
		return &ProtocolError{Code: protocol.ErrorProtocol}
	}
	return nil
}

func requirePeerClose(ctx context.Context, fd int) error {
	if err := waitFD(ctx, fd, unix.POLLIN); err != nil {
		return err
	}
	buffer := make([]byte, 1)
	control := make([]byte, ancillaryBufferBytes)
	count, controlCount, flags, _, err := unix.Recvmsg(fd, buffer, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil || count != 0 || controlCount != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeRights(control[:controlCount])
		return &ProtocolError{Code: protocol.ErrorProtocol}
	}
	return nil
}

func parseRights(control []byte) ([]int, error) {
	if len(control) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil, err
	}
	if len(messages) != 1 {
		return nil, errors.New("unexpected control message count")
	}
	if messages[0].Header.Level != unix.SOL_SOCKET || messages[0].Header.Type != unix.SCM_RIGHTS {
		return nil, errors.New("unexpected control message")
	}
	return unix.ParseUnixRights(&messages[0])
}

func closeRights(control []byte) {
	messages, _ := unix.ParseSocketControlMessage(control)
	for index := range messages {
		if messages[index].Header.Level != unix.SOL_SOCKET || messages[index].Header.Type != unix.SCM_RIGHTS {
			continue
		}
		descriptors, _ := unix.ParseUnixRights(&messages[index])
		closeDescriptors(descriptors)
	}
}

func closeDescriptors(descriptors []int) {
	for _, fd := range descriptors {
		_ = unix.Close(fd)
	}
}

func rejectAndClose(fd int, code protocol.ErrorCode) error {
	return rejectAndCloseVersion(fd, protocol.Version, code)
}

func rejectAndCloseVersion(fd, version int, code protocol.ErrorCode) error {
	defer unix.Close(fd)
	// Discard one queued packet so close cannot replace the stable error with ECONNRESET.
	buffer := make([]byte, protocol.MaxPacketBytes)
	control := make([]byte, ancillaryBufferBytes)
	_, controlCount, _, _, receiveErr := unix.Recvmsg(fd, buffer, control, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
	if receiveErr == nil {
		closeRights(control[:controlCount])
	}
	packet, err := protocol.MarshalResponse(protocol.FailureForVersion(version, code))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return sendPacket(ctx, fd, packet, nil)
}

func boundedContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	if maximum <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, maximum)
}

func waitFD(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := 100
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if milliseconds := int(remaining.Milliseconds()); milliseconds < timeout {
				timeout = milliseconds
				if timeout < 1 {
					timeout = 1
				}
			}
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		count, err := unix.Poll(poll, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return &ProtocolError{Code: protocol.ErrorProtocol}
		}
		if poll[0].Revents&(events|unix.POLLHUP) != 0 {
			return nil
		}
	}
}
