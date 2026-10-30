//go:build linux

package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
	"golang.org/x/sys/unix"
)

func TestLinuxSeqpacketRoundTripAndPeerCredential(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	peerResult := make(chan PeerIdentity, 1)
	go func() {
		exchange, err := listener.Accept(context.Background())
		if err != nil {
			peerResult <- PeerIdentity{PID: -1}
			return
		}
		defer exchange.Close()
		peerResult <- exchange.Peer
		_ = exchange.Respond(context.Background(), protocol.Success(testTransportReceipt()))
	}()
	response, err := client.RoundTrip(context.Background(), protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationCurrent}, nil)
	if err != nil || !response.OK {
		t.Fatalf("round trip = %#v, %v", response, err)
	}
	peer := <-peerResult
	if peer.PID <= 0 || peer.UID != uint32(os.Geteuid()) || peer.GID != uint32(os.Getegid()) {
		t.Fatalf("peer = %#v", peer)
	}
	if authorizedPeer(PeerIdentity{UID: peer.UID + 1, GID: peer.GID}, listener.policy) {
		t.Fatal("wrong UID authorized")
	}
	if authorizedPeer(PeerIdentity{UID: peer.UID, GID: peer.GID + 1}, listener.policy) {
		t.Fatal("wrong GID authorized")
	}
}

// The production socket is owned by the unprivileged agent account while a
// native root Agent connects through it. Root must be accepted end to end.
func TestLinuxRootPeerAcceptedOnAgentOwnedSocket(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires root to own the socket as a different account")
	}
	const agentUID, agentGID = 64991, 64992
	listener, client := testTransportPair(t)
	defer listener.Close()
	if err := os.Chown(listener.policy.path, agentUID, agentGID); err != nil {
		t.Fatal(err)
	}
	listener.policy.uid, listener.policy.gid = agentUID, agentGID
	client.policy = listener.policy
	peerResult := make(chan PeerIdentity, 1)
	go func() {
		exchange, err := listener.Accept(context.Background())
		if err != nil {
			peerResult <- PeerIdentity{PID: -1}
			return
		}
		defer exchange.Close()
		peerResult <- exchange.Peer
		_ = exchange.Respond(context.Background(), protocol.Success(testTransportReceipt()))
	}()
	response, err := client.RoundTrip(context.Background(), protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationCurrent}, nil)
	if err != nil || !response.OK {
		t.Fatalf("root round trip = %#v, %v", response, err)
	}
	if peer := <-peerResult; peer.PID <= 0 || peer.UID != 0 || peer.GID != 0 {
		t.Fatalf("peer = %#v", peer)
	}
}

func TestValidateArtifactClosesFailedFDBeforeReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	content := []byte("artifact")
	if err := os.WriteFile(path, content, 0o400); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Request{
		ArtifactSize:   int64(len(content)),
		ArtifactSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	if _, code := validateArtifact(fd, request); code != protocol.ErrorArtifactMismatch {
		t.Fatalf("validateArtifact code = %s, want %s", code, protocol.ErrorArtifactMismatch)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("failed artifact fd = %v, want closed", err)
	}

	reusedPath := filepath.Join(t.TempDir(), "reused")
	if err := os.WriteFile(reusedPath, []byte("reused"), 0o400); err != nil {
		t.Fatal(err)
	}
	reused, err := unix.Open(reusedPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(reused)
	if reused != fd {
		t.Fatalf("reused fd = %d, want closed fd %d", reused, fd)
	}
	for range 3 {
		runtime.GC()
		runtime.Gosched()
	}
	if _, err := unix.FcntlInt(uintptr(reused), unix.F_GETFD, 0); err != nil {
		t.Fatalf("reused fd after GC = %v", err)
	}
}

func TestRejectAndCloseReturnsStableErrorWithQueuedRequest(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	if _, err := unix.SendmsgN(pair[0], []byte(`{"untrusted":true}`), nil, nil, unix.MSG_NOSIGNAL); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(pair[0], unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if err := rejectAndClose(pair[1], protocol.ErrorUnauthorized); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, protocol.MaxPacketBytes)
	count, _, _, _, err := unix.Recvmsg(pair[0], buffer, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ParseResponse(buffer[:count])
	if err != nil || response.OK || response.ErrorCode != protocol.ErrorUnauthorized {
		t.Fatalf("response = %#v, %v", response, err)
	}
}

func TestLinuxTransportRejectsBadFramesAndDescriptors(t *testing.T) {
	receipt := testTransportReceipt()
	digest := sha256.Sum256([]byte("artifact"))
	install := protocol.Request{
		ProtocolVersion: 1, Operation: protocol.OperationInstall, TransactionID: "txn-123",
		ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0",
		Platform: "linux", Architecture: "amd64", ArtifactSHA256: hex.EncodeToString(digest[:]),
		ArtifactSize: 8, AuditBasename: "artifact", CurrentReceipt: &receipt,
	}
	installPacket, err := protocol.MarshalRequest(install)
	if err != nil {
		t.Fatal(err)
	}
	queryPacket, err := protocol.MarshalRequest(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: "txn-123"})
	if err != nil {
		t.Fatal(err)
	}
	prepare := install
	prepare.ProtocolVersion = protocol.JournalVersion
	prepare.Operation = protocol.OperationPrepareInstall
	preparePacket, err := protocol.MarshalRequest(prepare)
	if err != nil {
		t.Fatal(err)
	}
	inspectPacket, err := protocol.MarshalRequest(protocol.Request{ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationInspectTransaction, TransactionID: "txn-123"})
	if err != nil {
		t.Fatal(err)
	}
	ack := protocol.PreparedAck{
		SchemaVersion: 1, TransactionID: "txn-123", InstallPayloadSHA256: receipt.ArtifactSHA256,
		ReleaseSequence: 2, ArtifactSHA256: receipt.ArtifactSHA256, ManifestSHA256: receipt.ArtifactSHA256,
		ExecutableSHA256: receipt.ArtifactSHA256, SBOMSHA256: receipt.ArtifactSHA256,
		PreviousVersion: "1.0.0", TargetVersion: "1.1.0",
	}
	activatePacket, err := protocol.MarshalRequest(protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationActivateInstall,
		TransactionID: "txn-123", InstallPayloadSHA256: receipt.ArtifactSHA256, PreparedAck: &ack,
	})
	if err != nil {
		t.Fatal(err)
	}
	readOnly := testArtifact(t, []byte("artifact"), unix.O_RDONLY)
	writable := testArtifact(t, []byte("artifact"), unix.O_RDWR)
	modeWritable := testArtifactWithMode(t, []byte("artifact"), unix.O_RDONLY, 0o600)
	directory, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directory)
	device, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(device)
	socketFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socketFD)
	symlinkTarget := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(symlinkTarget, []byte("artifact"), 0o400); err != nil {
		t.Fatal(err)
	}
	symlinkPath := symlinkTarget + "-link"
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatal(err)
	}
	symlinkFD, err := unix.Open(symlinkPath, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(symlinkFD)
	hardlinkPath := filepath.Join(t.TempDir(), "hardlink-artifact")
	if err := os.WriteFile(hardlinkPath, []byte("artifact"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hardlinkPath, hardlinkPath+"-second"); err != nil {
		t.Fatal(err)
	}
	hardlinkFD, err := unix.Open(hardlinkPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(hardlinkFD)

	tests := []struct {
		name   string
		packet []byte
		fds    []int
		want   protocol.ErrorCode
	}{
		{"oversize", make([]byte, protocol.MaxPacketBytes+1), nil, protocol.ErrorProtocol},
		{"truncated", []byte(`{"protocol_version":1,"operation":`), nil, protocol.ErrorBadRequest},
		{"truncated-v4", []byte(`{"protocol_version":4,"operation":`), nil, protocol.ErrorProtocol},
		{"unknown field", []byte(`{"protocol_version":1,"operation":"query","transaction_id":"txn-123","extra":1}`), nil, protocol.ErrorBadRequest},
		{"missing fd", installPacket, nil, protocol.ErrorFDRequired},
		{"prepare missing fd", preparePacket, nil, protocol.ErrorFDRequired},
		{"forbidden fd", queryPacket, []int{readOnly}, protocol.ErrorFDForbidden},
		{"inspect forbidden fd", inspectPacket, []int{readOnly}, protocol.ErrorFDForbidden},
		{"activate forbidden fd", activatePacket, []int{readOnly}, protocol.ErrorFDForbidden},
		{"extra fd", installPacket, []int{readOnly, readOnly}, protocol.ErrorFDUnsafe},
		{"directory fd", installPacket, []int{directory}, protocol.ErrorFDUnsafe},
		{"device fd", installPacket, []int{device}, protocol.ErrorFDUnsafe},
		{"socket fd", installPacket, []int{socketFD}, protocol.ErrorFDUnsafe},
		{"symlink fd", installPacket, []int{symlinkFD}, protocol.ErrorFDUnsafe},
		{"hardlink fd", installPacket, []int{hardlinkFD}, protocol.ErrorFDUnsafe},
		{"writable fd", installPacket, []int{writable}, protocol.ErrorFDUnsafe},
		{"writable inode", installPacket, []int{modeWritable}, protocol.ErrorFDUnsafe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, _ := testTransportPair(t)
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				_, err := listener.Accept(context.Background())
				result <- err
			}()
			response := rawRoundTrip(t, listener.policy.path, test.packet, test.fds)
			wantVersion := protocol.Version
			if bytes.Contains(test.packet, []byte(`"protocol_version":2`)) {
				wantVersion = protocol.JournalVersion
			}
			if response.ProtocolVersion != wantVersion || response.OK || response.ErrorCode != test.want {
				t.Fatalf("response = %#v, want %s", response, test.want)
			}
			if err := <-result; err == nil {
				t.Fatal("bad request reached handler")
			}
		})
	}
}

func TestLinuxTransportRejectsExtraPacket(t *testing.T) {
	listener, _ := testTransportPair(t)
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		_, err := listener.Accept(context.Background())
		result <- err
	}()
	packet, err := protocol.MarshalRequest(protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationQuery, TransactionID: "txn-123"})
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: listener.policy.path}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := unix.SendmsgN(fd, packet, nil, nil, unix.MSG_NOSIGNAL); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Shutdown(fd, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, protocol.MaxPacketBytes)
	count, _, _, _, err := unix.Recvmsg(fd, buffer, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ParseResponse(buffer[:count])
	if err != nil || response.ErrorCode != protocol.ErrorProtocol {
		t.Fatalf("response = %#v, %v", response, err)
	}
	if err := <-result; err == nil {
		t.Fatal("extra packet reached handler")
	}
}

func TestLinuxTransportRejectsDigestAndSizeTamper(t *testing.T) {
	receipt := testTransportReceipt()
	artifactFD := testArtifact(t, []byte("artifact"), unix.O_RDONLY)
	for _, test := range []struct {
		name   string
		size   int64
		digest string
	}{
		{"size", 7, receipt.ArtifactSHA256},
		{"digest", 8, receipt.ArtifactSHA256},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := protocol.Request{
				ProtocolVersion: 1, Operation: protocol.OperationInstall, TransactionID: "txn-123",
				ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0",
				Platform: "linux", Architecture: "amd64", ArtifactSHA256: test.digest,
				ArtifactSize: test.size, AuditBasename: "artifact", CurrentReceipt: &receipt,
			}
			packet, err := protocol.MarshalRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			listener, _ := testTransportPair(t)
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				_, err := listener.Accept(context.Background())
				result <- err
			}()
			response := rawRoundTrip(t, listener.policy.path, packet, []int{artifactFD})
			if response.ErrorCode != protocol.ErrorArtifactMismatch {
				t.Fatalf("response = %#v", response)
			}
			<-result
		})
	}
}

func TestLinuxClientContextDeadline(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.RoundTrip(ctx, protocol.Request{ProtocolVersion: 1, Operation: protocol.OperationCurrent}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestLinuxClientEnforcesV2DescriptorRulesBeforeConnect(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	receipt := testTransportReceipt()
	prepare := protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationPrepareInstall,
		TransactionID: "txn-prepare", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0",
		Platform: "linux", Architecture: "amd64", ArtifactSHA256: receipt.ArtifactSHA256,
		ArtifactSize: 8, AuditBasename: "artifact", CurrentReceipt: &receipt,
	}
	if _, err := client.RoundTrip(context.Background(), prepare, nil); protocolErrorCode(err) != protocol.ErrorFDRequired {
		t.Fatalf("prepare without fd error = %v", err)
	}
	artifact := os.NewFile(uintptr(testArtifact(t, []byte("artifact"), unix.O_RDONLY)), "artifact")
	inspect := protocol.Request{ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationInspectTransaction, TransactionID: "txn-prepare"}
	if _, err := client.RoundTrip(context.Background(), inspect, artifact); protocolErrorCode(err) != protocol.ErrorFDForbidden {
		t.Fatalf("inspect with fd error = %v", err)
	}
}

func TestLinuxClientRejectsResponseProtocolDowngrade(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		exchange, err := listener.Accept(context.Background())
		if err != nil {
			serverResult <- err
			return
		}
		defer exchange.Close()
		serverResult <- exchange.Respond(context.Background(), protocol.Success(testTransportReceipt()))
	}()
	request := protocol.Request{ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationInspectTransaction, TransactionID: "txn-123"}
	_, err := client.RoundTrip(context.Background(), request, nil)
	if protocolErrorCode(err) != protocol.ErrorProtocol {
		t.Fatalf("downgraded response error = %v", err)
	}
	var negotiationErr *LegacyNegotiationError
	if errors.As(err, &negotiationErr) {
		t.Fatalf("ordinary protocol downgrade unexpectedly marked as legacy negotiation: %#v", negotiationErr)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestLinuxClientMarksV1BadRequestVersionNegotiation(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		exchange, err := listener.Accept(context.Background())
		if err != nil {
			serverResult <- err
			return
		}
		respondErr := exchange.Respond(context.Background(), protocol.FailureForVersion(protocol.Version, protocol.ErrorBadRequest))
		closeErr := exchange.Close()
		if respondErr != nil {
			serverResult <- respondErr
			return
		}
		serverResult <- closeErr
	}()
	digest := testTransportReceipt().ArtifactSHA256
	ack := protocol.PreparedAck{
		SchemaVersion: 1, TransactionID: "txn-123", InstallPayloadSHA256: digest, ReleaseSequence: 2,
		ArtifactSHA256: digest, ManifestSHA256: digest, ExecutableSHA256: digest, SBOMSHA256: digest,
		PreviousVersion: "1.0.0", TargetVersion: "1.1.0",
	}
	request := protocol.Request{
		ProtocolVersion: protocol.JournalV4Version, Operation: protocol.OperationMarkInstalling,
		TransactionID: "txn-123", InstallPayloadSHA256: digest, PreparedAck: &ack,
	}
	_, err := client.RoundTrip(context.Background(), request, nil)
	var negotiationErr *LegacyNegotiationError
	if !errors.As(err, &negotiationErr) || negotiationErr.RequestVersion != protocol.JournalV4Version ||
		negotiationErr.PeerVersion != protocol.Version || negotiationErr.Code != protocol.ErrorBadRequest ||
		protocolErrorCode(err) != protocol.ErrorProtocol {
		t.Fatalf("legacy negotiation error = %#v, %v", negotiationErr, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestLinuxTransportRejectsMalformedV4WithoutLegacyNegotiation(t *testing.T) {
	listener, _ := testTransportPair(t)
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		_, err := listener.Accept(context.Background())
		serverResult <- err
	}()
	response := rawRoundTrip(t, listener.policy.path, []byte(`{"protocol_version":4,"operation":`), nil)
	if response.ProtocolVersion != protocol.Version || response.OK || response.ErrorCode != protocol.ErrorProtocol {
		t.Fatalf("malformed v4 response = %#v", response)
	}
	if err := <-serverResult; err == nil {
		t.Fatal("malformed v4 request reached handler")
	}
}

func TestLinuxClientRejectsPeerCloseControlMessage(t *testing.T) {
	listener, client := testTransportPair(t)
	defer listener.Close()
	artifactFD := testArtifact(t, []byte("close-control"), unix.O_RDONLY)
	serverResult := make(chan error, 1)
	go func() {
		exchange, err := listener.Accept(context.Background())
		if err != nil {
			serverResult <- err
			return
		}
		defer exchange.Close()
		if err := exchange.Respond(context.Background(), protocol.Success(testTransportReceipt())); err != nil {
			serverResult <- err
			return
		}
		_, err = unix.SendmsgN(exchange.fd, nil, unix.UnixRights(artifactFD), nil, unix.MSG_NOSIGNAL)
		serverResult <- err
	}()
	_, err := client.RoundTrip(context.Background(), protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil)
	if protocolErrorCode(err) != protocol.ErrorProtocol {
		t.Fatalf("peer close control error = %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func protocolErrorCode(err error) protocol.ErrorCode {
	code, _ := ErrorCode(err)
	return code
}

func testTransportPair(t *testing.T) (*Listener, *Client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	policy := socketPolicy{path: path, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	listener, err := listenerFromFD(fd, policy)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	return listener, &Client{policy: policy}
}

func testTransportReceipt() protocol.Receipt {
	digest := sha256.Sum256([]byte("baseline"))
	return protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: "bootstrap-v1", ReleaseSequence: 1,
		ArtifactSHA256: hex.EncodeToString(digest[:]), CurrentVersion: "1.0.0", Status: "active",
		IssuedAt:  time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		Signature: protocol.Signature{KeyID: "helper-2026-01", Value: base64.RawStdEncoding.EncodeToString(make([]byte, 64))},
	}
}

func testArtifact(t *testing.T, content []byte, flags int) int {
	return testArtifactWithMode(t, content, flags, 0o400)
}

func testArtifactWithMode(t *testing.T, content []byte, flags int, finalMode os.FileMode) int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, finalMode); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func rawRoundTrip(t *testing.T, path string, packet []byte, fds []int) protocol.Response {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	var control []byte
	if len(fds) != 0 {
		control = unix.UnixRights(fds...)
	}
	if _, err := unix.SendmsgN(fd, packet, control, nil, unix.MSG_NOSIGNAL); err != nil {
		t.Fatal(err)
	}
	if err := unix.Shutdown(fd, unix.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, protocol.MaxPacketBytes)
	count, _, _, _, err := unix.Recvmsg(fd, buffer, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ParseResponse(buffer[:count])
	if err != nil {
		t.Fatal(err)
	}
	return response
}
