package helper

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

const (
	ProductionSocketPath = "/run/cdnca-edge-agent/helper.sock"
	productionAccount    = "cdnca-edge"
	SystemdListenerFD    = 3
)

var ErrTransportUnavailable = errors.New("packaging helper transport unavailable")

type PeerIdentity struct {
	PID int32
	UID uint32
	GID uint32
}

type ProtocolError struct {
	Code protocol.ErrorCode
}

func (e *ProtocolError) Error() string {
	return string(e.Code)
}

// LegacyNegotiationError preserves the peer response that proves a v4 request
// reached a v1 helper and was rejected as an unsupported request.
type LegacyNegotiationError struct {
	RequestVersion int
	PeerVersion    int
	Code           protocol.ErrorCode
}

func (e *LegacyNegotiationError) Error() string {
	return string(e.Code)
}

func (*LegacyNegotiationError) Unwrap() error {
	return &ProtocolError{Code: protocol.ErrorProtocol}
}

func ErrorCode(err error) (protocol.ErrorCode, bool) {
	var protocolErr *ProtocolError
	if errors.As(err, &protocolErr) {
		return protocolErr.Code, true
	}
	return "", false
}

type socketPolicy struct {
	path string
	uid  uint32
	gid  uint32
}

type Client struct {
	policy socketPolicy
}

func NewClient() (*Client, error) {
	policy, err := productionPolicy()
	if err != nil {
		return nil, err
	}
	return &Client{policy: policy}, nil
}

func (c *Client) RoundTrip(ctx context.Context, request protocol.Request, artifact *os.File) (protocol.Response, error) {
	if c == nil {
		return protocol.Response{}, ErrTransportUnavailable
	}
	return roundTrip(ctx, c.policy, request, artifact)
}

func productionPolicy() (socketPolicy, error) {
	account, err := user.Lookup(productionAccount)
	if err != nil {
		return socketPolicy{}, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return socketPolicy{}, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return socketPolicy{}, &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	return socketPolicy{path: ProductionSocketPath, uid: uint32(uid), gid: uint32(gid)}, nil
}

// authorizedPeer accepts the fixed agent account, or the exact root identity
// used by native nodes whose Agent must run as root. Root already holds every
// privilege the helper exercises, so accepting 0:0 grants it nothing new; any
// other UID/GID pair, including partial root identities, stays unauthorized.
func authorizedPeer(peer PeerIdentity, policy socketPolicy) bool {
	if peer.UID == 0 && peer.GID == 0 {
		return true
	}
	return peer.UID == policy.uid && peer.GID == policy.gid
}

func validateSocketPath(policy socketPolicy) error {
	info, err := os.Lstat(policy.path)
	if err != nil || info.Mode()&os.ModeType != os.ModeSocket ||
		info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o600 {
		return &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint32(stat.Uid) != policy.uid || uint32(stat.Gid) != policy.gid {
		return &ProtocolError{Code: protocol.ErrorSocketPolicy}
	}
	return nil
}
