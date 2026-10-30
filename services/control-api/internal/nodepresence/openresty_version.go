package nodepresence

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"unicode"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const maxOpenRestyVersionBytes = 128

// sessionOpenRestyVersion is the OpenResty version declared by the
// capabilities snapshot of one node session (node_session_capabilities).
// A native node rewrites openresty.version when it switches its runtime to
// the one of its Agent release and declares it on the next Connect, so the
// console shows the runtime actually in use (node-runtime-upgrade). Any
// snapshot that does not match its digest or decode cleanly yields nil:
// this is display only, never a reason to fail the inventory read.
func sessionOpenRestyVersion(snapshot, digest []byte) *string {
	if len(snapshot) == 0 || len(snapshot) > 64<<10 {
		return nil
	}
	actual := sha256.Sum256(snapshot)
	if !bytes.Equal(actual[:], digest) {
		return nil
	}
	capabilities := new(agentv1.AgentCapabilities)
	if err := proto.Unmarshal(snapshot, capabilities); err != nil {
		return nil
	}
	version := capabilities.GetOpenrestyVersion()
	if version == "" || len(version) > maxOpenRestyVersionBytes || strings.TrimSpace(version) != version ||
		!utf8.ValidString(version) || strings.IndexFunc(version, unicode.IsControl) >= 0 {
		return nil
	}
	return &version
}
