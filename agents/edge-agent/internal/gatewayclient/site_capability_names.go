package gatewayclient

import (
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// siteRuntimeCapabilityName is the site object root's name of a command
// capability (the documents' required_capabilities vocabulary). The table is
// siteobject.RuntimeCapabilityNames, shared with the control plane's
// siteruntimecap, so the two sides cannot drift (fix-l4cap).
func siteRuntimeCapabilityName(name agentv1.CapabilityName) (string, bool) {
	if _, defined := agentv1.CapabilityName_name[int32(name)]; !defined {
		return "", false
	}
	document, known := siteobject.RuntimeCapabilityNames[name.String()]
	return document, known
}
