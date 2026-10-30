package edgeconfig

import (
	"regexp"
	"strconv"
	"strings"
)

// ServerTelemetryIdentity is the signed telemetry identity a site server logs
// under: the values its renderTelemetryServer `set`s assign.
type ServerTelemetryIdentity struct {
	TenantID              string
	SiteID                string
	PackageSubscriptionID string
	ConfigVersionID       string
}

// ccV2IdentityVariables are the identity variables a CC v2 server hook
// assigns, in renderTelemetryServer order.
var ccV2IdentityVariables = [...]string{"cdnca_tenant_id", "cdnca_site_id", "cdnca_package_subscription_id", "cdnca_config_version_id"}

var ccV2IdentityValue = regexp.MustCompile(`^[A-Za-z0-9._-]{0,128}$`)

// ccV2IdentityPrelude is the Lua a CC v2 server_rewrite hook runs before the
// CC decision: it assigns the server's telemetry identity. nginx runs a
// phase's handlers last registered first and lua registers its
// server_rewrite handler after the rewrite module's, so the hook runs before
// the server's `set`s; a request it refuses there (429, ban, challenge page)
// would otherwise log no tenant, site or package. The `set`s that follow for
// a request the hook passes assign the same values. "" without an identity
// (a server without telemetry has no such variables) or with a value Lua
// could not hold literally.
func ccV2IdentityPrelude(identity *ServerTelemetryIdentity) string {
	if identity == nil {
		return ""
	}
	values := [...]string{identity.TenantID, identity.SiteID, identity.PackageSubscriptionID, identity.ConfigVersionID}
	parts := make([]string, len(values))
	for index, value := range values {
		if !ccV2IdentityValue.MatchString(value) {
			return ""
		}
		parts[index] = "ngx.var." + ccV2IdentityVariables[index] + " = " + strconv.Quote(value) + ";"
	}
	return strings.Join(parts, " ")
}

// ccV2ServerIdentityPrelude is the prelude a server's own telemetry `set`s
// call for: "" when the server sets no identity, ok false when it sets only
// part of one or one Lua could not hold literally.
func ccV2ServerIdentityPrelude(document *nginxDocument, server int) (string, bool) {
	values := make(map[string]string, len(ccV2IdentityVariables))
	for _, directive := range document.directNamed(server, "set") {
		if len(directive.fields) != 3 {
			continue
		}
		for _, name := range ccV2IdentityVariables {
			if directive.fields[1] == "$"+name {
				if _, duplicate := values[name]; duplicate {
					return "", false
				}
				values[name] = directive.fields[2]
			}
		}
	}
	if len(values) == 0 {
		return "", true
	}
	if len(values) != len(ccV2IdentityVariables) {
		return "", false
	}
	prelude := ccV2IdentityPrelude(&ServerTelemetryIdentity{TenantID: values["cdnca_tenant_id"], SiteID: values["cdnca_site_id"],
		PackageSubscriptionID: values["cdnca_package_subscription_id"], ConfigVersionID: values["cdnca_config_version_id"]})
	return prelude, prelude != ""
}
