//go:build integration

package edgeautopublish_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// FX07 through the real site store: a new HTTPS site follows the system
// default (bootstrap: off) unless the request says; forced HTTPS and its port
// persist, and turning HTTPS off ends forced HTTPS instead of failing.
func TestSiteForceHTTPSPersistsAndFollowsHTTPS(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}

	request := newSiteRequest("force-https.example.test", "force-https-create")
	request.Fields.HTTPSEnabled, request.Fields.HTTPSPorts = true, []string{"443", "8443"}
	created, err := service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Site.ForceHTTPS || created.Site.HTTPSRedirectPort != 0 {
		t.Fatalf("new site forced HTTPS = %v/%d, want the system default (off)", created.Site.ForceHTTPS, created.Site.HTTPSRedirectPort)
	}
	// be-gap-2: forced HTTPS is only turned on with a bound certificate (asset FKs skipped for the fact).
	if _, err := pool.Exec(t.Context(), `BEGIN; SET LOCAL session_replication_role = replica;
		INSERT INTO certificate_site_binding_facts (tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,
			expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at)
		VALUES ('`+identity.tenantScope.String()+`','`+created.Site.ID.String()+`',1,'bind',gen_random_uuid(),gen_random_uuid(),true,
			0,1,'force-https-bind','`+identity.tenantScope.String()+`','`+identity.tenantUser.String()+`',now()); COMMIT`); err != nil {
		t.Fatal(err)
	}
	enabled, port := true, 8443
	fields := request.Fields
	fields.ForceHTTPS, fields.HTTPSRedirectPort = &enabled, &port
	updated, err := service.Update(t.Context(), actor, site.UpdateRequest{ID: created.Site.ID, ExpectedRevision: created.Site.Revision,
		Fields: fields, IdempotencyKey: "force-https-on", RequestID: "force-https-on"})
	if err != nil || !updated.Site.ForceHTTPS || updated.Site.HTTPSRedirectPort != 8443 {
		t.Fatalf("enable forced HTTPS = %+v %v", updated.Site, err)
	}
	// A client that does not send the fields keeps them.
	fields = request.Fields
	fields.CNAME = "kept.example.test"
	kept, err := service.Update(t.Context(), actor, site.UpdateRequest{ID: created.Site.ID, ExpectedRevision: updated.Site.Revision,
		Fields: fields, IdempotencyKey: "force-https-kept", RequestID: "force-https-kept"})
	if err != nil || !kept.Site.ForceHTTPS || kept.Site.HTTPSRedirectPort != 8443 {
		t.Fatalf("update without the fields = %+v %v", kept.Site, err)
	}
	// Dropping the redirect port's listener falls back to the lowest port.
	fields.HTTPSPorts = []string{"443"}
	narrowed, err := service.Update(t.Context(), actor, site.UpdateRequest{ID: created.Site.ID, ExpectedRevision: kept.Site.Revision,
		Fields: fields, IdempotencyKey: "force-https-port", RequestID: "force-https-port"})
	if err != nil || !narrowed.Site.ForceHTTPS || narrowed.Site.HTTPSRedirectPort != 0 {
		t.Fatalf("redirect port removed = %+v %v", narrowed.Site, err)
	}
	fields.HTTPSEnabled, fields.HTTPSPorts = false, nil
	off, err := service.Update(t.Context(), actor, site.UpdateRequest{ID: created.Site.ID, ExpectedRevision: narrowed.Site.Revision,
		Fields: fields, IdempotencyKey: "force-https-off", RequestID: "force-https-off"})
	if err != nil || off.Site.ForceHTTPS {
		t.Fatalf("HTTPS off = %+v %v, want forced HTTPS off", off.Site, err)
	}

	// An explicit request value wins over the default on create.
	explicit := newSiteRequest("force-https-explicit.example.test", "force-https-explicit")
	explicit.Fields.HTTPSEnabled, explicit.Fields.HTTPSPorts, explicit.Fields.ForceHTTPS = true, []string{"443"}, &enabled
	created, err = service.Create(t.Context(), actor, explicit)
	if err != nil || !created.Site.ForceHTTPS {
		t.Fatalf("explicit forced HTTPS on create = %+v %v", created.Site, err)
	}
}
