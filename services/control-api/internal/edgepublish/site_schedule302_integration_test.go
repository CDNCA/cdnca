//go:build integration

package edgepublish

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A site's 302 scheduling settings reach the v2 document and
// require SCHED302 v1; a node without it is refused (and named), with it the
// release is built. The signing key never enters the document.
func TestSiteRuntimeV2Schedule302FromDatabase(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	setup := func(t *testing.T, sched302Node bool) (*publishFixture, uuid.UUID, int64) {
		t.Helper()
		fixture := newL4V2ContractFixture(t)
		site := fixture.createSite(t, "dl-302.example.com", 18094, false).Site
		features := append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion})
		if sched302Node {
			features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SCHED302, ApiVersion: 1})
		}
		seedSiteRuntimeV2Capabilities(t, fixture, "", features)
		return fixture, site.ID, fixture.sourceRevision()
	}
	compile := func(t *testing.T, fixture *publishFixture, revision int64) (*siteRuntimeV2Document, []byte, []*agentv1.Capability, error) {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
			VALUES($1,$2,now()) ON CONFLICT DO NOTHING`, fixture.nodeID, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		canonical, _, _, _, capabilities, _, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
			revision, TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		var document siteRuntimeV2Document
		if err := json.Unmarshal(canonical, &document); err != nil {
			t.Fatal(err)
		}
		return &document, canonical, capabilities, nil
	}
	schedule := func(t *testing.T, fixture *publishFixture, siteID uuid.UUID) {
		t.Helper()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_schedule302_settings(scope_id,site_id,target,keep_path,keep_query,
				signature_ttl_seconds,https_to_http,extensions,path_prefixes,min_size_bytes,sign_key,updated_by_user_id,updated_at)
			VALUES($1,$2,'address',true,false,90,false,'{mp4,zip}','{/dl/}',1048576,$3,$4,now())`,
			fixture.scopeID, siteID, key, fixture.userID); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("node without SCHED302 is refused", func(t *testing.T) {
		fixture, siteID, revision := setup(t, false)
		document, _, capabilities, err := compile(t, fixture, revision)
		if err != nil {
			t.Fatalf("release without scheduling: %v", err)
		}
		if document.Sites[0].Schedule302 != nil || siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SCHED302) != 0 {
			t.Fatalf("unscheduled site carries schedule302: %+v %v", document.Sites[0].Schedule302, capabilities)
		}
		schedule(t, fixture, siteID)
		var refusal *TargetCapabilityError
		if _, _, _, err := compile(t, fixture, revision); !errors.As(err, &refusal) ||
			refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SCHED302 {
			t.Fatalf("node without SCHED302: %v", err)
		}
	})
	t.Run("scheduled release", func(t *testing.T) {
		fixture, siteID, revision := setup(t, true)
		schedule(t, fixture, siteID)
		document, canonical, capabilities, err := compile(t, fixture, revision)
		if err != nil {
			t.Fatalf("scheduled release: %v", err)
		}
		settings := document.Sites[0].Schedule302
		if settings == nil || settings.Target != "address" || !settings.KeepPath || settings.KeepQuery ||
			settings.SignatureTTLSeconds != 90 || len(settings.Extensions) != 2 || settings.PathPrefixes[0] != "/dl/" ||
			settings.MinSizeBytes != 1<<20 {
			t.Fatalf("schedule302 in the document: %+v", settings)
		}
		if siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SCHED302) != 1 {
			t.Fatalf("release does not require SCHED302: %v", capabilities)
		}
		if containsBytes(canonical, key) {
			t.Fatal("signing key leaked into the document")
		}
	})
}

func containsBytes(haystack, needle []byte) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if string(haystack[index:index+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
