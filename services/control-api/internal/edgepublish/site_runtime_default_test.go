package edgepublish

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

// 1.0.35 publishes only site runtime v2: one rule (ResolveSiteRuntimeSchema)
// for every entry point, and any other schema (v1 included) is refused.
func TestSiteRuntimeSchemaIsV2Only(t *testing.T) {
	if DefaultSiteRuntimeSchema != siteRuntimeV2Schema || SiteRuntimeV2Schema != siteRuntimeV2Schema {
		t.Fatalf("default=%q v2=%q", DefaultSiteRuntimeSchema, SiteRuntimeV2Schema)
	}
	const v1 = "cdnca.edge.site-runtime/v1"
	for input, want := range map[string]string{"": siteRuntimeV2Schema,
		siteRuntimeV2Schema: siteRuntimeV2Schema, "cdnca.edge.site-runtime/v3": "cdnca.edge.site-runtime/v3"} {
		if got := ResolveSiteRuntimeSchema(input); got != want {
			t.Fatalf("ResolveSiteRuntimeSchema(%q)=%q want %q", input, got, want)
		}
	}

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	request := PublishRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 7, NodeIDs: []uuid.UUID{uuid.New()},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: now.Add(time.Hour), MaxAttempts: 3,
		IdempotencyKey: "publish-default", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	digests := map[string][32]byte{}
	for _, schema := range []string{"", siteRuntimeV2Schema} {
		request.SiteRuntimeSchema = schema
		for name, normalize := range map[string]func(PublishRequest, time.Time) (normalizedPublishRequest, error){
			"manual": normalizePublishRequest, "replay": normalizePublishReplayRequest,
			"automatic": func(request PublishRequest, now time.Time) (normalizedPublishRequest, error) {
				request.Actor.ScopeKind = ScopeKindTenant
				return normalizeAutomaticPublishRequest(request, now)
			},
		} {
			normalized, err := normalize(request, now)
			if err != nil {
				t.Fatalf("%s %q: %v", name, schema, err)
			}
			if want := ResolveSiteRuntimeSchema(schema); normalized.SiteRuntimeSchema != want {
				t.Fatalf("%s %q normalized to %q, want %q", name, schema, normalized.SiteRuntimeSchema, want)
			}
		}
		normalized, err := normalizePublishRequest(request, now)
		if err != nil {
			t.Fatal(err)
		}
		if digests[schema], err = publicationRequestDigest(normalized); err != nil {
			t.Fatal(err)
		}
	}
	// The default is v2 itself (same request digest).
	if digests[""] != digests[siteRuntimeV2Schema] {
		t.Fatal("default schema digest is not the v2 digest")
	}
	for _, schema := range []string{v1, "cdnca.edge.site-runtime/v3"} {
		request.SiteRuntimeSchema = schema
		if _, err := normalizePublishRequest(request, now); err == nil {
			t.Fatalf("schema %q accepted", schema)
		}
	}
}
