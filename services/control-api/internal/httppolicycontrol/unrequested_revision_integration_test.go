//go:build integration

package httppolicycontrol

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-finalgaps2 (保存即生效): a policy revision advances the scope's source
// revision (zz_http_policy_edge_source_revision_167) outside any site
// request, so every write asks the site revision publisher, in its own
// transaction and after the revision advanced, to publish it. (The
// publisher itself, edgeautopublish.UnrequestedRevisionPublisher, cannot be
// imported here; its enqueue is covered in edgeautopublish.)

type recordedRevision struct {
	scopeID, siteID uuid.UUID
	requestID       string
	revision        int64
}

type recordingRevisionPublisher struct{ calls []recordedRevision }

func (publisher *recordingRevisionPublisher) EnqueueUnrequestedSiteRevisionTx(
	ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string,
) (bool, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&revision); err != nil {
		return false, err
	}
	publisher.calls = append(publisher.calls, recordedRevision{scopeID: scopeID, siteID: siteID, requestID: requestID, revision: revision})
	return true, nil
}

func TestHTTPPolicyWritesPublishTheirSourceRevision(t *testing.T) {
	fixture := newIntegrationFixture(t, allowTestGate())
	publisher := &recordingRevisionPublisher{}
	fixture.service.store.WithSiteRevisionPublisher(publisher)
	scopeRevision := func() int64 {
		t.Helper()
		var revision int64
		if err := fixture.pool.QueryRow(context.Background(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
			fixture.tenantA).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		return revision
	}
	created := createServicePolicy(t, fixture, fixture.siteA, "unrequested-create")
	if _, err := fixture.service.Update(context.Background(), fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.ID, ExpectedRevision: created.Revision,
		Config: validTestConfig(), WriteMetadata: testMetadata("unrequested-update"),
	}); err != nil {
		t.Fatal(err)
	}
	if len(publisher.calls) != 2 {
		t.Fatalf("publisher calls=%d, want 2 (create, update)", len(publisher.calls))
	}
	for index, want := range []string{"http-policy/unrequested-create-request", "http-policy/unrequested-update-request"} {
		call := publisher.calls[index]
		if call.scopeID != fixture.tenantA || call.siteID != fixture.siteA || call.requestID != want {
			t.Fatalf("call %d=%+v, want scope %s site %s request %s", index, call, fixture.tenantA, fixture.siteA, want)
		}
	}
	if current := scopeRevision(); publisher.calls[1].revision != current || publisher.calls[0].revision >= current {
		t.Fatalf("published revisions %d,%d; scope now %d", publisher.calls[0].revision, publisher.calls[1].revision, current)
	}
}
