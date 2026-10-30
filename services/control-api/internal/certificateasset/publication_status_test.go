package certificateasset

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublicationStatusReadModelContainsNoLeaseOrPrivateMaterial44(t *testing.T) {
	for _, value := range []any{
		PublicationStatus{}, PublicationStatusEvent{}, PublicationStatusDetail{},
		PublicationStatusPage{}, PublicationStatusCursor{}, PublicationStatusFilter{},
	} {
		typeOfValue := reflect.TypeOf(value)
		for index := 0; index < typeOfValue.NumField(); index++ {
			name := strings.ToLower(typeOfValue.Field(index).Name)
			for _, forbidden := range []string{"lease", "owner", "token", "private", "cipher", "nonce", "raw", "error"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s exposes forbidden field %q", typeOfValue.Name(), name)
				}
			}
		}
	}
	source, err := os.ReadFile("publication_status.go")
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(source))
	for _, forbidden := range []string{"lease_token", "lease_owner", "private_key", "failure_detail", "raw_error"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("publication status source exposes forbidden durable field %q", forbidden)
		}
	}
}

func TestPublicationStatusSQLUsesAuthorizedSnapshotKeysetAndExactHistory44(t *testing.T) {
	source, err := os.ReadFile("publication_status.go")
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(source)), " ")
	for _, required := range []string{
		"pgx.RepeatableRead",
		"authorizeActor(ctx, tx, actor, tenantScopeID, false)",
		"SELECT transaction_timestamp()",
		"FROM certificate_publication_intents intent",
		"JOIN LATERAL",
		"FROM certificate_publication_intent_state_facts state",
		"state.occurred_at<=$2",
		"ORDER BY state.sequence DESC LIMIT 1",
		"latest.occurred_at<$6",
		"latest.occurred_at=$6 AND intent.site_id>$7",
		"intent.site_id=$7 AND intent.binding_revision<$8",
		"ORDER BY latest.occurred_at DESC,intent.site_id,intent.binding_revision DESC",
		"binding_revision=$3",
		"ORDER BY sequence",
	} {
		if !strings.Contains(compact, strings.Join(strings.Fields(required), " ")) {
			t.Errorf("publication status contract missing %q", required)
		}
	}
	for _, forbidden := range []string{"DISTINCT ON (intent.site_id)", "OFFSET"} {
		if strings.Contains(compact, forbidden) {
			t.Errorf("publication status contract contains unstable history pagination %q", forbidden)
		}
	}
}

func TestPublicationStatusFilterCursorAndActorFailClosed44(t *testing.T) {
	siteID := uuid.New()
	for _, filter := range []PublicationStatusFilter{
		{}, {State: "pending"}, {State: "leased"}, {State: "retry_wait"},
		{State: "succeeded"}, {State: "permanent_failed"},
		{Operation: "publish"}, {Operation: "unpublish"}, {SiteID: siteID},
	} {
		if !validPublicationStatusFilter(filter) {
			t.Fatalf("valid filter rejected: %+v", filter)
		}
	}
	for _, filter := range []PublicationStatusFilter{
		{State: "failed"}, {Operation: "delete"}, {State: "pending "},
	} {
		if validPublicationStatusFilter(filter) {
			t.Fatalf("invalid filter accepted: %+v", filter)
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	valid := PublicationStatusCursor{
		SnapshotAt: now, LastOccurredAt: now.Add(-time.Second),
		LastSiteID: siteID, LastBindingRevision: 7,
	}
	if !validPublicationStatusCursor(PublicationStatusCursor{}) || !validPublicationStatusCursor(valid) {
		t.Fatal("valid publication cursor rejected")
	}
	for _, cursor := range []PublicationStatusCursor{
		{SnapshotAt: now},
		{SnapshotAt: now, LastOccurredAt: now.Add(time.Second), LastSiteID: siteID, LastBindingRevision: 7},
		{SnapshotAt: now, LastOccurredAt: now, LastBindingRevision: 7},
		{SnapshotAt: now, LastOccurredAt: now, LastSiteID: siteID},
	} {
		if validPublicationStatusCursor(cursor) {
			t.Fatalf("invalid cursor accepted: %+v", cursor)
		}
	}

	tenantScopeID := uuid.New()
	tenant := Actor{UserID: uuid.New(), ScopeID: tenantScopeID, ScopeKind: ScopeTenant}
	if err := validateActor(tenant, tenantScopeID); err != nil {
		t.Fatal(err)
	}
	if err := validateActor(tenant, uuid.New()); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant actor error=%v", err)
	}
	forged := tenant
	forged.ScopeKind = ScopePlatform
	if err := validateActor(forged, tenantScopeID); err != nil {
		t.Fatalf("platform-shaped actor must reach durable authorization: %v", err)
	}
	forged.ScopeKind = "operator"
	if err := validateActor(forged, tenantScopeID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("forged scope kind error=%v", err)
	}
}

func TestPublicationStatusPageUsesLastVisibleTupleWithoutOverlap44(t *testing.T) {
	snapshot := time.Now().UTC().Truncate(time.Microsecond)
	firstSite, secondSite, thirdSite := uuid.New(), uuid.New(), uuid.New()
	items := []PublicationStatus{
		{SiteID: firstSite, BindingRevision: 3, OccurredAt: snapshot.Add(-time.Second)},
		{SiteID: secondSite, BindingRevision: 2, OccurredAt: snapshot.Add(-2 * time.Second)},
		{SiteID: thirdSite, BindingRevision: 1, OccurredAt: snapshot.Add(-3 * time.Second)},
	}
	page := publicationStatusPage(items, 2, snapshot)
	if len(page.Items) != 2 || page.NextCursor == nil || page.SnapshotAt != snapshot {
		t.Fatalf("page=%+v", page)
	}
	last := page.Items[1]
	if page.NextCursor.LastOccurredAt != last.OccurredAt ||
		page.NextCursor.LastSiteID != last.SiteID ||
		page.NextCursor.LastBindingRevision != last.BindingRevision {
		t.Fatalf("next cursor=%+v last=%+v", page.NextCursor, last)
	}
	if page.NextCursor.LastSiteID == items[2].SiteID {
		t.Fatal("next cursor advanced past the last visible item")
	}
}

func TestPublicationStatusValidationTracksOldRevisionHistory44(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	status := PublicationStatus{
		TenantScopeID: uuid.New(), SiteID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(),
		BindingRevision: 2, Operation: "unpublish", StateSequence: 4,
		State: "retry_wait", Attempt: 2, NextAttemptAt: pointerTime44(now.Add(time.Second)),
		OccurredAt: now, FailureCode: "edge_unavailable",
	}
	if !validPublicationStatus(status) {
		t.Fatalf("valid old revision status rejected: %+v", status)
	}
	status.FailureCode = "raw provider timeout"
	if validPublicationStatus(status) {
		t.Fatal("raw failure detail was accepted")
	}
	status.FailureCode = "edge_unavailable"
	status.BindingRevision = 0
	if validPublicationStatus(status) {
		t.Fatal("zero revision was accepted")
	}
}

func TestPublicationStatusSuccessExposesOnlyDurableResultIdentity47(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	publicationID, configID, rolloutID := uuid.New(), uuid.New(), uuid.New()
	status := PublicationStatus{
		TenantScopeID: uuid.New(), SiteID: uuid.New(), AssetID: uuid.New(), VersionID: uuid.New(),
		BindingRevision: 4, Operation: "publish", StateSequence: 3, State: "succeeded", Attempt: 1,
		OccurredAt: now, PublicationID: &publicationID, PublicationRevision: 1,
		ConfigVersionID: &configID, RolloutID: &rolloutID, RolloutRevision: 1,
	}
	if !validPublicationStatus(status) {
		t.Fatalf("valid successful status rejected: %+v", status)
	}
	missing := status
	missing.RolloutID = nil
	if validPublicationStatus(missing) {
		t.Fatal("successful status without complete durable identity accepted")
	}
	nonsuccess := status
	nonsuccess.State = "retry_wait"
	nonsuccess.NextAttemptAt = pointerTime44(now.Add(time.Second))
	nonsuccess.FailureCode = "publication_unavailable"
	if validPublicationStatus(nonsuccess) {
		t.Fatal("non-success status exposed durable result identity")
	}
}

func pointerTime44(value time.Time) *time.Time { return &value }
