package identitysessionhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionCursorRoundTripAndActorBinding(t *testing.T) {
	actor := testActor()
	cursor := sessionCursor{Version: 1, ScopeID: actor.ScopeID, UserID: actor.UserID,
		SnapshotAt:    time.Date(2026, 8, 8, 12, 0, 0, 123456000, time.UTC),
		LastCreatedAt: time.Date(2026, 8, 7, 12, 0, 0, 654321000, time.UTC),
		LastFamilyID:  uuid.MustParse("66666666-6666-4666-8666-666666666666")}
	encoded, err := encodeCursor(cursor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCursor(encoded, actor)
	if err != nil || decoded != cursor {
		t.Fatalf("decoded=(%+v, %v), want %+v", decoded, err, cursor)
	}
	otherActor := actor
	otherActor.UserID = uuid.New()
	if _, err := decodeCursor(encoded, otherActor); !errorsIs(err, ErrInvalidCursor) {
		t.Fatalf("cross-user cursor error=%v", err)
	}
	otherActor = actor
	otherActor.ScopeID = uuid.New()
	if _, err := decodeCursor(encoded, otherActor); !errorsIs(err, ErrInvalidCursor) {
		t.Fatalf("cross-scope cursor error=%v", err)
	}
	for _, invalid := range []string{"", encoded + "=", "not-base64!", encoded[:len(encoded)-1]} {
		if _, err := decodeCursor(invalid, actor); !errorsIs(err, ErrInvalidCursor) {
			t.Fatalf("cursor %q error=%v", invalid, err)
		}
	}
}

func TestMaskSourceIPNeverReturnsFullAddress(t *testing.T) {
	tests := map[string]string{
		"203.0.113.47":                        "203.0.113.0/24",
		"2001:db8:1234:5678:90ab:cdef:1234:1": "2001:db8:1234:5678::/64",
		"":                                    "",
		"not-an-ip":                           "",
	}
	for input, expected := range tests {
		if actual := maskSourceIP(input); actual != expected {
			t.Fatalf("maskSourceIP(%q)=%q want %q", input, actual, expected)
		}
	}
}

func TestRevokeDigestBindsActorFamilyRevisionAndKey(t *testing.T) {
	request := RevokeRequest{Actor: testActor(), FamilyID: uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		ExpectedRevision: 3, IdempotencyKey: "revoke-key", RequestID: "request-a"}
	digest := revokeRequestDigest(request)
	if digest == ([sha256.Size]byte{}) {
		t.Fatal("empty digest")
	}
	for _, mutate := range []func(*RevokeRequest){
		func(value *RevokeRequest) { value.FamilyID = uuid.New() },
		func(value *RevokeRequest) { value.ExpectedRevision++ },
		func(value *RevokeRequest) { value.IdempotencyKey = "other-key" },
		func(value *RevokeRequest) { value.Actor.SessionID = uuid.New() },
		func(value *RevokeRequest) { value.Actor.ScopeID = uuid.New() },
		func(value *RevokeRequest) { value.Actor.UserID = uuid.New() },
	} {
		changed := request
		mutate(&changed)
		if revokeRequestDigest(changed) == digest {
			t.Fatalf("digest did not bind mutation: %+v", changed)
		}
	}
	if hex.EncodeToString(digest[:]) == "" {
		t.Fatal("digest hex unavailable")
	}
}

func TestStoreSQLContractsFenceCallerScopeAndLockFamily(t *testing.T) {
	for _, required := range []string{
		"caller.id=$1", "caller.scope_id=$2", "caller.user_id=$3", "caller.revoked_at IS NULL",
		"caller.expires_at>$4", "user_row.status='active'", "membership.status='active'", "scope.kind=$5",
		"FOR UPDATE OF caller,user_row,membership",
	} {
		if !strings.Contains(lockActorSQL, required) {
			t.Fatalf("lockActorSQL missing %q", required)
		}
	}
	for _, required := range []string{
		"session.family_id=$1", "session.scope_id=$2", "session.user_id=$3", "FOR UPDATE",
	} {
		if !strings.Contains(lockFamilySQL, required) {
			t.Fatalf("lockFamilySQL missing %q", required)
		}
	}
	for _, required := range []string{
		"payload->>'idempotency_key'=$3", "result='success'", "action='auth.session_family.revoke'",
	} {
		if !strings.Contains(loadReceiptSQL, required) {
			t.Fatalf("loadReceiptSQL missing %q", required)
		}
	}
	for _, forbidden := range []string{"refresh_token_hash", "source_ip::text", "SELECT *"} {
		if strings.Contains(listFamiliesSQL, forbidden) {
			t.Fatalf("listFamiliesSQL leaks forbidden %q", forbidden)
		}
	}
}

func testActor() Actor {
	return Actor{SessionID: uuid.MustParse("88888888-8888-4888-8888-888888888888"),
		ScopeID: uuid.MustParse("99999999-9999-4999-8999-999999999999"),
		UserID:  uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), ScopeKind: "tenant"}
}

func errorsIs(err, target error) bool { return err == target }

// E1: pgx scans timestamptz in time.Local, so a page boundary row taken from
// a non-UTC session must still yield a valid, decodable next-page cursor.
func TestNextPageCursorNormalisesNonUTCCreatedAt(t *testing.T) {
	actor := testActor()
	shanghai := time.FixedZone("UTC+8", 8*60*60)
	current := sessionCursor{Version: 1, ScopeID: actor.ScopeID, UserID: actor.UserID,
		SnapshotAt: time.Date(2026, 10, 22, 12, 0, 0, 123000, time.UTC)}
	last := SessionFamily{FamilyID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		CreatedAt: time.Date(2026, 10, 22, 18, 30, 0, 456000, shanghai)}
	encoded, err := nextPageCursor(current, last)
	if err != nil {
		t.Fatalf("nextPageCursor error=%v", err)
	}
	decoded, err := decodeCursor(encoded, actor)
	if err != nil {
		t.Fatalf("decodeCursor error=%v", err)
	}
	if !decoded.LastCreatedAt.Equal(last.CreatedAt) || decoded.LastCreatedAt.Location() != time.UTC ||
		decoded.LastFamilyID != last.FamilyID || decoded.SnapshotAt != current.SnapshotAt {
		t.Fatalf("decoded=%+v", decoded)
	}
}
