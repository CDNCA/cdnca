package regioncatalog

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestListRejectsInvalidOrNonPlatformActorsBeforeDatabaseAccess(t *testing.T) {
	valid := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionRead}}
	for _, test := range []struct {
		name    string
		actor   Actor
		request ListRequest
		want    error
	}{
		{name: "missing identity", actor: Actor{}, want: ErrUnauthenticated},
		{name: "tenant", actor: Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{PermissionRead}}, want: ErrPermissionDenied},
		{name: "missing permission", actor: Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}, want: ErrPermissionDenied},
		{name: "negative limit", actor: valid, request: ListRequest{Limit: -1}, want: ErrInvalidInput},
		{name: "oversized search", actor: valid, request: ListRequest{Search: string(make([]byte, 129))}, want: ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewStore(nil).List(context.Background(), test.actor, test.request)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestValidGeo(t *testing.T) {
	for _, ok := range [][3]string{{"", "", ""}, {"", "CN", ""}, {"", "CN", "440000"}, {"", "CN", "810000"}, {"", "US", ""},
		{"", "HK", ""}, {"southeast_asia", "", ""}, {"global", "", ""}, {"africa", "", ""},
		{"asia", "", ""}, {"oceania", "", ""}, {"northern_europe", "", ""}, {"caribbean", "", ""}} {
		if !ValidGeo(ok[0], ok[1], ok[2]) {
			t.Errorf("%q/%q/%q refused", ok[0], ok[1], ok[2])
		}
	}
	for _, bad := range [][3]string{{"", "", "440000"}, {"", "cn", ""}, {"", "CHN", ""}, {"", "ZZ", ""}, {"", "EU", ""},
		{"", "US", "440000"}, {"", "CN", "440300"}, {"", "CN", "990000"}, {"", "CN", "44000"},
		{"antarctica", "", ""}, {"Europe", "", ""}, {"europe", "DE", ""}, {"east_asia", "CN", "440000"}, {"east_asia", "", "440000"}} {
		if ValidGeo(bad[0], bad[1], bad[2]) {
			t.Errorf("%q/%q/%q accepted", bad[0], bad[1], bad[2])
		}
	}
}

// A create or update with an invalid geography is refused before the
// database is reached.
func TestWritesRefuseInvalidGeo(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionManage}}
	if _, _, err := NewStore(nil).Create(context.Background(), actor, CreateRequest{Name: "华南", L2CheckPort: 80,
		CountryCode: "US", ProvinceCode: "440000", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("create error = %v", err)
	}
	if _, _, err := NewStore(nil).Update(context.Background(), actor, UpdateRequest{ID: "1", ExpectedRevision: 1, Name: "华南",
		L2CheckPort: 80, CountryCode: "cn", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("update error = %v", err)
	}
	if _, _, err := NewStore(nil).Create(context.Background(), actor, CreateRequest{Name: "东南亚", L2CheckPort: 80,
		AreaCode: "southeast_asia", CountryCode: "SG", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("area+country create error = %v", err)
	}
	if _, _, err := NewStore(nil).Update(context.Background(), actor, UpdateRequest{ID: "1", ExpectedRevision: 1, Name: "大洋洲",
		L2CheckPort: 80, AreaCode: "antarctica", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown area update error = %v", err)
	}
	if _, _, err := NewStore(nil).Create(context.Background(), actor, CreateRequest{Name: "东南亚", L2CheckPort: 80,
		AreaCode: "southeast_asia", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("valid area create error = %v (want the database to be reached)", err)
	}
	if _, _, err := NewStore(nil).Create(context.Background(), actor, CreateRequest{Name: "华南", L2CheckPort: 80,
		CountryCode: "CN", ProvinceCode: "440000", IdempotencyKey: "k1", RequestID: "r1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("valid create error = %v (want the database to be reached)", err)
	}
}

func TestListAllowsPlatformAdminFallbackAndLimitZero(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	_, err := NewStore(nil).List(context.Background(), actor, ListRequest{Limit: 0})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v", err)
	}
}

// The region page offers apps/web/src/pages/regionGeo.ts regionCountryCodes
// (the 249 ISO 3166-1 alpha-2 codes); every one must be accepted.
func TestValidGeoAcceptsTheWebCountryList(t *testing.T) {
	codes := strings.Fields("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW")
	if len(codes) != 249 {
		t.Fatalf("%d codes", len(codes))
	}
	for _, code := range codes {
		if !ValidGeo("", code, "") {
			t.Errorf("%s refused", code)
		}
	}
}
