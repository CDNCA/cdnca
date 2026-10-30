package cachecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestActorRequiresExplicitActorScope(t *testing.T) {
	typeOfActor := reflect.TypeOf(Actor{})
	if _, exists := typeOfActor.FieldByName("ActorScopeID"); !exists {
		t.Fatal("Actor.ActorScopeID is missing")
	}

	value := reflect.New(typeOfActor).Elem()
	value.FieldByName("UserID").Set(reflect.ValueOf(uuid.New()))
	value.FieldByName("ScopeID").Set(reflect.ValueOf(uuid.New()))
	if validActor(value.Interface().(Actor)) {
		t.Fatal("actor without an explicit actor scope was accepted")
	}
	value.FieldByName("ActorScopeID").Set(value.FieldByName("ScopeID"))
	if !validActor(value.Interface().(Actor)) {
		t.Fatal("fully scoped actor was rejected")
	}
}

func TestPolicyRuleOrderMatchingAndCanonicalization(t *testing.T) {
	document, err := normalizePolicy(PolicyDocument{
		Mode: PolicyOverride,
		Rules: []Rule{
			{Order: 1, Extensions: []string{".CSS"}, StatusCodes: []int{200}, TTLSeconds: 60},
			{Order: 2, PathPrefix: "/api", StatusCodes: []int{404}, TTLSeconds: 5},
		},
		QueryMode: QueryInclude, QueryNames: []string{"version", "lang"},
		VaryHeaders:    []string{"Accept-Encoding", "Accept-Language"},
		DiskQuotaBytes: minDiskQuotaBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if document.Rules[0].Extensions[0] != ".css" || document.Rules[1].PathPrefix != "/api/" {
		t.Fatalf("rules were not canonicalized: %+v", document.Rules)
	}
	if got := strings.Join(document.QueryNames, ","); got != "lang,version" {
		t.Fatalf("query names=%q", got)
	}
	if got := strings.Join(document.VaryHeaders, ","); got != "accept-encoding,accept-language" {
		t.Fatalf("vary headers=%q", got)
	}
	matched := MatchRule(document, RequestFacts{Path: "/static/app.CSS", StatusCode: 200})
	if matched == nil || matched.Order != 1 || matched.TTLSeconds != 60 {
		t.Fatalf("extension rule did not match: %+v", matched)
	}
	matched = MatchRule(document, RequestFacts{Path: "/api/missing", StatusCode: 404})
	if matched == nil || matched.Order != 2 || matched.TTLSeconds != 5 {
		t.Fatalf("path rule did not match: %+v", matched)
	}
	if matched := MatchRule(document, RequestFacts{Path: "/api/missing", StatusCode: 200}); matched != nil {
		t.Fatalf("unexpected rule match: %+v", matched)
	}
}

func TestPolicyStrictlyRejectsAmbiguityAndBounds(t *testing.T) {
	base := PolicyDocument{
		Mode:           PolicyOverride,
		Rules:          []Rule{{Order: 1, Extensions: []string{".css"}, TTLSeconds: 60}},
		QueryMode:      QueryPreserve,
		DiskQuotaBytes: minDiskQuotaBytes,
	}
	tests := []struct {
		name   string
		mutate func(*PolicyDocument)
	}{
		{"overlapping extension", func(value *PolicyDocument) {
			value.Rules = append(value.Rules, Rule{Order: 2, Extensions: []string{".css"}, StatusCodes: []int{200}, TTLSeconds: 30})
		}},
		{"overlapping paths", func(value *PolicyDocument) {
			value.Rules = []Rule{
				{Order: 1, PathPrefix: "/assets/", TTLSeconds: 60},
				{Order: 2, PathPrefix: "/assets/images/", TTLSeconds: 30},
			}
		}},
		{"non contiguous order", func(value *PolicyDocument) { value.Rules[0].Order = 2 }},
		{"ttl zero", func(value *PolicyDocument) { value.Rules[0].TTLSeconds = 0 }},
		{"ttl too large", func(value *PolicyDocument) { value.Rules[0].TTLSeconds = maxTTLSeconds + 1 }},
		{"quota too small", func(value *PolicyDocument) { value.DiskQuotaBytes = minDiskQuotaBytes - 1 }},
		{"too many rules", func(value *PolicyDocument) {
			value.Rules = make([]Rule, maxRules+1)
		}},
		{"query names without boundary mode", func(value *PolicyDocument) { value.QueryNames = []string{"v"} }},
		{"vary wildcard", func(value *PolicyDocument) { value.VaryHeaders = []string{"*"} }},
		{"vary cookie", func(value *PolicyDocument) { value.VaryHeaders = []string{"Cookie"} }},
		{"control character", func(value *PolicyDocument) { value.QueryMode = QueryInclude; value.QueryNames = []string{"bad\nname"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Rules = append([]Rule(nil), base.Rules...)
			test.mutate(&value)
			if _, err := normalizePolicy(value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v, want invalid input", err)
			}
		})
	}
}

func TestPolicyModes(t *testing.T) {
	valid := []PolicyDocument{
		{Mode: PolicyDisabled, QueryMode: QueryIgnore},
		{Mode: PolicyFollowOrigin, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes},
	}
	for _, document := range valid {
		if _, err := normalizePolicy(document); err != nil {
			t.Fatalf("valid mode %q: %v", document.Mode, err)
		}
	}
	invalid := []PolicyDocument{
		{Mode: PolicyDisabled, QueryMode: QueryIgnore, DiskQuotaBytes: minDiskQuotaBytes},
		{Mode: PolicyFollowOrigin, QueryMode: QueryPreserve},
		{Mode: PolicyOverride, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes},
	}
	for _, document := range invalid {
		if _, err := normalizePolicy(document); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid mode %q accepted: %v", document.Mode, err)
		}
	}
}

func TestPolicyV1CanonicalBytesAndDigestRemainStable(t *testing.T) {
	document, err := normalizePolicy(PolicyDocument{
		Mode: PolicyOverride,
		Rules: []Rule{{
			Order: 1, Extensions: []string{".css"}, StatusCodes: []int{200}, TTLSeconds: 60,
		}},
		QueryMode:      QueryPreserve,
		DiskQuotaBytes: minDiskQuotaBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != PolicySchemaV1 {
		t.Fatalf("V1 internal schema=%d, want %d", document.SchemaVersion, PolicySchemaV1)
	}
	want := []byte(`{"mode":"override","rules":[{"order":1,"extensions":[".css"],"status_codes":[200],"ttl_seconds":60}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`)
	got, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("V1 JSON changed:\n got %s\nwant %s", got, want)
	}
	digest, err := digestJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if wantDigest := sha256.Sum256(want); digest != wantDigest {
		t.Fatalf("V1 digest=%x, want %x", digest, wantDigest)
	}
}

func TestPolicyJSONRejectsDuplicateKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"V1 document", `{"mode":"disabled","mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`},
		{"V1 escaped document", `{"mode":"disabled","\u006dode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`},
		{"V2 document", `{"schema_version":2,"schema_version":2,"mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`},
		{"V1 rule", `{"mode":"override","rules":[{"order":1,"ttl_seconds":60,"ttl_seconds":60}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"V2 rule", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","action":"cache","ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"V2 escaped rule", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","\u0061ction":"cache","ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document PolicyDocument
			if err := json.Unmarshal([]byte(test.raw), &document); err == nil {
				t.Fatal("duplicate JSON key was accepted")
			}
		})
	}
}

func TestPolicyV1LegacyJSONCompatibility(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "null collections and unknown document field",
			raw:  `{"mode":"disabled","rules":null,"query_mode":"ignore","query_names":null,"vary_headers":null,"disk_quota_bytes":0,"legacy_unknown":{"kept_out_of_model":true}}`,
		},
		{
			name: "optional null rule fields and unknown rule field",
			raw:  `{"mode":"override","rules":[{"order":1,"extensions":null,"path_prefix":null,"status_codes":null,"ttl_seconds":60,"legacy_unknown":true}],"query_mode":"preserve","query_names":null,"vary_headers":null,"disk_quota_bytes":67108864}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document PolicyDocument
			if err := json.Unmarshal([]byte(test.raw), &document); err != nil {
				t.Fatalf("legacy V1 decode: %v", err)
			}
			normalized, err := normalizePolicy(document)
			if err != nil {
				t.Fatalf("legacy V1 normalize: %v", err)
			}
			if normalized.SchemaVersion != PolicySchemaV1 {
				t.Fatalf("legacy V1 schema=%d", normalized.SchemaVersion)
			}
		})
	}

	var versionlessV2 PolicyDocument
	if err := json.Unmarshal([]byte(`{"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`), &versionlessV2); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizePolicy(versionlessV2); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("versionless V2 fields error=%v, want invalid input", err)
	}
}

func TestLoadPolicyRevisionMarksLegacyV1ForReadAndReplay(t *testing.T) {
	scopeID, siteID, tenantID, userID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	row := legacyPolicyRevisionRow{
		scopeID: scopeID, siteID: siteID, tenantID: tenantID, userID: userID,
		createdAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	for _, path := range []string{"read", "replay"} {
		t.Run(path, func(t *testing.T) {
			result, err := loadPolicyRevision(
				context.Background(), legacyPolicyRevisionQuery{row: row}, scopeID, siteID, 7,
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.Document.SchemaVersion != PolicySchemaV1 {
				t.Fatalf("internal schema=%d, want %d", result.Document.SchemaVersion, PolicySchemaV1)
			}
			encoded, err := json.Marshal(result.Document)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "schema_version") {
				t.Fatalf("legacy V1 wire exposed internal schema: %s", encoded)
			}
		})
	}
}

type legacyPolicyRevisionQuery struct {
	row legacyPolicyRevisionRow
}

func (query legacyPolicyRevisionQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	return query.row
}

type legacyPolicyRevisionRow struct {
	scopeID   uuid.UUID
	siteID    uuid.UUID
	tenantID  uuid.UUID
	userID    uuid.UUID
	createdAt time.Time
}

func (row legacyPolicyRevisionRow) Scan(destinations ...any) error {
	if len(destinations) != 18 {
		return fmt.Errorf("scan destinations=%d, want 18", len(destinations))
	}
	*destinations[0].(*uuid.UUID) = row.siteID
	*destinations[1].(*uuid.UUID) = row.scopeID
	*destinations[2].(*uuid.UUID) = row.tenantID
	*destinations[3].(*int64) = 7
	*destinations[4].(*BindingMode) = BindingOverride
	*destinations[5].(*uuid.UUID) = row.siteID
	*destinations[6].(*int64) = 7
	*destinations[7].(*int) = PolicySchemaV1
	*destinations[8].(*PolicyMode) = PolicyOverride
	*destinations[9].(*[]byte) = []byte(`[{"order":1,"extensions":[".css"],"status_codes":[200],"ttl_seconds":60}]`)
	*destinations[10].(*QueryMode) = QueryPreserve
	*destinations[11].(*[]string) = []string{}
	*destinations[12].(*[]string) = []string{}
	*destinations[13].(*int64) = minDiskQuotaBytes
	*destinations[14].(*uuid.UUID) = row.userID
	*destinations[15].(*string) = "legacy-read"
	*destinations[16].(*time.Time) = row.createdAt
	*destinations[17].(*[]byte) = []byte(`{}`)
	return nil
}

func TestPolicyV2CanonicalBytesDigestAndOrderedOverlap(t *testing.T) {
	document, err := normalizePolicy(PolicyDocument{
		SchemaVersion: PolicySchemaV2,
		Mode:          PolicyOverride,
		Rules: []Rule{
			{
				Order: 1, Extensions: []string{".CSS"}, PathPrefix: "/assets", StatusCodes: []int{200},
				Action: RuleActionCache, TTLSeconds: 3600, BrowserTTLSeconds: 600,
			},
			{
				Order: 2, PathPrefix: "/assets/", StatusCodes: []int{200},
				Action: RuleActionNoCache, TTLSeconds: 0, BrowserTTLSeconds: 0,
			},
		},
		QueryMode:      QueryPreserve,
		DiskQuotaBytes: minDiskQuotaBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"schema_version":2,"mode":"override","rules":[{"order":1,"extensions":[".css"],"path_prefix":"/assets/","status_codes":[200],"action":"cache","ttl_seconds":3600,"browser_ttl_seconds":600},{"order":2,"path_prefix":"/assets/","status_codes":[200],"action":"no_cache","ttl_seconds":0,"browser_ttl_seconds":0}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`)
	got, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("V2 JSON is not canonical:\n got %s\nwant %s", got, want)
	}
	digest, err := digestJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if wantDigest := sha256.Sum256(want); digest != wantDigest {
		t.Fatalf("V2 digest=%x, want %x", digest, wantDigest)
	}

	matched := MatchRule(document, RequestFacts{Path: "/assets/app.css", StatusCode: 200})
	if matched == nil || matched.Order != 1 || matched.Action != RuleActionCache {
		t.Fatalf("first complete ordered match=%+v", matched)
	}
	matched = MatchRule(document, RequestFacts{Path: "/assets/app.js", StatusCode: 200})
	if matched == nil || matched.Order != 2 || matched.Action != RuleActionNoCache {
		t.Fatalf("fallback ordered match=%+v", matched)
	}

	equivalent, err := normalizePolicy(PolicyDocument{
		SchemaVersion: PolicySchemaV2,
		Mode:          PolicyOverride,
		Rules: []Rule{
			{
				Order: 1, Extensions: []string{".css"}, PathPrefix: "/assets/", StatusCodes: []int{200},
				Action: RuleActionCache, TTLSeconds: 3600, BrowserTTLSeconds: 600,
			},
			{
				Order: 2, PathPrefix: "/assets", StatusCodes: []int{200},
				Action: RuleActionNoCache,
			},
		},
		QueryMode: QueryPreserve, QueryNames: []string{}, VaryHeaders: []string{},
		DiskQuotaBytes: minDiskQuotaBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	equivalentDigest, err := digestJSON(equivalent)
	if err != nil {
		t.Fatal(err)
	}
	if digest != equivalentDigest {
		t.Fatalf("equivalent V2 digest=%x, want %x", equivalentDigest, digest)
	}
}

func TestPolicyV2StrictWireAndSemanticValidation(t *testing.T) {
	valid := `{"schema_version":2,"mode":"override","rules":[{"order":1,"extensions":[".css"],"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`
	var document PolicyDocument
	if err := json.Unmarshal([]byte(valid), &document); err != nil {
		t.Fatalf("decode valid V2: %v", err)
	}
	if _, err := normalizePolicy(document); err != nil {
		t.Fatalf("normalize valid V2: %v", err)
	}

	invalid := []struct {
		name string
		raw  string
	}{
		{"null schema", `{"schema_version":null,"mode":"override","rules":[],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"explicit V1 schema", `{"schema_version":1,"mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`},
		{"unknown document field", `{"schema_version":2,"mode":"disabled","rules":[],"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0,"unknown":true}`},
		{"null rules", `{"schema_version":2,"mode":"disabled","rules":null,"query_mode":"ignore","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`},
		{"null query names", `{"schema_version":2,"mode":"disabled","rules":[],"query_mode":"ignore","query_names":null,"vary_headers":[],"disk_quota_bytes":0}`},
		{"unknown rule field", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30,"unknown":true}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"missing action", `{"schema_version":2,"mode":"override","rules":[{"order":1,"ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"missing browser ttl", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"null browser ttl", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":null}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"wrong ttl type", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":"60","browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"noncontiguous order", `{"schema_version":2,"mode":"override","rules":[{"order":2,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"unknown action", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"bypass","ttl_seconds":0,"browser_ttl_seconds":0}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"cache ttl zero", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":0,"browser_ttl_seconds":0}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"browser ttl above edge", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":61}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"no cache ttl nonzero", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"no_cache","ttl_seconds":1,"browser_ttl_seconds":0}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
		{"no cache browser ttl nonzero", `{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"no_cache","ttl_seconds":0,"browser_ttl_seconds":1}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}`},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			var candidate PolicyDocument
			err := json.Unmarshal([]byte(test.raw), &candidate)
			if err == nil {
				_, err = normalizePolicy(candidate)
			}
			if err == nil {
				t.Fatal("invalid V2 policy was accepted")
			}
		})
	}

	for _, candidate := range []PolicyDocument{
		{SchemaVersion: PolicySchemaV2, Mode: PolicyDisabled, QueryMode: QueryIgnore},
		{SchemaVersion: PolicySchemaV2, Mode: PolicyFollowOrigin, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes},
	} {
		if _, err := normalizePolicy(candidate); err != nil {
			t.Fatalf("V2 empty-rule mode %q: %v", candidate.Mode, err)
		}
	}
}

func TestDecodeStoredPolicyDocumentIsSchemaStrict(t *testing.T) {
	v2, err := DecodeStoredPolicyDocument(
		PolicySchemaV2, PolicyOverride,
		[]byte(`[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30},{"order":2,"action":"no_cache","ttl_seconds":0,"browser_ttl_seconds":0}]`),
		QueryPreserve, []string{}, []string{}, minDiskQuotaBytes,
	)
	if err != nil || v2.SchemaVersion != PolicySchemaV2 || len(v2.Rules) != 2 ||
		v2.Rules[0].BrowserTTLSeconds != 30 || v2.Rules[1].Action != RuleActionNoCache {
		t.Fatalf("stored V2 document=%+v err=%v", v2, err)
	}
	v1, err := DecodeStoredPolicyDocument(
		PolicySchemaV1, PolicyOverride, []byte(`[{"order":1,"ttl_seconds":60}]`),
		QueryIgnore, []string{}, []string{}, minDiskQuotaBytes,
	)
	if err != nil || v1.SchemaVersion != PolicySchemaV1 || v1.Rules[0].Action != "" {
		t.Fatalf("stored V1 document=%+v err=%v", v1, err)
	}
	for name, candidate := range map[string]struct {
		schema int
		rules  string
	}{
		"unknown schema":         {schema: 3, rules: `[]`},
		"missing V2 action":      {schema: PolicySchemaV2, rules: `[{"order":1,"ttl_seconds":60,"browser_ttl_seconds":30}]`},
		"missing V2 browser ttl": {schema: PolicySchemaV2, rules: `[{"order":1,"action":"cache","ttl_seconds":60}]`},
		"V2 fields under V1":     {schema: PolicySchemaV1, rules: `[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":30}]`},
		"null rules":             {schema: PolicySchemaV2, rules: `null`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeStoredPolicyDocument(
				candidate.schema, PolicyOverride, []byte(candidate.rules),
				QueryPreserve, []string{}, []string{}, minDiskQuotaBytes,
			); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestURLCanonicalizationAndTargetBoundaries(t *testing.T) {
	site := siteDescriptor{
		Domain: "example.com", HTTPPorts: []string{"80", "8080"}, HTTPSPorts: []string{"443"},
	}
	target, err := normalizeTargetURL("HTTP://EXAMPLE.COM:80/assets/%7e.css?b=2&a=1", false, site, false)
	if err != nil {
		t.Fatal(err)
	}
	if target.CanonicalURL != "http://example.com/assets/~.css?b=2&a=1" || target.CanonicalPath != "/assets/~.css" {
		t.Fatalf("canonical target=%+v", target)
	}
	prefix, err := normalizeTargetURL("http://example.com:8080/assets", true, site, false)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.CanonicalURL != "http://example.com:8080/assets/" || prefix.CanonicalPath != "/assets/" {
		t.Fatalf("canonical prefix=%+v", prefix)
	}

	invalid := []string{
		"http://other.example/assets/a.css",
		"http://example.com:81/assets/a.css",
		"http://user@example.com/assets/a.css",
		"http://example.com/a/../b",
		"http://example.com/a%2fb",
		"http://example.com/a\\b",
		"http://example.com/a#fragment",
		"http://example.com/a\n",
	}
	for _, raw := range invalid {
		if _, err := normalizeTargetURL(raw, false, site, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("target %q err=%v, want invalid", raw, err)
		}
	}
	if _, err := normalizeTargetURL("http://example.com/assets/?v=1", true, site, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("prefix query err=%v, want invalid", err)
	}
	if _, err := normalizeTargets([]string{"http://example.com/a", "http://EXAMPLE.com:80/a"}, ActionPurge, TargetExactURL, site); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("canonical duplicate err=%v, want invalid", err)
	}
	tooMany := make([]string, maxTargets+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("http://example.com/assets/%d", index)
	}
	if _, err := normalizeTargets(tooMany, ActionPurge, TargetExactURL, site); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("%d targets err=%v, want 16-target wire boundary", len(tooMany), err)
	}
	whole, err := normalizeTargets(nil, ActionPurge, TargetWholeSite, site)
	if err != nil || len(whole) != 1 || whole[0].CanonicalPath != "/" {
		t.Fatalf("whole-site target=%+v err=%v", whole, err)
	}
}
