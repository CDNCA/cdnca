package domaineventsource

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/migrations"
)

var (
	sqlTypeRow  = regexp.MustCompile(`\('(io\.cdnca\.[a-z0-9_.]+)', '([a-z_]+)', '(events\.[a-z_]+\.read)', (true|false)\)`)
	sqlFieldRow = regexp.MustCompile(`\('(io\.cdnca\.[a-z0-9_.]+)', '([a-z0-9_]+)', '(uuid|string|integer|timestamp|string_array)', (true|false),\s*(NULL|ARRAY\[([^\]]*)\])\)`)
	sqlLiteral  = regexp.MustCompile(`'([^']*)'`)
)

// TestContractsMatchMigrations keeps the Go contracts and the SQL registry
// (domain_event_types_368 / domain_event_contract_fields_368 rows inserted by
// the 367+ migrations) identical, so both validators accept the same events.
func TestContractsMatchMigrations(t *testing.T) {
	names, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlTypes := map[string]Contract{}
	sqlFields := map[string][]Field{}
	for _, name := range names {
		if name < "367" {
			continue
		}
		raw, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		for _, match := range sqlTypeRow.FindAllStringSubmatch(body, -1) {
			sqlTypes[match[1]] = Contract{Type: match[1], SubjectKind: match[2], RequiredPermission: match[3],
				SiteBound: match[4] == "true"}
		}
		for _, match := range sqlFieldRow.FindAllStringSubmatch(body, -1) {
			field := Field{Name: match[2], Kind: match[3], Required: match[4] == "true"}
			for _, literal := range sqlLiteral.FindAllStringSubmatch(match[6], -1) {
				field.Allowed = append(field.Allowed, literal[1])
			}
			sqlFields[match[1]] = append(sqlFields[match[1]], field)
		}
	}
	if len(sqlTypes) != len(contracts) {
		t.Fatalf("SQL registers %d event types, Go %d", len(sqlTypes), len(contracts))
	}
	for eventType, contract := range contracts {
		sqlType, ok := sqlTypes[eventType]
		if !ok || sqlType.SubjectKind != contract.SubjectKind ||
			sqlType.RequiredPermission != contract.RequiredPermission || sqlType.SiteBound != contract.SiteBound {
			t.Errorf("%s: SQL type row %+v differs from Go contract", eventType, sqlType)
		}
		want := normalized(contract.Fields)
		got := normalized(sqlFields[eventType])
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s fields differ:\n Go  %+v\n SQL %+v", eventType, want, got)
		}
		if len(contract.Fields)+2 > MaxDataFields {
			t.Errorf("%s exceeds %d delivered data fields", eventType, MaxDataFields)
		}
		if contract.SiteBound != hasField(contract, "site_id") {
			t.Errorf("%s: site_bound must match the presence of site_id", eventType)
		}
	}
}

func normalized(fields []Field) []Field {
	result := make([]Field, len(fields))
	for index, field := range fields {
		field.Allowed = append([]string(nil), field.Allowed...)
		if len(field.Allowed) == 0 {
			field.Allowed = nil
		}
		result[index] = field
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func hasField(contract Contract, name string) bool {
	for _, field := range contract.Fields {
		if strings.EqualFold(field.Name, name) {
			return true
		}
	}
	return false
}

// TestContractsMatchPublicSchema keeps api/schemas/marketplace/v1/
// domain-event.schema.json (what plugin developers validate against) equal to
// the Go contracts: same types, subject kinds, fields, required set and enums.
func TestContractsMatchPublicSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "schemas", "marketplace", "v1", "domain-event.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Type struct {
				Enum []string `json:"enum"`
			} `json:"type"`
		} `json:"properties"`
		AllOf []struct {
			If struct {
				Properties struct {
					Type struct {
						Const string `json:"const"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"if"`
			Then struct {
				Properties struct {
					Subject struct {
						Pattern string `json:"pattern"`
					} `json:"subject"`
					Data struct {
						Ref string `json:"$ref"`
					} `json:"data"`
				} `json:"properties"`
			} `json:"then"`
		} `json:"allOf"`
		Definitions map[string]json.RawMessage `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if got := append([]string(nil), schema.Properties.Type.Enum...); !reflect.DeepEqual(sortedCopy(got), Types()) {
		t.Fatalf("schema type enum %v, Go %v", got, Types())
	}
	if len(schema.AllOf) != len(contracts) {
		t.Fatalf("schema has %d typed branches, Go %d contracts", len(schema.AllOf), len(contracts))
	}
	for _, branch := range schema.AllOf {
		contract, ok := Lookup(branch.If.Properties.Type.Const)
		if !ok || branch.Then.Properties.Subject.Pattern != "^"+contract.SubjectKind+"/" {
			t.Errorf("%s: unknown type or subject pattern %q", branch.If.Properties.Type.Const, branch.Then.Properties.Subject.Pattern)
			continue
		}
		var definition struct {
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
		}
		name := strings.TrimPrefix(branch.Then.Properties.Data.Ref, "#/definitions/")
		if err := json.Unmarshal(schema.Definitions[name], &definition); err != nil ||
			definition.AdditionalProperties == nil || *definition.AdditionalProperties {
			t.Errorf("%s: data definition %q must be closed", contract.Type, name)
			continue
		}
		wantRequired := []string{FieldSubscriptionID, FieldSubjectSequence}
		for _, field := range contract.Fields {
			if field.Required {
				wantRequired = append(wantRequired, field.Name)
			}
			property, ok := definition.Properties[field.Name]
			if !ok {
				t.Errorf("%s: schema lacks field %s", contract.Type, field.Name)
				continue
			}
			if got := schemaEnum(t, schema.Definitions, property); !reflect.DeepEqual(sortedCopy(got), sortedCopy(field.Allowed)) {
				t.Errorf("%s.%s: schema enum %v, Go %v", contract.Type, field.Name, got, field.Allowed)
			}
		}
		if len(definition.Properties) != len(contract.Fields)+2 ||
			!reflect.DeepEqual(sortedCopy(definition.Required), sortedCopy(wantRequired)) {
			t.Errorf("%s: schema properties %d required %v; Go fields %d required %v", contract.Type,
				len(definition.Properties), definition.Required, len(contract.Fields), wantRequired)
		}
	}
}

func schemaEnum(t *testing.T, definitions map[string]json.RawMessage, property json.RawMessage) []string {
	t.Helper()
	var value struct {
		Enum  []string `json:"enum"`
		Ref   string   `json:"$ref"`
		Items *struct {
			Enum []string `json:"enum"`
		} `json:"items"`
	}
	if err := json.Unmarshal(property, &value); err != nil {
		t.Fatal(err)
	}
	if value.Ref != "" {
		return schemaEnum(t, definitions, definitions[strings.TrimPrefix(value.Ref, "#/definitions/")])
	}
	if value.Items != nil {
		return value.Items.Enum
	}
	return value.Enum
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
