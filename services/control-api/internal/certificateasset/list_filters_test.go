package certificateasset

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidListFiltersRejectsUnknownValues(t *testing.T) {
	yes := true
	provider := uuid.New()
	valid := ListFilters{Domain: "a", Domains: []string{"a.example.com"}, User: "u", CertificateID: "1", Name: "n",
		Remark: "r", Source: SourceACME, DNSProviderID: &provider, Expiry: "within30", AutoRenew: &yes,
		Issue: "issued", Sync: "complete"}
	if !validListFilters(valid) || !validListFilters(ListFilters{}) {
		t.Fatal("valid filters rejected")
	}
	nilID := uuid.Nil
	tooMany := make([]string, MaxListFilterDomains+1)
	for index := range tooMany {
		tooMany[index] = "a.example.com"
	}
	for name, filters := range map[string]ListFilters{
		"source":   {Source: "manual"},
		"expiry":   {Expiry: "30"},
		"issue":    {Issue: "revoked"},
		"sync":     {Sync: "unknown"},
		"provider": {DNSProviderID: &nilID},
		"control":  {Name: "a\nb"},
		"padded":   {Remark: " r"},
		"long":     {User: strings.Repeat("u", 129)},
		"empty":    {Domains: []string{""}},
		"domains":  {Domains: tooMany},
	} {
		if validListFilters(filters) {
			t.Fatalf("%s accepted: %#v", name, filters)
		}
	}
}

// 90 天内到期只含仍在使用、未过期的版本（不再把 30 天 + 已过期当 90 天），
// 每项条件都进同一 WHERE（总数与列表一致）。
func TestListFilterSQLExpiryAndBindings(t *testing.T) {
	var arguments []any
	sql := listFilterSQL(ListFilters{Expiry: "within90"}, &arguments, 7)
	if !strings.Contains(sql, "fact.expiry IN ('normal','expiring')") || !strings.Contains(sql, "$7 <= interval '90 days'") ||
		strings.Contains(sql, "'expired'") || len(arguments) != 0 {
		t.Fatalf("within90 = %s %v", sql, arguments)
	}
	sql = listFilterSQL(ListFilters{Expiry: "expired"}, &arguments, 7)
	if sql != " AND fact.expiry='expired'" {
		t.Fatalf("expired = %s", sql)
	}
	no := false
	arguments = []any{"scope", "now"}
	sql = listFilterSQL(ListFilters{Name: "Prod", Domains: []string{"A.example.com"}, AutoRenew: &no}, &arguments, 2)
	if !strings.Contains(sql, "strpos(lower(asset.name),lower($4))>0") || !strings.Contains(sql, "fact.latest_sans @> $3::text[]") ||
		!strings.Contains(sql, "NOT renew.auto_renew") || len(arguments) != 4 {
		t.Fatalf("combined = %s %v", sql, arguments)
	}
	if domains, ok := arguments[2].([]string); !ok || domains[0] != "a.example.com" {
		t.Fatalf("domains are matched lower-case: %#v", arguments[2])
	}
	if listFilterSQL(ListFilters{}, &arguments, 2) != "" {
		t.Fatal("empty filters add a clause")
	}
}
