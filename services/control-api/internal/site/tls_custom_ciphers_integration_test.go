//go:build integration

package site

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// 待出包前全量跑：the custom preset stores its ordered
// list (migration 520); another preset clears it; TLSv1.3 only over a stored
// custom list is refused by CHECK 517 (ErrTLSProfileInvalid, not a server
// error); the change is audited as tls_cipher_suites.
func TestSiteTLSCustomCipherSuitesStoredAndChecked(t *testing.T) {
	f := newTrustFixture(t)
	created, err := f.createSite(f.a, f.a, "tls-custom.example.test")
	if err != nil {
		t.Fatal(err)
	}
	revision := created.Site.Revision
	update := func(fields func(*SiteFields)) (Site, error) {
		t.Helper()
		key := f.key("update")
		request := SiteFields{Domains: []string{"tls-custom.example.test"}, HTTPPorts: []string{"80"},
			Origins: []string{"192.0.2.1"}, Enabled: true, Status: StatusActive}
		fields(&request)
		result, err := f.sites.Update(context.Background(), f.a.siteActor(), UpdateRequest{
			ID: created.Site.ID, ExpectedRevision: revision, IdempotencyKey: key, RequestID: key, SourceIP: "198.51.100.9",
			Fields: request})
		if err == nil {
			revision = result.Site.Revision
		}
		return result.Site, err
	}
	text := func(value string) *string { return &value }
	suites := []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA"}
	custom, err := update(func(fields *SiteFields) {
		fields.TLSCipherPreset, fields.TLSCipherSuites = text("custom"), suites
	})
	if err != nil || custom.TLSCipherPreset != "custom" || !slices.Equal(custom.TLSCipherSuites, suites) {
		t.Fatalf("custom profile: %+v, %v", custom, err)
	}
	kept, err := update(func(*SiteFields) {})
	if err != nil || !slices.Equal(kept.TLSCipherSuites, suites) {
		t.Fatalf("plain update changed the list: %+v, %v", kept, err)
	}
	if _, err := update(func(fields *SiteFields) { fields.TLSProtocols = []string{"TLSv1.3"} }); !errors.Is(err, ErrTLSProfileInvalid) {
		t.Fatalf("TLSv1.3 only over a custom list: %v, want ErrTLSProfileInvalid", err)
	}
	modern, err := update(func(fields *SiteFields) { fields.TLSCipherPreset = text("modern") })
	if err != nil || modern.TLSCipherPreset != "modern" || modern.TLSCipherSuites != nil {
		t.Fatalf("modern clears the list: %+v, %v", modern, err)
	}
	var audited int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE action='site.tls_profile.update' AND resource_id=$1 AND changes @> '[{"field":"tls_cipher_suites"}]'::jsonb`,
		created.Site.ID.String()).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("tls_cipher_suites audit events = %d, %v (want set and cleared)", audited, err)
	}
	// The database refuses what Go would: custom without a list.
	if _, err := f.pool.Exec(context.Background(), `UPDATE sites SET tls_cipher_preset='custom' WHERE id=$1`,
		created.Site.ID); err == nil {
		t.Fatal("custom preset without suites stored")
	}
}
