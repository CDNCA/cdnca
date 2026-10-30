//go:build integration

package site

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// A new site takes the system TLS default (protocols and
// cipher preset as one SSL mode, OCSP stapling); an update changes only the
// TLS fields it names and is audited as site.tls_profile.update (the client
// CA by digest); a combination only the stored row reveals as invalid is
// ErrTLSProfileInvalid, not a server error.
func TestSiteTLSProfileDefaultsUpdateAndAudit(t *testing.T) {
	f := newTrustFixture(t)
	// Fresh installation: the project bootstrap default is legacy_tls12
	// (compatible preset, TLSv1.2+TLSv1.3) with OCSP stapling on.
	created, err := f.createSite(f.a, f.a, "tls-profile.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if created.Site.TLSCipherPreset != "compatible" || !created.Site.TLSOCSPStapling || created.Site.TLSClientAuth != "off" ||
		!slices.Equal(created.Site.TLSProtocols, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Fatalf("new site TLS = %+v", created.Site)
	}
	revision := created.Site.Revision
	update := func(fields func(*SiteFields)) (Site, error) {
		t.Helper()
		key := f.key("update")
		request := SiteFields{Domains: []string{"tls-profile.example.test"}, HTTPPorts: []string{"80"},
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
	// An update naming no TLS field keeps all of them.
	kept, err := update(func(*SiteFields) {})
	if err != nil || kept.TLSCipherPreset != "compatible" || !kept.TLSOCSPStapling {
		t.Fatalf("plain update changed TLS: %+v, %v", kept, err)
	}
	legacy, err := update(func(fields *SiteFields) {
		fields.TLSProtocols = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
		fields.TLSCipherPreset = text("legacy")
	})
	if err != nil || legacy.TLSCipherPreset != "legacy" || len(legacy.TLSProtocols) != 4 {
		t.Fatalf("legacy profile: %+v, %v", legacy, err)
	}
	// Stored TLSv1 with a modern preset: only the row shows it is invalid.
	if _, err := update(func(fields *SiteFields) { fields.TLSCipherPreset = text("modern") }); !errors.Is(err, ErrTLSProfileInvalid) {
		t.Fatalf("modern over stored TLSv1: %v, want ErrTLSProfileInvalid", err)
	}
	ca := testClientCAPEM(t)
	verified, err := update(func(fields *SiteFields) {
		fields.TLSProtocols = []string{"TLSv1.3"}
		fields.TLSCipherPreset = text("modern")
		fields.TLSClientAuth, fields.TLSClientCAPEM = text("required"), text(ca)
	})
	if err != nil || verified.TLSClientAuth != "required" || verified.TLSClientCAPEM == "" {
		t.Fatalf("client verification: %+v, %v", verified, err)
	}
	off, err := update(func(fields *SiteFields) { fields.TLSClientAuth = text("off") })
	if err != nil || off.TLSClientAuth != "off" || off.TLSClientCAPEM != "" {
		t.Fatalf("client verification off: %+v, %v", off, err)
	}
	// The audit log moves payload["changes"] into its changes column.
	rows, err := f.pool.Query(context.Background(), `SELECT payload,changes FROM audit_events
		WHERE action='site.tls_profile.update' AND resource_id=$1 ORDER BY stream_position`, created.Site.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type event struct {
		payload map[string]any
		changes map[string][2]any
		raw     string
	}
	var events []event
	for rows.Next() {
		var payloadRaw, changesRaw []byte
		if err := rows.Scan(&payloadRaw, &changesRaw); err != nil {
			t.Fatal(err)
		}
		item := event{payload: map[string]any{}, changes: map[string][2]any{}, raw: string(payloadRaw) + string(changesRaw)}
		var changes []struct {
			Field         string
			Before, After any
		}
		if err := json.Unmarshal(payloadRaw, &item.payload); err != nil || json.Unmarshal(changesRaw, &changes) != nil {
			t.Fatal(err)
		}
		for _, change := range changes {
			item.changes[change.Field] = [2]any{change.Before, change.After}
		}
		events = append(events, item)
	}
	if len(events) != 3 {
		t.Fatalf("TLS audit events = %d, want 3 (legacy, verification on, off): %v", len(events), events)
	}
	digest := events[1].changes["tls_client_ca_sha256"]
	if events[1].payload["ip"] != "198.51.100.9" || digest[0] != "" || len(digest[1].(string)) != 64 ||
		events[1].changes["tls_client_auth"] != [2]any{"off", "required"} {
		t.Fatalf("verification audit = %+v", events[1])
	}
	for _, item := range events {
		if strings.Contains(item.raw, "BEGIN CERTIFICATE") {
			t.Fatal("audit carries the CA bundle")
		}
	}
}
