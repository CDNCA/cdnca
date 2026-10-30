//go:build integration

package migrations_test

import (
	"testing"
)

// Reproduction: while a DNS provider mutation claim is active the
// rollout-terminal IPv6 observation write (edgedeployment/
// site_ipv6_projection.go) was refused with P8903, rolling back the healthy
// status projection that carried it; the status was redelivered forever and
// never stored. 474 lets the observation columns through and keeps every
// authority change refused.
const siteIPv6ObservationUpdate474 = `UPDATE sites
	SET ipv6_runtime_state='disabled', ipv6_runtime_source_revision=ipv6_runtime_source_revision+1,
	    updated_at=GREATEST(updated_at, statement_timestamp())
	WHERE id=$1`

func TestSiteClaimGuardRuntimeObservation474(t *testing.T) {
	before := packageCommerceRBAC079Pool(t, siteClaimGuardObservationVersion-1)
	fixture := seedDNSProviderClaim089(t, before, "n9-before")
	insertDNSProviderClaim089(t, before, fixture)
	_, err := before.Exec(t.Context(), siteIPv6ObservationUpdate474, fixture.siteID)
	assertDNSProviderClaimCode089(t, err, "P8903")

	pool := packageCommerceRBAC079Pool(t, siteClaimGuardObservationVersion)
	fixture = seedDNSProviderClaim089(t, pool, "n9-after")
	insertDNSProviderClaim089(t, pool, fixture)
	command, err := pool.Exec(t.Context(), siteIPv6ObservationUpdate474, fixture.siteID)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("IPv6 observation update under an active claim = (%v, %v), want one row", command, err)
	}
	var state string
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT ipv6_runtime_state, ipv6_runtime_source_revision FROM sites WHERE id=$1`,
		fixture.siteID).Scan(&state, &revision); err != nil || state != "disabled" || revision != 1 {
		t.Fatalf("site observation = (%q, %d, %v)", state, revision, err)
	}
	for _, query := range []string{
		`UPDATE sites SET revision=revision+1 WHERE id=$1`,
		`UPDATE sites SET domain='changed.example.test',revision=revision+1 WHERE id=$1`,
		`UPDATE sites SET ipv6_enabled=NOT ipv6_enabled WHERE id=$1`,
		`UPDATE sites SET ipv6_runtime_state='active', origins=ARRAY['192.0.2.55:80'] WHERE id=$1`,
		`DELETE FROM sites WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), query, fixture.siteID)
		assertDNSProviderClaimCode089(t, err, "P8903")
	}
}

func TestSiteClaimGuardRuntimeObservation474Down(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, siteClaimGuardObservationVersion)
	if err := migrateVersionIsolated(t.Context(), pool, "down", siteClaimGuardObservationVersion); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, siteClaimGuardObservationVersion-1)
	fixture := seedDNSProviderClaim089(t, pool, "n9-down")
	insertDNSProviderClaim089(t, pool, fixture)
	_, err := pool.Exec(t.Context(), siteIPv6ObservationUpdate474, fixture.siteID)
	assertDNSProviderClaimCode089(t, err, "P8903")
}
