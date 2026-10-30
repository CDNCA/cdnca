//go:build integration

package migrations_test

import "testing"

// (475): under an active DNS provider mutation claim only what
// breaks the claim's binding is refused (delete, revision, 089 site digest
// columns). 474 still refuses any column outside its IPv6 observation list,
// e.g. the cache status header switch written without a site revision (it is
// not DNS authority, not in the 089 digest); 475 lets it through. n9's 474 test runs on
// a pool migrated to 474 only, so its "other columns stay refused" cases are
// 474's contract, not the head's.
const siteNonAuthorityUpdate475 = `UPDATE sites SET cache_status_header=NOT cache_status_header,updated_at=clock_timestamp() WHERE id=$1`

func TestDNSSiteClaimGuardBinding475(t *testing.T) {
	before := packageCommerceRBAC079Pool(t, dnsSiteClaimGuardVersion-1)
	fixture := seedDNSProviderClaim089(t, before, "n7n8-before")
	insertDNSProviderClaim089(t, before, fixture)
	_, err := before.Exec(t.Context(), siteNonAuthorityUpdate475, fixture.siteID)
	assertDNSProviderClaimCode089(t, err, "P8903")

	pool := packageCommerceRBAC079Pool(t, dnsSiteClaimGuardVersion)
	fixture = seedDNSProviderClaim089(t, pool, "n7n8-after")
	insertDNSProviderClaim089(t, pool, fixture)
	for _, query := range []string{siteNonAuthorityUpdate475, siteIPv6ObservationUpdate474} {
		if command, err := pool.Exec(t.Context(), query, fixture.siteID); err != nil || command.RowsAffected() != 1 {
			t.Fatalf("%s under an active claim = (%v, %v), want one row", query, command, err)
		}
	}
	for _, query := range []string{
		`UPDATE sites SET revision=revision+1 WHERE id=$1`,
		`UPDATE sites SET cache_status_header=NOT cache_status_header,revision=revision+1 WHERE id=$1`,
		`UPDATE sites SET domain='changed.example.test' WHERE id=$1`,
		`UPDATE sites SET origins=ARRAY['192.0.2.55:80'] WHERE id=$1`,
		`DELETE FROM sites WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), query, fixture.siteID)
		assertDNSProviderClaimCode089(t, err, "P8903")
	}
}

func TestDNSSiteClaimGuardBinding475Down(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, dnsSiteClaimGuardVersion)
	if err := migrateVersionIsolated(t.Context(), pool, "down", dnsSiteClaimGuardVersion); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, dnsSiteClaimGuardVersion-1)
	fixture := seedDNSProviderClaim089(t, pool, "n7n8-down")
	insertDNSProviderClaim089(t, pool, fixture)
	_, err := pool.Exec(t.Context(), siteNonAuthorityUpdate475, fixture.siteID)
	assertDNSProviderClaimCode089(t, err, "P8903")
	if _, err := pool.Exec(t.Context(), siteIPv6ObservationUpdate474, fixture.siteID); err != nil {
		t.Fatalf("474 IPv6 observation after 475 down: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", dnsSiteClaimGuardVersion); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, dnsSiteClaimGuardVersion)
}
