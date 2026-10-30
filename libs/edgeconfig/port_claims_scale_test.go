package edgeconfig

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

// referencePortConflicts is the pairwise algorithm FindPortConflicts
// replaced: it defines the expected result (pairs and order).
func referencePortConflicts(claims []PortClaim) []PortConflict {
	sorted := sortPortClaims(claims)
	var conflicts []PortConflict
	for i := range sorted {
		for j := i + 1; j < len(sorted) && sorted[j].Port <= sorted[i].LastPort(); j++ {
			if conflict, ok := portClaimPairConflict(sorted[i], sorted[j]); ok {
				conflicts = append(conflicts, conflict)
			}
		}
	}
	return conflicts
}

// FindPortConflicts returns exactly what the pairwise algorithm returns, on
// random mixes of every claim kind, ranges, PROXY streams and repeated
// names in different case.
func TestFindPortConflictsMatchesPairwiseReference(t *testing.T) {
	random := rand.New(rand.NewSource(20261018))
	kinds := []PortClaimKind{PortClaimPlainHTTP, PortClaimTLSSite, PortClaimQUIC, PortClaimPlainL4, PortClaimTLSL4, PortClaimReserved}
	names := []string{"a.example.test", "A.example.test", "b.example.test", "*.example.test", "c.example.test"}
	for round := 0; round < 400; round++ {
		claims := make([]PortClaim, 1+random.Intn(40))
		for index := range claims {
			claim := PortClaim{
				Owner: fmt.Sprintf("scope-%d", random.Intn(3)), ID: fmt.Sprintf("id-%d", random.Intn(12)),
				Kind: kinds[random.Intn(len(kinds))], Protocol: StreamProtocolTCP, Port: uint16(80 + random.Intn(6)),
				ProxyProtocol: random.Intn(6) == 0,
			}
			if random.Intn(2) == 0 {
				claim.Protocol = StreamProtocolUDP
			}
			if random.Intn(8) == 0 {
				claim.PortEnd = claim.Port + uint16(random.Intn(4))
			}
			for count := random.Intn(3); count > 0; count-- {
				claim.Names = append(claim.Names, names[random.Intn(len(names))])
			}
			claims[index] = claim
		}
		got, want := FindPortConflicts(claims), referencePortConflicts(claims)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: %d conflicts, want %d\ngot  %+v\nwant %+v", round, len(got), len(want), got, want)
		}
	}
}

// 20 000 HTTPS sites (80 + 443 + QUIC, two names each) and a few streams:
// the pairwise algorithm compares ~1.2e9 pairs; this must stay linear.
func TestFindPortConflictsScalesLinearly(t *testing.T) {
	var claims []PortClaim
	for index := 0; index < 20000; index++ {
		siteID := fmt.Sprintf("site-%05d", index)
		domains := []string{fmt.Sprintf("s%05d.example.test", index), fmt.Sprintf("www.s%05d.example.test", index)}
		claims = append(claims, SiteListenerPortClaims("scope", siteID, 80, false, false, nil)...)
		claims = append(claims, SiteListenerPortClaims("scope", siteID, 443, true, true, domains)...)
	}
	// One duplicated name and one plain stream on 80: exactly the expected conflicts.
	claims = append(claims, SiteListenerPortClaims("other", "dup", 443, true, false, []string{"S00007.example.test"})...)
	claims = append(claims, PortClaim{Owner: "other", ID: "stream", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 80})
	started := time.Now()
	conflicts := FindPortConflicts(claims)
	elapsed := time.Since(started)
	if len(conflicts) != 20001 {
		t.Fatalf("%d conflicts, want 20000 (stream vs every plain site) + 1 (duplicated name)", len(conflicts))
	}
	if elapsed > 2*time.Second {
		t.Fatalf("FindPortConflicts on %d claims took %s", len(claims), elapsed)
	}
}
