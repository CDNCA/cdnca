package cnameallocation

import (
	"math/rand/v2"
	"testing"

	"github.com/google/uuid"
)

// fix-cnamerand: a CNAME without a domain draws one of the random-allocation
// zones uniformly (any provider); the draw source is injectable.
func TestChooseZoneDrawsUniformlyAcrossProviders(t *testing.T) {
	providerA, providerB := uuid.New(), uuid.New()
	candidates := []zoneAuthority{
		{providerID: providerA, zoneID: uuid.New(), domain: "a.cdn.example"},
		{providerID: providerB, zoneID: uuid.New(), domain: "b.cdn.example"},
		{providerID: providerB, zoneID: uuid.New(), domain: "c.cdn.example"},
	}
	source := rand.New(rand.NewPCG(1, 2))
	counts := map[string]int{}
	const draws = 30_000
	for range draws {
		counts[chooseZone(candidates, source.IntN).domain]++
	}
	for _, zone := range candidates {
		// Expected 10 000 each; 5% tolerance is far outside PCG noise.
		if got := counts[zone.domain]; got < 9_500 || got > 10_500 {
			t.Fatalf("%s drawn %d of %d times: %v", zone.domain, got, draws, counts)
		}
	}
}

func TestChooseZoneUsesThePickedIndex(t *testing.T) {
	candidates := []zoneAuthority{{domain: "a.cdn.example"}, {domain: "b.cdn.example"}}
	if got := chooseZone(candidates, func(int) int { return 1 }); got.domain != "b.cdn.example" {
		t.Fatalf("picked %q", got.domain)
	}
	// A broken source cannot index outside the candidates.
	if got := chooseZone(candidates, func(int) int { return 7 }); got.domain != "a.cdn.example" {
		t.Fatalf("out-of-range pick gave %q", got.domain)
	}
	if got := chooseZone(candidates[:1], nil); got.domain != "a.cdn.example" {
		t.Fatalf("single candidate gave %q", got.domain)
	}
}

func TestNewStoreDrawsZonesAtRandomByDefault(t *testing.T) {
	store := &Store{}
	if store.zonePick() == nil {
		t.Fatal("store has no zone draw source")
	}
	store.UseZonePick(func(int) int { return 0 })
	if store.zonePick()(5) != 0 {
		t.Fatal("injected draw source not used")
	}
}
