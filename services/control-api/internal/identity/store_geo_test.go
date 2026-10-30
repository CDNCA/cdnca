package identity

import (
	"context"
	"testing"
)

type testGeoResolver struct {
	value GeoAttribution
	err   error
}

func (resolver testGeoResolver) Resolve(context.Context, string) (GeoAttribution, error) {
	return resolver.value, resolver.err
}

func TestStoreLoginGeoUsesValidatedResolverAttribution(t *testing.T) {
	store := &Store{geoResolver: testGeoResolver{value: GeoAttribution{
		CountryCode: "CN", Region: "湖南省", City: "长沙市", Resolution: "matched",
	}}}
	if got := store.loginGeo(context.Background(), "192.0.2.1"); got.CountryCode != "CN" || got.Region != "湖南省" || got.City != "长沙市" || got.Resolution != "matched" {
		t.Fatalf("resolved login geography = %+v", got)
	}
}

func TestStoreLoginGeoFailsClosedForInvalidResolverAttribution(t *testing.T) {
	store := &Store{geoResolver: testGeoResolver{value: GeoAttribution{
		CountryCode: "cn", Region: "湖南省", City: "长沙市", Resolution: "matched",
	}}}
	if got := store.loginGeo(context.Background(), "192.0.2.1"); got.CountryCode != "unknown" || got.Resolution != "unknown" {
		t.Fatalf("invalid login geography = %+v", got)
	}
}
