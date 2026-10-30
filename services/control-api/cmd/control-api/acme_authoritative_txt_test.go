package main

import "testing"

func TestACMEAuthoritativeTXTCheckerFollowsBootstrapResolvers(t *testing.T) {
	env := func(values map[string]string) accountRecoveryEnvLookup {
		return func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	}
	if checker, err := acmeAuthoritativeTXTChecker(env(nil)); checker != nil || err != nil {
		t.Fatalf("without bootstrap resolvers = %v, %v", checker, err)
	}
	checker, err := acmeAuthoritativeTXTChecker(env(map[string]string{
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS": "cloudflare=1.1.1.1:53,google=8.8.8.8:53"}))
	if checker == nil || err != nil {
		t.Fatalf("installer default = %v, %v", checker, err)
	}
	if _, err := acmeAuthoritativeTXTChecker(env(map[string]string{
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS": "local=127.0.0.1:53"})); err == nil {
		t.Fatal("a loopback bootstrap resolver was accepted")
	}
}
