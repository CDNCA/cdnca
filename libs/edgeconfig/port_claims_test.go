package edgeconfig

import "testing"

func TestFindPortConflictsSharingRules(t *testing.T) {
	plainHTTP := func(owner string) PortClaim {
		return SiteListenerPortClaims(owner, owner+"-site", 443, false, false, nil)[0]
	}
	tlsSite := func(owner string, names ...string) []PortClaim {
		return SiteListenerPortClaims(owner, owner+"-site", 443, true, true, names)
	}
	plainL4 := func(owner string, protocol StreamProtocol) PortClaim {
		return PortClaim{Owner: owner, ID: owner + "-" + string(protocol), Kind: PortClaimPlainL4, Protocol: protocol, Port: 443}
	}
	tlsL4 := func(owner string, names ...string) PortClaim {
		return PortClaim{Owner: owner, ID: owner + "-sni", Kind: PortClaimTLSL4, Protocol: StreamProtocolTCP, Port: 443, Names: names}
	}
	join := func(groups ...[]PortClaim) []PortClaim {
		var claims []PortClaim
		for _, group := range groups {
			claims = append(claims, group...)
		}
		return claims
	}
	one := func(claims ...PortClaim) []PortClaim { return claims }
	for name, c := range map[string]struct {
		claims []PortClaim
		want   string // "" no conflict, otherwise the conflicting name or "socket"
	}{
		"plaintext websites share by Host":    {one(plainHTTP("a"), plainHTTP("b")), ""},
		"plaintext and TLS websites":          {join(one(plainHTTP("a")), tlsSite("b", "b.example")), ""},
		"TLS websites with distinct names":    {join(tlsSite("a", "a.example"), tlsSite("b", "b.example")), ""},
		"TCP and UDP plain L4 on one number":  {one(plainL4("a", StreamProtocolTCP), plainL4("b", StreamProtocolUDP)), ""},
		"plain TCP L4 next to a TLS website":  {join(one(plainL4("a", StreamProtocolTCP)), tlsSite("b", "b.example")[:1]), ""},
		"plain TCP L4 next to TLS L4":         {one(plainL4("a", StreamProtocolTCP), tlsL4("b", "b.example")), ""},
		"TLS L4 next to a plaintext website":  {one(tlsL4("a", "a.example"), plainHTTP("b")), ""},
		"TLS L4 with distinct SNI":            {one(tlsL4("a", "a.example"), tlsL4("b", "b.example")), ""},
		"wildcard next to a name it covers":   {one(tlsL4("a", "*.a.com"), tlsL4("b", "x.a.com")), ""},
		"wildcard next to its own apex":       {one(tlsL4("a", "*.a.com"), tlsL4("b", "a.com")), ""},
		"two plain TCP L4":                    {one(plainL4("a", StreamProtocolTCP), plainL4("b", StreamProtocolTCP)), "socket"},
		"two plain UDP L4":                    {one(plainL4("a", StreamProtocolUDP), plainL4("b", StreamProtocolUDP)), "socket"},
		"plain TCP L4 with a plaintext site":  {one(plainL4("a", StreamProtocolTCP), plainHTTP("b")), "socket"},
		"plain UDP L4 with HTTP/3":            {join(one(plainL4("a", StreamProtocolUDP)), tlsSite("b", "b.example")), "socket"},
		"same SNI on TLS L4":                  {one(tlsL4("a", "x.example"), tlsL4("b", "X.example")), "x.example"},
		"same wildcard on TLS L4":             {one(tlsL4("a", "*.a.com"), tlsL4("b", "*.a.com")), "*.a.com"},
		"TLS L4 SNI on a TLS website domain":  {join(one(tlsL4("a", "b.example")), tlsSite("b", "b.example")[:1]), "b.example"},
		"same owner follows the same rules":   {one(plainL4("a", StreamProtocolTCP), plainHTTP("a")), "socket"},
		"reserved port takes every protocol":  {one(PortClaim{Kind: PortClaimReserved, Protocol: StreamProtocolTCP, Port: 443}, plainL4("a", StreamProtocolUDP)), "socket"},
		"one stream does not conflict itself": {one(tlsL4("a", "a.example"), tlsL4("a", "a.example")), ""},
		"other ports never conflict":          {one(plainL4("a", StreamProtocolTCP), PortClaim{Owner: "b", ID: "b", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 444}), ""},
	} {
		conflicts := FindPortConflicts(c.claims)
		switch {
		case c.want == "" && len(conflicts) != 0:
			t.Errorf("%s: unexpected conflicts %+v", name, conflicts)
		case c.want == "socket" && (len(conflicts) == 0 || conflicts[0].Name != ""):
			t.Errorf("%s: conflicts %+v, want a socket conflict", name, conflicts)
		case c.want != "" && c.want != "socket" && (len(conflicts) == 0 || conflicts[0].Name != c.want):
			t.Errorf("%s: conflicts %+v, want name %q", name, conflicts, c.want)
		}
	}
}

func TestFindPortConflictsRefusesProxyProtocolOnSplitSockets(t *testing.T) {
	proxied := PortClaim{Owner: "a", ID: "a", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 443, ProxyProtocol: true}
	sni := PortClaim{Owner: "b", ID: "b", Kind: PortClaimTLSL4, Protocol: StreamProtocolTCP, Port: 443, Names: []string{"b.example"}}
	site := SiteListenerPortClaims("c", "c", 443, true, true, []string{"c.example"})
	for name, c := range map[string]struct {
		claims []PortClaim
		want   bool
	}{
		"alone":                       {[]PortClaim{proxied}, false},
		"next to a passthrough":       {[]PortClaim{proxied, sni}, true},
		"passthrough with PROXY":      {[]PortClaim{func() PortClaim { c := sni; c.ProxyProtocol = true; return c }(), site[0]}, true},
		"next to a TLS website":       {append([]PortClaim{proxied}, site[0]), true},
		"same number, other protocol": {append([]PortClaim{func() PortClaim { c := proxied; c.Port = 8443; return c }()}, site...), false},
		"one stream, two listeners":   {[]PortClaim{proxied, proxied}, false},
	} {
		conflicts := FindPortConflicts(c.claims)
		got := len(conflicts) == 1 && conflicts[0].ProxyProtocol && conflicts[0].Name == ""
		if got != c.want || (!c.want && len(conflicts) != 0) {
			t.Errorf("%s: conflicts=%+v want PROXY conflict=%t", name, conflicts, c.want)
		}
	}
	stream := passthroughBundleSpec().L4StreamsV2[0]
	stream.ProxyProtocolOutbound = true
	if claims := L4StreamPortClaims("scope", stream); !claims[0].ProxyProtocol {
		t.Fatal("stream claims lost the PROXY flag")
	}
}

func TestL4StreamPortClaimsCoverEveryListener(t *testing.T) {
	stream := passthroughBundleSpec().L4StreamsV2[0]
	claims := L4StreamPortClaims("scope", stream)
	if len(claims) != 2 || claims[0].Kind != PortClaimTLSL4 || claims[1].Port != 18444 || len(claims[1].Names) != len(stream.ServerNames) {
		t.Fatalf("claims=%+v", claims)
	}
	stream.TLSPassthrough, stream.ServerNames = false, nil
	if claims := L4StreamPortClaims("scope", stream); claims[0].Kind != PortClaimPlainL4 || claims[0].Names != nil {
		t.Fatalf("plain claims=%+v", claims)
	}
}
