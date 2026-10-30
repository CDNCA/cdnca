package dnscheck

import (
	"errors"
	"testing"
	"time"
)

func TestNewCheckerRejectsDuplicateResolverVoteIdentity(t *testing.T) {
	t.Parallel()

	udpOne := resolverEndpointForIdentityTest(t, "udp", "192.0.2.53", 53)
	tcpOne := resolverEndpointForIdentityTest(t, "tcp", "192.0.2.53", 53)
	udpTwo := resolverEndpointForIdentityTest(t, "udp", "192.0.2.54", 53)
	udpOtherPort := resolverEndpointForIdentityTest(t, "udp", "192.0.2.53", 5353)

	tests := []struct {
		name          string
		authoritative []NamedResolver
		public        []NamedResolver
		wantErr       bool
	}{
		{
			name: "authoritative same transport",
			authoritative: []NamedResolver{
				{Name: "ns1.example.test", Endpoint: udpOne},
				{Name: "ns2.example.test", Endpoint: udpOne},
			},
			public:  []NamedResolver{{Name: "public-a", Endpoint: udpTwo}},
			wantErr: true,
		},
		{
			name:          "public same transport",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpTwo}},
			public: []NamedResolver{
				{Name: "public-a", Endpoint: udpOne},
				{Name: "public-b", Endpoint: udpOne},
			},
			wantErr: true,
		},
		{
			name:          "across roles same transport",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpOne}},
			public:        []NamedResolver{{Name: "public-a", Endpoint: udpOne}},
			wantErr:       true,
		},
		{
			name: "authoritative ignores transport",
			authoritative: []NamedResolver{
				{Name: "ns1.example.test", Endpoint: udpOne},
				{Name: "ns2.example.test", Endpoint: tcpOne},
			},
			public:  []NamedResolver{{Name: "public-a", Endpoint: udpTwo}},
			wantErr: true,
		},
		{
			name:          "public ignores transport",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpTwo}},
			public: []NamedResolver{
				{Name: "public-a", Endpoint: udpOne},
				{Name: "public-b", Endpoint: tcpOne},
			},
			wantErr: true,
		},
		{
			name:          "across roles ignores transport",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpOne}},
			public:        []NamedResolver{{Name: "public-a", Endpoint: tcpOne}},
			wantErr:       true,
		},
		{
			name:          "distinct address accepted",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpOne}},
			public:        []NamedResolver{{Name: "public-a", Endpoint: udpTwo}},
		},
		{
			name:          "distinct port accepted",
			authoritative: []NamedResolver{{Name: "ns1.example.test", Endpoint: udpOne}},
			public:        []NamedResolver{{Name: "public-a", Endpoint: udpOtherPort}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoints := make([]ResolverEndpoint, 0, len(test.authoritative)+len(test.public))
			for _, resolver := range test.authoritative {
				endpoints = append(endpoints, resolver.Endpoint)
			}
			for _, resolver := range test.public {
				endpoints = append(endpoints, resolver.Endpoint)
			}
			policy, err := NewEndpointPolicy(endpoints...)
			if err != nil {
				t.Fatalf("NewEndpointPolicy() error = %v", err)
			}

			_, err = NewChecker(Config{
				Resolver:               newFakeResolver(),
				EndpointPolicy:         policy,
				AuthoritativeResolvers: test.authoritative,
				PublicResolvers:        test.public,
				QueryTimeout:           time.Second,
				Attempts:               1,
				MaxCNAMEDepth:          1,
			})
			if test.wantErr && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewChecker() error = %v, want %v", err, ErrInvalidInput)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("NewChecker() error = %v, want nil", err)
			}
		})
	}
}

func resolverEndpointForIdentityTest(t *testing.T, network, address string, port uint16) ResolverEndpoint {
	t.Helper()
	endpoint, err := NewResolverEndpoint(network, address, port)
	if err != nil {
		t.Fatalf("NewResolverEndpoint() error = %v", err)
	}
	return endpoint
}
