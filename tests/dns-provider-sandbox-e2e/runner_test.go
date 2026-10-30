package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderlive"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

func TestRecordLifecycleJournalsMutationsAndRecoversLostResponses(t *testing.T) {
	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	evidence := batchEvidence{
		Schema: evidenceSchema, Status: "running", Reason: "running",
		Providers: []providerEvidence{{Code: "cloudflare", Status: "running", Reason: "running"}},
	}
	writer := evidenceWriter{path: evidencePath}
	if err := writer.write(evidence); err != nil {
		t.Fatal(err)
	}
	remote := &lostResponseRemote{t: t, evidencePath: evidencePath}
	waits := 0
	waiter := func(_ context.Context, _ preparedProvider, _ string, recordType dnscheck.RecordType, value string, present bool) (bool, bool) {
		waits++
		if recordType != dnscheck.RecordAAAA || value != "2001:db8::11" {
			t.Fatalf("unexpected DNS observation: type=%s value=%q", recordType, value)
		}
		return true, true
	}
	spec := recordLifecycleSpec{
		Kind: "aaaa_record", Type: dnscheck.RecordAAAA,
		Initial: "2001:db8::10", Updated: "2001:db8::11",
	}
	prepared := preparedProvider{input: providerInput{Code: "cloudflare", TTL: 300, UpdatedTTL: 600, CleanupTimeoutSeconds: 60}}
	if !runRecordLifecycle(
		context.Background(), prepared, remote, dnsproviderremote.ProviderConfig{}, spec,
		"record.example.test.", "0123456789abcdef0123456789abcdef", 0, writer, &evidence, waiter, false,
	) {
		t.Fatalf("runRecordLifecycle() failed: %+v", evidence)
	}
	if waits != 2 {
		t.Fatalf("DNS waits = %d, want present and absent", waits)
	}
	if remote.mutations != 3 {
		t.Fatalf("mutations = %d, want create/update/delete", remote.mutations)
	}
	if len(evidence.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(evidence.Resources))
	}
	resource := evidence.Resources[0]
	if resource.State != "absent" || resource.Revision != 3 || resource.ProviderIdentitySHA256 == "" {
		t.Fatalf("resource = %+v", resource)
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"provider-record-1", "2001:db8::10", "2001:db8::11", "record.example.test"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("evidence leaked %q", forbidden)
		}
	}
}

func TestRecordObservationQueriesAuthorityBeforeTwoPublicResolvers(t *testing.T) {
	prepared := preparedProvider{
		authority: []dnsproviderlive.Endpoint{{Address: netip.MustParseAddrPort("192.0.2.53:53")}},
		public: []dnsproviderlive.Endpoint{
			{Address: netip.MustParseAddrPort("198.51.100.53:53")},
			{Address: netip.MustParseAddrPort("203.0.113.53:53")},
		},
	}
	resolver := &orderedResolver{}
	authority, public := waitForRecordStateWithResolver(
		context.Background(), prepared, resolver, "record.example.test.", dnscheck.RecordCNAME,
		"target.example.test.", true,
	)
	if !authority || !public {
		t.Fatalf("convergence = authority:%v public:%v", authority, public)
	}
	want := []string{"192.0.2.53", "198.51.100.53", "203.0.113.53"}
	if !equalStrings(resolver.calls, want) {
		t.Fatalf("resolver order = %v, want %v", resolver.calls, want)
	}
}

type lostResponseRemote struct {
	t            *testing.T
	evidencePath string
	mutations    int
	state        string
}

func (remote *lostResponseRemote) Lookup(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	switch operation.Action {
	case dnscheck.ProviderDelete:
		return dnsproviderremote.ReconcileLookup{TargetComplete: remote.state == "absent", RecordID: operation.RecordID}, nil
	case dnscheck.ProviderCreate:
		return dnsproviderremote.ReconcileLookup{TargetComplete: remote.state == "initial", RecordID: "provider-record-1"}, nil
	case dnscheck.ProviderUpdate:
		return dnsproviderremote.ReconcileLookup{TargetComplete: remote.state == "updated", RecordID: "provider-record-1"}, nil
	default:
		return dnsproviderremote.ReconcileLookup{}, errors.New("unexpected action")
	}
}

func (remote *lostResponseRemote) Mutate(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	remote.mutations++
	raw, err := os.ReadFile(remote.evidencePath)
	if err != nil {
		remote.t.Fatal(err)
	}
	var current batchEvidence
	if err := json.Unmarshal(raw, &current); err != nil {
		remote.t.Fatal(err)
	}
	steps := current.Providers[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].Status != "pending" || steps[len(steps)-1].Reason != "mutation_journaled" {
		remote.t.Fatalf("mutation %s began without durable journal: %+v", operation.Action, steps)
	}
	switch operation.Action {
	case dnscheck.ProviderCreate:
		remote.state = "initial"
		return "provider-record-1", nil
	case dnscheck.ProviderUpdate:
		remote.state = "updated"
		return "", errors.New("response lost")
	case dnscheck.ProviderDelete:
		remote.state = "absent"
		return "", errors.New("response lost")
	default:
		remote.t.Fatalf("unexpected mutation action %s", operation.Action)
		return "", errors.New("unexpected action")
	}
}

type orderedResolver struct{ calls []string }

func (resolver *orderedResolver) Resolve(_ context.Context, endpoint dnscheck.ResolverEndpoint, query dnscheck.DNSQuery) (dnscheck.DNSResponse, error) {
	resolver.calls = append(resolver.calls, endpoint.Address.String())
	return dnscheck.DNSResponse{
		Authoritative: endpoint.Address == netip.MustParseAddr("192.0.2.53"),
		RCode:         0,
		Answers:       []dnscheck.DNSRecord{{Name: query.Name, Type: query.Type, TTL: 60, Value: "target.example.test."}},
	}, nil
}

var _ dnsproviderremote.ReconcileRemote = (*lostResponseRemote)(nil)
var _ dnscheck.Resolver = (*orderedResolver)(nil)
