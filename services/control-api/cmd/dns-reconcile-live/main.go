// Command dns-reconcile-live proves the production DNS write path against a
// real provider zone: the reconcile remote creates a platform A record set and
// a site CNAME, re-targets the set the way a paused node does, and the
// production propagation engine verifies each state on the zone's NS-discovered
// authoritative servers plus the installer's public resolvers (2 of 3).
//
// It only ever touches owners named cdnca-test-<random>.<zone> and
// cdnca-test-<random>-site.<zone>, deletes them before exiting, and never prints
// the credential. Cloudflare only for now.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

const (
	envAck       = "CDNCA_DNS_RECONCILE_LIVE_ACK"
	envZone      = "CDNCA_DNS_RECONCILE_LIVE_ZONE"
	envTokenFile = "CDNCA_DNS_RECONCILE_LIVE_CLOUDFLARE_TOKEN_FILE"
	requiredAck  = "only-cdnca-test-records"
	testPrefix   = "cdnca-test-"
	recordTTL    = 60
)

// Same resolvers and quorum as install-control.sh writes for native consoles.
var resolvers = []dnspropagation.Resolver{
	{ID: "1.1.1.1:53", Name: "cloudflare"}, {ID: "8.8.8.8:53", Name: "google"}, {ID: "223.5.5.5:53", Name: "alidns"},
}

type noMetrics struct{}

func (noMetrics) Record(dnspropagation.Metric) {}

type live struct {
	config  dnsproviderremote.ProviderConfig
	remote  dnsproviderremote.ReconcileRemote
	engine  *dnspropagation.Engine
	tenant  uuid.UUID
	created map[string]dnscheck.ProviderOperation // record ID -> last written state
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Println("RESULT fail:", err)
		os.Exit(1)
	}
	fmt.Println("RESULT pass")
}

func run(ctx context.Context) error {
	zone := strings.ToLower(strings.TrimSuffix(os.Getenv(envZone), "."))
	if os.Getenv(envAck) != requiredAck || zone == "" || strings.ContainsAny(zone, " /") {
		return errors.New("set " + envAck + "=" + requiredAck + " and " + envZone)
	}
	token, err := os.ReadFile(os.Getenv(envTokenFile))
	if err != nil {
		return errors.New("credential file is unreadable")
	}
	session, err := newLive(zone, strings.TrimSpace(string(token)))
	clear(token)
	if err != nil {
		return err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	label := testPrefix + hex.EncodeToString(suffix)
	target := label + "." + zone + "."    // platform-owned label the CNAME worker publishes
	site := label + "-site." + zone + "." // stands in for the customer's site hostname
	defer session.cleanup()
	return session.scenario(ctx, site, target)
}

func newLive(zone, token string) (*live, error) {
	tenant, scope := uuid.New(), uuid.New()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	source, err := dnspropagation.NewWireSource(dnspropagation.WireSourceConfig{
		Bootstrap: resolvers, DialContext: dialer.DialContext, QueryTimeout: 5 * time.Second,
		MaximumResponseBytes: 4096, Now: time.Now, FamilyAvailable: dnspropagation.LocalAddressFamilies(),
	})
	if err != nil {
		return nil, err
	}
	engine, err := dnspropagation.NewEngine(dnspropagation.Config{
		Source: source, Public: resolvers, PublicQuorum: 2, MinTTL: time.Second, MaxTTL: 7 * 24 * time.Hour,
		MinNegativeTTL: time.Second, MaxNegativeTTL: 24 * time.Hour, MaxAge: 30 * time.Second, Now: time.Now,
		Metrics: noMetrics{},
	})
	if err != nil {
		return nil, err
	}
	return &live{
		config: dnsproviderremote.ProviderConfig{
			TenantID: tenant, ScopeID: scope, TenantScopeID: scope, ProviderID: uuid.New(), ProviderType: "cloudflare",
			ZoneID: uuid.New(), ZoneName: zone, Credentials: map[string]string{"api_token": token},
		},
		remote: dnsproviderremote.NewReconcileRemote(), engine: engine, tenant: tenant,
		created: map[string]dnscheck.ProviderOperation{},
	}, nil
}

// TEST-NET-3 documentation addresses: never routable, safe to publish.
const nodeA, nodeB, nodeC = "203.0.113.10", "203.0.113.11", "203.0.113.12"

func (session *live) scenario(ctx context.Context, site, target string) error {
	fmt.Printf("OWNERS target=%s site=%s\n", target, site)
	ids := map[string]string{}
	for _, value := range []string{nodeA, nodeB} {
		id, err := session.mutate(ctx, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
			Name: target, Type: dnscheck.RecordA, Value: value, TTL: recordTTL})
		if err != nil {
			return err
		}
		ids[value] = id
	}
	if _, err := session.mutate(ctx, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: site, Type: dnscheck.RecordCNAME, Value: target, TTL: recordTTL}); err != nil {
		return err
	}
	if err := session.verifyAll(ctx, "create", site, target, nodeA, nodeB); err != nil {
		return err
	}
	// Node B paused: its endpoint leaves the serving set and node C takes over.
	if _, err := session.mutate(ctx, dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate,
		RecordID: ids[nodeB], Name: target, Type: dnscheck.RecordA, Value: nodeC, TTL: recordTTL,
		PreviousValue: nodeB, PreviousTTL: recordTTL}); err != nil {
		return err
	}
	if err := session.verifyAll(ctx, "retarget-replace", site, target, nodeA, nodeC); err != nil {
		return err
	}
	// Node A auto-disabled with no replacement: the set shrinks to node C.
	if _, err := session.mutate(ctx, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete,
		RecordID: ids[nodeA], Name: target, Type: dnscheck.RecordA, Value: nodeA, TTL: recordTTL}); err != nil {
		return err
	}
	return session.verifyAll(ctx, "retarget-shrink", site, target, nodeC)
}

// mutate writes through the production reconcile remote, then confirms the
// provider state with an exact record-ID lookup.
func (session *live) mutate(ctx context.Context, operation dnscheck.ProviderOperation) (string, error) {
	if !owned(operation.Name, session.config.ZoneName) {
		return "", errors.New("refusing to touch a non-test owner")
	}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	id, err := session.remote.Mutate(callCtx, session.config, operation)
	if err != nil {
		return "", fmt.Errorf("%s %s %s: %w", operation.Action, operation.Type, operation.Name, err)
	}
	confirm := operation
	confirm.RecordID = id
	if operation.Action == dnscheck.ProviderCreate {
		confirm.Action = dnscheck.ProviderUpdate
		confirm.PreviousValue, confirm.PreviousTTL = operation.Value, operation.TTL
		session.created[id] = confirm // tracked before confirming so cleanup never leaks it
	}
	lookup, err := session.remote.Lookup(callCtx, session.config, confirm)
	if err != nil || !lookup.TargetComplete || lookup.Conflict || lookup.Ambiguous {
		return "", fmt.Errorf("provider confirm %s %s failed: %+v %v", operation.Action, operation.Name, lookup, err)
	}
	if operation.Action == dnscheck.ProviderDelete {
		delete(session.created, id)
	} else {
		session.created[id] = confirm
	}
	fmt.Printf("PROVIDER %s %s %s %s ok\n", operation.Action, operation.Type, operation.Name, operation.Value)
	return id, nil
}

func (session *live) verifyAll(ctx context.Context, phase, site, target string, values ...string) error {
	if err := session.verify(ctx, phase, target, []dnspropagation.RRSet{{Type: dnscheck.RecordA, Values: values}}); err != nil {
		return err
	}
	return session.verify(ctx, phase, site, []dnspropagation.RRSet{{Type: dnscheck.RecordCNAME, Values: []string{target}}})
}

// verify polls the production propagation engine until the authoritative
// servers (from the zone's NS) and 2 of 3 public resolvers serve exactly expected.
func (session *live) verify(ctx context.Context, phase, name string, expected []dnspropagation.RRSet) error {
	sort.Strings(expected[0].Values)
	deadline := time.Now().Add(6 * time.Minute)
	for attempt := 1; ; attempt++ {
		observeCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		result, err := session.engine.Observe(observeCtx, dnspropagation.Request{
			TenantID: session.tenant, ZoneID: session.config.ZoneID, OperationID: "live-" + phase,
			Zone: session.config.ZoneName + ".", Name: name, Expected: expected,
		})
		cancel()
		if err == nil && result.Success {
			fmt.Printf("VERIFIED %s %s %s=%v authoritative=%d public=%d/%d attempts=%d\n", phase, name,
				expected[0].Type, expected[0].Values, result.AuthoritativeVotes, result.PublicVotes, len(resolvers), attempt)
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%s %s not converged: reason=%s err=%v", phase, name, result.Reason, err)
		}
		fmt.Printf("WAIT %s %s reason=%s err=%v\n", phase, name, result.Reason, err)
		select {
		case <-ctx.Done():
		case <-time.After(15 * time.Second):
		}
	}
}

func (session *live) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for id, operation := range session.created {
		operation.Action, operation.RecordID = dnscheck.ProviderDelete, id
		if _, err := session.mutate(ctx, operation); err != nil {
			fmt.Println("CLEANUP failed:", err)
			continue
		}
	}
	fmt.Printf("CLEANUP remaining=%d\n", len(session.created))
	session.config.Credentials["api_token"] = ""
}

func owned(name, zone string) bool {
	relative, found := strings.CutSuffix(name, "."+zone+".")
	return found && strings.HasPrefix(relative, testPrefix) && !strings.Contains(relative, ".")
}
