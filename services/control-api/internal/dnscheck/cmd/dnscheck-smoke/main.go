package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

const (
	answerCorrect  = 1
	answerWrong    = 2
	answerNXDOMAIN = 3
)

type localDNSServer struct {
	connection    *net.UDPConn
	authoritative bool
	mu            sync.RWMutex
	mode          int
}

type localProvider struct {
	mu        sync.Mutex
	revision  int64
	request   dnscheck.CheckRequest
	servers   []*localDNSServer
	mutations []dnscheck.ProviderMutation
}

func (p *localProvider) CurrentRevision(ctx context.Context, request dnscheck.ProviderRevisionRequest) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if request.TenantID != p.request.TenantID || request.SiteID != p.request.SiteID || request.ZoneID != p.request.Provider.ZoneID {
		return 0, &dnscheck.ProviderError{Class: dnscheck.ProviderErrorPermanent, Code: "scope_mismatch"}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision, nil
}

func (p *localProvider) Mutate(ctx context.Context, mutation dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	if err := ctx.Err(); err != nil {
		return dnscheck.ProviderMutationResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if mutation.TenantID != p.request.TenantID || mutation.SiteID != p.request.SiteID || mutation.ZoneID != p.request.Provider.ZoneID {
		return dnscheck.ProviderMutationResult{}, &dnscheck.ProviderError{Class: dnscheck.ProviderErrorPermanent, Code: "scope_mismatch"}
	}
	if mutation.ExpectedRevision != p.revision {
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	p.mutations = append(p.mutations, mutation)
	p.revision++
	call := len(p.mutations)
	recordID := mutation.Operation.RecordID
	if mutation.Operation.Action == dnscheck.ProviderCreate {
		recordID = "smoke-created-record"
		p.servers[0].setMode(answerCorrect)
		p.servers[1].setMode(answerWrong)
		p.servers[2].setMode(answerWrong)
		p.servers[3].setMode(answerWrong)
	}
	return dnscheck.ProviderMutationResult{
		ProviderRequestID: fmt.Sprintf("smoke-provider-request-%d", call),
		RecordID:          recordID,
		Revision:          p.revision,
	}, nil
}

func (p *localProvider) snapshot() (int64, []dnscheck.ProviderMutation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision, append([]dnscheck.ProviderMutation(nil), p.mutations...)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dns-check smoke failed:", err)
		os.Exit(1)
	}
}

func run() error {
	servers := make([]*localDNSServer, 0, 4)
	for _, authoritative := range []bool{true, true, false, false} {
		server, err := startLocalDNSServer(authoritative)
		if err != nil {
			closeServers(servers)
			return err
		}
		servers = append(servers, server)
	}
	defer closeServers(servers)

	endpoints := make([]dnscheck.ResolverEndpoint, 0, len(servers))
	for _, server := range servers {
		address := server.connection.LocalAddr().(*net.UDPAddr)
		endpoint, err := dnscheck.NewResolverEndpoint("udp", address.IP.String(), uint16(address.Port))
		if err != nil {
			return err
		}
		endpoints = append(endpoints, endpoint)
	}
	policy, err := dnscheck.NewEndpointPolicy(endpoints...)
	if err != nil {
		return err
	}
	resolver, err := dnscheck.NewNetworkResolver(policy, dnscheck.NetworkResolverOptions{MaximumResponseBytes: 4096})
	if err != nil {
		return err
	}
	checker, err := dnscheck.NewChecker(dnscheck.Config{
		Resolver:       resolver,
		EndpointPolicy: policy,
		AuthoritativeResolvers: []dnscheck.NamedResolver{
			{Name: "ns-a.smoke.test", Endpoint: endpoints[0]},
			{Name: "ns-b.smoke.test", Endpoint: endpoints[1]},
		},
		PublicResolvers: []dnscheck.NamedResolver{
			{Name: "recursive-a", Endpoint: endpoints[2]},
			{Name: "recursive-b", Endpoint: endpoints[3]},
		},
		QueryTimeout:  250 * time.Millisecond,
		Attempts:      2,
		MaxCNAMEDepth: 8,
		Now:           time.Now,
	})
	if err != nil {
		return err
	}

	for _, server := range servers {
		server.setMode(answerCorrect)
	}
	if err := checkScenario(checker, request(nil, answerCorrect), "correct", dnscheck.ClassificationHealthy, 0); err != nil {
		return err
	}
	for _, server := range servers {
		server.setMode(answerWrong)
	}
	if err := checkScenario(checker, request(nil, answerWrong), "wrong", dnscheck.ClassificationWrongValue, 1); err != nil {
		return err
	}
	servers[0].setMode(answerCorrect)
	servers[1].setMode(answerWrong)
	servers[2].setMode(answerCorrect)
	servers[3].setMode(answerCorrect)
	if err := checkScenario(checker, request(nil, answerCorrect), "split-authority", dnscheck.ClassificationAuthorityInconsistent, 0); err != nil {
		return err
	}
	for _, server := range servers {
		server.setMode(answerNXDOMAIN)
	}
	if err := checkScenario(checker, request(nil, answerCorrect), "nxdomain", dnscheck.ClassificationNXDOMAIN, 0); err != nil {
		return err
	}
	servers[0].setMode(answerCorrect)
	servers[1].setMode(answerCorrect)
	servers[2].setMode(answerWrong)
	servers[3].setMode(answerWrong)
	started := time.Now().UTC().Add(-time.Minute)
	if err := checkScenario(checker, request(&started, answerCorrect), "propagating", dnscheck.ClassificationPublicPropagating, 0); err != nil {
		return err
	}
	servers[2].setMode(answerCorrect)
	servers[3].setMode(answerCorrect)
	if err := checkScenario(checker, request(&started, answerCorrect), "converged", dnscheck.ClassificationHealthy, 0); err != nil {
		return err
	}
	if err := checkReconciliation(checker, servers); err != nil {
		return err
	}
	return nil
}

func checkReconciliation(checker *dnscheck.Checker, servers []*localDNSServer) error {
	for _, server := range servers {
		server.setMode(answerWrong)
	}
	checkRequest := request(nil, answerWrong)
	provider := &localProvider{revision: checkRequest.Provider.Revision, request: checkRequest, servers: servers}
	reconciler, err := dnscheck.NewReconciler(dnscheck.ReconcilerConfig{
		Checker:             checker,
		Provider:            provider,
		ProviderAttempts:    2,
		ProviderTimeout:     250 * time.Millisecond,
		PollAttempts:        4,
		RequiredConsecutive: 2,
		InitialBackoff:      time.Millisecond,
		MaximumBackoff:      2 * time.Millisecond,
		OverallTimeout:      3 * time.Second,
		JitterFraction:      0,
		Now:                 time.Now,
		Random:              func() float64 { return 0.5 },
		Sleep: func(ctx context.Context, _ time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, server := range servers {
				server.setMode(answerCorrect)
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	reconcileRequest := dnscheck.ReconcileRequest{IdempotencyKey: "dns-smoke-reconcile", Check: checkRequest}
	dryRun, err := reconciler.DryRun(reconcileRequest)
	if err != nil {
		return fmt.Errorf("reconcile dry-run: %w", err)
	}
	_, mutations := provider.snapshot()
	if dryRun.Status != dnscheck.TaskDryRun || len(mutations) != 0 {
		return fmt.Errorf("reconcile dry-run status=%s mutations=%d", dryRun.Status, len(mutations))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	applied, err := reconciler.Apply(ctx, reconcileRequest)
	if err != nil {
		return fmt.Errorf("reconcile apply: %w", err)
	}
	_, mutations = provider.snapshot()
	if applied.Status != dnscheck.TaskReadyToCommit || len(applied.Propagation) != 3 ||
		applied.Propagation[0].Status != dnscheck.ClassificationAuthorityInconsistent ||
		len(applied.Operations) != 1 || applied.Operations[0].Status != dnscheck.OperationSucceeded ||
		applied.Operations[0].ClientRequestID == "" || applied.Operations[0].ProviderRequestID == "" ||
		len(applied.DeferredDeletes) != 1 || applied.DeferredDeletes[0].Status != dnscheck.OperationDeferred ||
		applied.DeferredDeletes[0].ClientRequestID != "" || len(mutations) != 1 ||
		mutations[0].Operation.Action != dnscheck.ProviderCreate {
		return fmt.Errorf("reconcile apply status=%s propagation=%v operations=%v deferred=%v mutations=%v", applied.Status, applied.Propagation, applied.Operations, applied.DeferredDeletes, mutations)
	}

	committed, err := reconciler.Commit(ctx, dnscheck.CommitRequest{
		TenantID:       applied.TenantID,
		SiteID:         applied.SiteID,
		IdempotencyKey: reconcileRequest.IdempotencyKey,
		PayloadDigest:  applied.PayloadDigest,
	})
	if err != nil {
		return fmt.Errorf("reconcile commit: %w", err)
	}
	revision, mutations := provider.snapshot()
	if committed.Status != dnscheck.TaskCommitted || revision != checkRequest.Provider.Revision+2 ||
		len(mutations) != 2 || mutations[1].Operation.Action != dnscheck.ProviderDelete ||
		mutations[1].ClientRequestID == "" || committed.DeferredDeletes[0].ProviderRequestID == "" {
		return fmt.Errorf("reconcile commit status=%s revision=%d deferred=%v mutations=%v", committed.Status, revision, committed.DeferredDeletes, mutations)
	}
	fmt.Printf("scenario=reconcile status=%s propagation=%d mutations=%d\n", committed.Status, len(applied.Propagation), len(mutations))
	return nil
}

func request(started *time.Time, providerMode int) dnscheck.CheckRequest {
	providerValue := "192.0.2.10"
	if providerMode == answerWrong {
		providerValue = "192.0.2.20"
	}
	return dnscheck.CheckRequest{
		TenantID:             uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		SiteID:               uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Name:                 "www.smoke.test",
		Expected:             []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"192.0.2.10"}}},
		AuthoritativeNS:      []string{"ns-a.smoke.test", "ns-b.smoke.test"},
		TTL:                  60,
		PropagationStartedAt: started,
		PropagationWindow:    5 * time.Minute,
		Provider: dnscheck.ProviderSnapshot{
			TenantID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
			SiteID:   uuid.MustParse("22222222-2222-4222-8222-222222222222"),
			ZoneID:   uuid.MustParse("33333333-3333-4333-8333-333333333333"),
			Revision: 9,
			Records: []dnscheck.ProviderRecord{{
				RecordID: "smoke-record-a", Name: "www.smoke.test", Type: dnscheck.RecordA, Value: providerValue, TTL: 60,
			}},
		},
	}
}

func checkScenario(checker *dnscheck.Checker, request dnscheck.CheckRequest, name string, expected dnscheck.Classification, operations int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := checker.Check(ctx, request)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if result.Status != expected || len(result.RepairPlan.Operations) != operations {
		return fmt.Errorf("%s: status=%s operations=%d, want status=%s operations=%d", name, result.Status, len(result.RepairPlan.Operations), expected, operations)
	}
	fmt.Printf("scenario=%s status=%s observations=%d operations=%d\n", name, result.Status, len(result.Observations), len(result.RepairPlan.Operations))
	return nil
}

func startLocalDNSServer(authoritative bool) (*localDNSServer, error) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}
	server := &localDNSServer{connection: connection, authoritative: authoritative, mode: answerCorrect}
	go server.serve()
	return server, nil
}

func (s *localDNSServer) setMode(mode int) {
	s.mu.Lock()
	s.mode = mode
	s.mu.Unlock()
}

func (s *localDNSServer) serve() {
	buffer := make([]byte, 4096)
	for {
		read, peer, err := s.connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:read]...)
		response := s.response(query)
		if response != nil {
			_, _ = s.connection.WriteToUDP(response, peer)
		}
	}
}

func (s *localDNSServer) response(query []byte) []byte {
	questionEnd, ok := dnsQuestionEnd(query)
	if !ok {
		return nil
	}
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()
	flags := uint16(0x8000)
	if s.authoritative {
		flags |= 0x0400
	}
	if mode == answerNXDOMAIN {
		flags |= 3
	}
	response := make([]byte, 12, questionEnd+16)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	if mode != answerNXDOMAIN {
		binary.BigEndian.PutUint16(response[6:8], 1)
	}
	response = append(response, query[12:questionEnd]...)
	if mode == answerNXDOMAIN {
		return response
	}
	address := []byte{192, 0, 2, 10}
	if mode == answerWrong {
		address = []byte{192, 0, 2, 20}
	}
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, uint16(dnscheck.RecordA))
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, uint16(len(address)))
	return append(response, address...)
}

func dnsQuestionEnd(message []byte) (int, bool) {
	if len(message) < 17 {
		return 0, false
	}
	offset := 12
	for {
		if offset >= len(message) {
			return 0, false
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(message) {
			return 0, false
		}
		offset += length
	}
	if offset+4 > len(message) {
		return 0, false
	}
	return offset + 4, true
}

func closeServers(servers []*localDNSServer) {
	for _, server := range servers {
		_ = server.connection.Close()
	}
}
