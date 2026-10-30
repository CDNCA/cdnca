package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
)

func main() {
	directoryURL := flag.String("directory", "https://127.0.0.1:14000/dir", "Pebble ACME directory URL")
	managementURL := flag.String("management", "http://127.0.0.1:8055", "pebble-challtestsrv management URL")
	dnsServer := flag.String("dns-server", "127.0.0.1:8053", "pebble-challtestsrv DNS server")
	eabKeyID := flag.String("eab-kid", "", "EAB key ID: the CA requires External Account Binding")
	eabKey := flag.String("eab-hmac", "", "EAB HMAC key (base64url) for -eab-kid")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if *eabKeyID != "" {
		if err := runEAB(ctx, *directoryURL, *managementURL, *dnsServer, *eabKeyID, *eabKey); err != nil {
			fmt.Fprintln(os.Stderr, "ACME_SMOKE eab failed:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(ctx, *directoryURL, *managementURL, *dnsServer); err != nil {
		fmt.Fprintln(os.Stderr, "ACME_SMOKE failed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, directoryURL, managementURL, dnsServer string) error {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	httpCertificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsCertificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	signers := &signerStore{keys: map[string]crypto.Signer{
		"account": accountKey,
		"http":    httpCertificateKey,
		"dns":     dnsCertificateKey,
	}}
	accounts := &accountStore{}
	certificates := &certificateStore{items: make(map[string]acmeworker.IssuedCertificate)}
	operations := &operationStore{items: make(map[string]*operation)}
	challengeClient := &http.Client{Timeout: 5 * time.Second}
	provider := &challengeProvider{
		managementURL: strings.TrimSuffix(managementURL, "/"),
		httpClient:    challengeClient,
		httpActive:    make(map[string]bool),
		dnsActive:     make(map[string]bool),
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", dnsServer)
			},
		},
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // Pebble's pinned test certificate.
	config := acmeworker.DefaultConfig(directoryURL)
	config.HTTPClient = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	config.OrderTimeout = 90 * time.Second
	config.RequestTimeout = 15 * time.Second
	config.ChallengeTimeout = 10 * time.Second
	config.PropagationTimeout = 15 * time.Second
	config.CleanupTimeout = 10 * time.Second
	config.MaxConcurrentAuthorizations = 1
	worker, err := acmeworker.New(config, acmeworker.Dependencies{
		Signers:      signers,
		Accounts:     accounts,
		HTTP01:       provider,
		DNS01:        provider,
		Certificates: certificates,
		Operations:   operations,
	})
	if err != nil {
		return err
	}

	httpOrderID := uuid.MustParse("21000000-0000-4000-8000-000000000001")
	httpResult, err := worker.Issue(ctx, acmeworker.IssueRequest{
		TenantID:           uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		ScopeID:            uuid.MustParse("23000000-0000-4000-8000-000000000001"),
		OperationID:        httpOrderID.String(),
		CertificateOrderID: httpOrderID,
		ActorUserID:        uuid.MustParse("22000000-0000-4000-8000-000000000001"),
		ProviderRef:        "",
		AccountKeyRef:      "account",
		CertificateKeyRef:  "http",
		Contacts:           []string{"mailto:acme-smoke@example.test"},
		AcceptTerms:        true,
		Domains:            []string{"http.acme-smoke.test"},
		ChallengeType:      acmeworker.ChallengeHTTP01,
	})
	if err != nil {
		return fmt.Errorf("HTTP-01 issuance: %w", err)
	}
	if len(httpResult.Certificate.ChainDER) < 2 || !slices.Equal(httpResult.Certificate.DNSNames, []string{"http.acme-smoke.test"}) {
		return errors.New("HTTP-01 returned an incomplete or mismatched chain")
	}
	if !provider.clean() {
		return errors.New("HTTP-01 token remained published after authorization")
	}
	fmt.Printf("ACME_SMOKE http-01 domains=%s chain=%d challenges_cleaned=true fingerprint=%s\n",
		strings.Join(httpResult.Certificate.DNSNames, ","), len(httpResult.Certificate.ChainDER), httpResult.Certificate.LeafFingerprint)

	dnsOrderID := uuid.MustParse("21000000-0000-4000-8000-000000000002")
	dnsResult, err := worker.Issue(ctx, acmeworker.IssueRequest{
		TenantID:           uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		ScopeID:            uuid.MustParse("23000000-0000-4000-8000-000000000001"),
		OperationID:        dnsOrderID.String(),
		CertificateOrderID: dnsOrderID,
		ActorUserID:        uuid.MustParse("22000000-0000-4000-8000-000000000001"),
		ProviderID:         uuid.MustParse("24000000-0000-4000-8000-000000000001"),
		ZoneID:             uuid.MustParse("25000000-0000-4000-8000-000000000001"),
		ProviderRef:        uuid.MustParse("24000000-0000-4000-8000-000000000001").String(),
		AccountKeyRef:      "account",
		CertificateKeyRef:  "dns",
		Contacts:           []string{"mailto:acme-smoke@example.test"},
		AcceptTerms:        true,
		Domains:            []string{"*.dns.acme-smoke.test", "dns.acme-smoke.test"},
		ChallengeType:      acmeworker.ChallengeDNS01,
	})
	if err != nil {
		return fmt.Errorf("DNS-01 wildcard issuance: %w", err)
	}
	wantDNSNames := []string{"*.dns.acme-smoke.test", "dns.acme-smoke.test"}
	if len(dnsResult.Certificate.ChainDER) < 2 || !slices.Equal(dnsResult.Certificate.DNSNames, wantDNSNames) {
		return errors.New("DNS-01 returned an incomplete or mismatched chain")
	}
	wildcardTracked := slices.ContainsFunc(dnsResult.Authorizations, func(progress acmeworker.AuthorizationProgress) bool {
		return progress.Identifier == "dns.acme-smoke.test" && progress.Wildcard && progress.Status == "valid"
	})
	if !wildcardTracked || len(dnsResult.Authorizations) != 2 {
		return errors.New("DNS-01 did not retain separate wildcard authorization evidence")
	}
	if !provider.clean() {
		return errors.New("DNS-01 TXT value remained published after authorization")
	}
	fmt.Printf("ACME_SMOKE dns-01 domains=%s wildcard=true authorizations=%d chain=%d challenges_cleaned=true fingerprint=%s\n",
		strings.Join(dnsResult.Certificate.DNSNames, ","), len(dnsResult.Authorizations),
		len(dnsResult.Certificate.ChainDER), dnsResult.Certificate.LeafFingerprint)
	return nil
}

type eabSource struct {
	keyID string
	key   []byte
	calls int
}

func (e *eabSource) ExternalAccountBinding(context.Context, string) (string, []byte, bool, error) {
	e.calls++
	if e.keyID == "" {
		return "", nil, false, nil
	}
	return e.keyID, append([]byte(nil), e.key...), true, nil
}

// runEAB issues one HTTP-01 certificate from a CA that requires External
// Account Binding: without credentials the worker refuses before
// registering (acme_eab_required); with them it registers and issues.
func runEAB(ctx context.Context, directoryURL, managementURL, dnsServer, keyID, encodedKey string) error {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encodedKey, "="))
	if err != nil {
		return fmt.Errorf("decode EAB key: %w", err)
	}
	newWorker := func(eab *eabSource, certificateKey string) (*acmeworker.Worker, *challengeProvider, error) {
		accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		provider := &challengeProvider{managementURL: strings.TrimSuffix(managementURL, "/"),
			httpClient: &http.Client{Timeout: 5 * time.Second}, httpActive: map[string]bool{}, dnsActive: map[string]bool{},
			resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", dnsServer)
			}}}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // Pebble's test certificate.
		config := acmeworker.DefaultConfig(directoryURL)
		config.HTTPClient = &http.Client{Transport: transport, Timeout: 15 * time.Second}
		config.OrderTimeout, config.RequestTimeout, config.ChallengeTimeout = 90*time.Second, 15*time.Second, 10*time.Second
		config.PropagationTimeout, config.CleanupTimeout, config.MaxConcurrentAuthorizations = 15*time.Second, 10*time.Second, 1
		worker, err := acmeworker.New(config, acmeworker.Dependencies{
			Signers:  &signerStore{keys: map[string]crypto.Signer{"account": accountKey, certificateKey: leafKey}},
			Accounts: &accountStore{}, HTTP01: provider, DNS01: provider,
			Certificates: &certificateStore{items: map[string]acmeworker.IssuedCertificate{}},
			Operations:   &operationStore{items: map[string]*operation{}}, EAB: eab,
		})
		return worker, provider, err
	}
	request := func(orderID uuid.UUID, certificateKey string) acmeworker.IssueRequest {
		return acmeworker.IssueRequest{
			TenantID: uuid.MustParse("20000000-0000-4000-8000-000000000003"), OperationID: orderID.String(),
			ScopeID:            uuid.MustParse("23000000-0000-4000-8000-000000000003"),
			CertificateOrderID: orderID, ActorUserID: uuid.MustParse("22000000-0000-4000-8000-000000000003"),
			AccountKeyRef: "account", CertificateKeyRef: certificateKey, Contacts: []string{"mailto:acme-eab@example.test"},
			AcceptTerms: true, Domains: []string{"eab.acme-smoke.test"}, ChallengeType: acmeworker.ChallengeHTTP01,
		}
	}
	missing := &eabSource{}
	worker, _, err := newWorker(missing, "missing")
	if err != nil {
		return err
	}
	_, err = worker.Issue(ctx, request(uuid.MustParse("21000000-0000-4000-8000-000000000011"), "missing"))
	var workerErr *acmeworker.Error
	if !errors.As(err, &workerErr) || workerErr.Code != acmeworker.CodeEABRequired || missing.calls != 1 {
		return fmt.Errorf("issuance without EAB credentials: %v (calls %d), want %s", err, missing.calls, acmeworker.CodeEABRequired)
	}
	fmt.Printf("ACME_SMOKE eab missing_credentials=refused code=%s\n", workerErr.Code)

	configured := &eabSource{keyID: keyID, key: key}
	worker, provider, err := newWorker(configured, "eab")
	if err != nil {
		return err
	}
	result, err := worker.Issue(ctx, request(uuid.MustParse("21000000-0000-4000-8000-000000000012"), "eab"))
	if err != nil {
		return fmt.Errorf("issuance with EAB credentials: %w", err)
	}
	if len(result.Certificate.ChainDER) < 2 || !slices.Equal(result.Certificate.DNSNames, []string{"eab.acme-smoke.test"}) ||
		configured.calls != 1 || result.AccountURI == "" || !provider.clean() {
		return errors.New("EAB issuance returned an incomplete chain or left state behind")
	}
	fmt.Printf("ACME_SMOKE eab registered_with_binding=true account=%s chain=%d fingerprint=%s\n",
		result.AccountURI, len(result.Certificate.ChainDER), result.Certificate.LeafFingerprint)
	return nil
}

type signerStore struct {
	keys map[string]crypto.Signer
}

func (s *signerStore) Signer(_ context.Context, keyRef string) (crypto.Signer, error) {
	signer := s.keys[keyRef]
	if signer == nil {
		return nil, errors.New("signer not found")
	}
	return signer, nil
}

type accountStore struct {
	mu      sync.Mutex
	account acmeworker.AccountRegistration
	found   bool
}

func (s *accountStore) LoadAccount(context.Context, string, string) (acmeworker.AccountRegistration, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account, s.found, nil
}

func (s *accountStore) SaveAccount(_ context.Context, _, _ string, account acmeworker.AccountRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = account
	s.found = true
	return nil
}

type certificateStore struct {
	mu    sync.Mutex
	items map[string]acmeworker.IssuedCertificate
}

func (s *certificateStore) Load(_ context.Context, tenantID uuid.UUID, operationID string) (acmeworker.IssuedCertificate, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	certificate, found := s.items[tenantID.String()+"/"+operationID]
	return certificate, found, nil
}

func (s *certificateStore) Save(_ context.Context, lease acmeworker.OperationLease, certificate acmeworker.IssuedCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := lease.TenantID.String() + "/" + lease.OperationID
	if existing, found := s.items[key]; found && existing.LeafFingerprint != certificate.LeafFingerprint {
		return errors.New("certificate operation conflict")
	}
	s.items[key] = certificate
	return nil
}

type operation struct {
	digest     string
	lease      acmeworker.OperationLease
	challenges map[uuid.UUID]acmeworker.ChallengeIdentity
	states     map[uuid.UUID]string
}

type operationStore struct {
	mu    sync.Mutex
	items map[string]*operation
}

type cleanupClaim struct {
	store         *operationStore
	item          *operation
	lease         acmeworker.OperationLease
	attemptID     uuid.UUID
	previousState string
	closed        bool
}

func (s *operationStore) Claim(_ context.Context, request acmeworker.IssueRequest, digest string, now, until time.Time) (acmeworker.OperationClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := request.TenantID.String() + "/" + request.OperationID
	item := s.items[key]
	if item == nil {
		lease := acmeworker.OperationLease{
			TenantID: request.TenantID, ScopeID: request.ScopeID, OperationID: request.OperationID, Token: uuid.New(),
			ExpiresAt: until, Revision: 1, Request: request, Digest: digest,
			State: acmeworker.OperationState{Phase: acmeworker.PhaseClaimed, Status: acmeworker.OperationActive},
		}
		s.items[key] = &operation{digest: digest, lease: lease,
			challenges: make(map[uuid.UUID]acmeworker.ChallengeIdentity), states: make(map[uuid.UUID]string)}
		return acmeworker.OperationClaim{State: acmeworker.OperationClaimed, Lease: lease}, nil
	}
	if item.digest != digest {
		return acmeworker.OperationClaim{}, &acmeworker.Error{Code: acmeworker.CodeOperationConflict}
	}
	if item.lease.State.Status == acmeworker.OperationCompleted {
		return acmeworker.OperationClaim{State: acmeworker.OperationDone, Lease: item.lease}, nil
	}
	if item.lease.State.Status == acmeworker.OperationActive && item.lease.ExpiresAt.After(now) {
		return acmeworker.OperationClaim{State: acmeworker.OperationBusy, Lease: item.lease}, nil
	}
	item.lease.Token = uuid.New()
	item.lease.ExpiresAt = until
	item.lease.Revision++
	item.lease.State.Status = acmeworker.OperationActive
	return acmeworker.OperationClaim{State: acmeworker.OperationClaimed, Lease: item.lease}, nil
}

func (s *operationStore) Advance(_ context.Context, lease acmeworker.OperationLease, _ string, next acmeworker.OperationState, now time.Time) (acmeworker.OperationLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fence(lease, now)
	if err != nil {
		return acmeworker.OperationLease{}, err
	}
	item.lease.Revision++
	item.lease.State = next
	if next.Status == acmeworker.OperationCompleted {
		item.lease.Token = uuid.Nil
		item.lease.ExpiresAt = time.Time{}
	}
	return item.lease, nil
}

func (s *operationStore) Release(_ context.Context, lease acmeworker.OperationLease, code acmeworker.ErrorCode, retry bool, now, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fence(lease, now)
	if err != nil {
		return err
	}
	item.lease.Revision++
	item.lease.Token = uuid.Nil
	item.lease.ExpiresAt = time.Time{}
	item.lease.State.FailureCode = code
	item.lease.State.Status = acmeworker.OperationFailed
	if retry {
		item.lease.State.Status = acmeworker.OperationRetryWait
	}
	return nil
}

func (s *operationStore) PrepareChallenge(_ context.Context, lease acmeworker.OperationLease, challenge acmeworker.ChallengeIdentity, now time.Time) (acmeworker.ChallengeIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fence(lease, now)
	if err != nil {
		return acmeworker.ChallengeIdentity{}, err
	}
	challenge.TenantID = lease.TenantID
	challenge.ScopeID = lease.ScopeID
	challenge.OperationID = lease.OperationID
	challenge.ProviderID, challenge.ZoneID = lease.Request.ProviderID, lease.Request.ZoneID
	challenge.AttemptID = uuid.New()
	item.challenges[challenge.AttemptID] = challenge
	item.states[challenge.AttemptID] = "intent"
	return challenge, nil
}

func (s *operationStore) MarkChallenge(_ context.Context, lease acmeworker.OperationLease, challenge acmeworker.ChallengeIdentity, state string, now time.Time) error {
	if state != "published" {
		return &acmeworker.Error{Code: acmeworker.CodeInvalidInput}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fence(lease, now)
	if err != nil {
		return err
	}
	stored, found := item.challenges[challenge.AttemptID]
	if !found {
		return errors.New("challenge attempt not found")
	}
	withoutHandle := challenge
	withoutHandle.TXTHandle = acmeworker.RemoteTXTHandle{}
	if stored != withoutHandle {
		return errors.New("challenge identity conflict")
	}
	item.challenges[challenge.AttemptID] = challenge
	item.states[challenge.AttemptID] = state
	return nil
}

func (s *operationStore) ClaimChallengeCleanup(_ context.Context, lease acmeworker.OperationLease, challenge acmeworker.ChallengeIdentity, now time.Time) (acmeworker.ChallengeCleanupClaim, error) {
	s.mu.Lock()
	item, err := s.fence(lease, now)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	previousState, found := item.states[challenge.AttemptID]
	if !found || previousState == "cleaned" || item.challenges[challenge.AttemptID] != challenge {
		s.mu.Unlock()
		return nil, errors.New("challenge cleanup state conflict")
	}
	item.states[challenge.AttemptID] = "cleanup_claimed"
	return &cleanupClaim{
		store: s, item: item, lease: lease, attemptID: challenge.AttemptID,
		previousState: previousState,
	}, nil
}

func (c *cleanupClaim) Complete(_ context.Context, now time.Time) error {
	if c.closed {
		return errors.New("challenge cleanup claim is closed")
	}
	if c.item.lease.Token != c.lease.Token || c.item.lease.Revision != c.lease.Revision ||
		c.item.lease.State.Status != acmeworker.OperationActive || !c.item.lease.ExpiresAt.After(now) {
		c.item.states[c.attemptID] = c.previousState
		c.closed = true
		c.store.mu.Unlock()
		return &acmeworker.Error{Code: acmeworker.CodeLeaseLost}
	}
	c.item.states[c.attemptID] = "cleaned"
	c.closed = true
	c.store.mu.Unlock()
	return nil
}

func (c *cleanupClaim) Abort(context.Context) error {
	if c.closed {
		return nil
	}
	c.item.states[c.attemptID] = c.previousState
	c.closed = true
	c.store.mu.Unlock()
	return nil
}

func (s *operationStore) OutstandingChallenges(_ context.Context, lease acmeworker.OperationLease, now time.Time) ([]acmeworker.ChallengeIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.fence(lease, now)
	if err != nil {
		return nil, err
	}
	var result []acmeworker.ChallengeIdentity
	for id, challenge := range item.challenges {
		if item.states[id] != "cleaned" {
			result = append(result, challenge)
		}
	}
	return result, nil
}

func (*operationStore) Recoverable(context.Context, time.Time, int) ([]acmeworker.IssueRequest, error) {
	return nil, nil
}

func (s *operationStore) fence(lease acmeworker.OperationLease, now time.Time) (*operation, error) {
	item := s.items[lease.TenantID.String()+"/"+lease.OperationID]
	if item == nil || item.lease.Token != lease.Token || item.lease.Revision != lease.Revision ||
		item.lease.State.Status != acmeworker.OperationActive || !item.lease.ExpiresAt.After(now) {
		return nil, &acmeworker.Error{Code: acmeworker.CodeLeaseLost}
	}
	return item, nil
}

type challengeProvider struct {
	managementURL string
	httpClient    *http.Client
	resolver      *net.Resolver
	mu            sync.Mutex
	httpActive    map[string]bool
	dnsActive     map[string]bool
}

func (p *challengeProvider) Publish(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	if err := p.post(ctx, "/add-http01", map[string]string{"token": challenge.Token, "content": challenge.ExactValue}); err != nil {
		return err
	}
	p.mu.Lock()
	p.httpActive[challenge.Token] = true
	p.mu.Unlock()
	return nil
}

func (p *challengeProvider) PresentTXT(ctx context.Context, challenge acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, error) {
	if err := p.post(ctx, "/set-txt", map[string]string{"host": challenge.RecordName, "value": challenge.ExactValue}); err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	p.mu.Lock()
	p.dnsActive[challenge.RecordName+"\x00"+challenge.ExactValue] = true
	p.mu.Unlock()
	return acmeworker.RemoteTXTHandle{
		ProviderRef: challenge.ProviderRef,
		RecordRef:   challenge.RecordName,
	}, nil
}

func (p *challengeProvider) ObserveTXT(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	host := strings.TrimSuffix(challenge.TXTHandle.RecordRef, ".")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		values, err := p.resolver.LookupTXT(ctx, host)
		if err == nil && slices.Contains(values, challenge.ExactValue) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *challengeProvider) Delete(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	if err := p.post(ctx, "/del-http01", map[string]string{"token": challenge.Token}); err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.httpActive, challenge.Token)
	p.mu.Unlock()
	return nil
}

func (p *challengeProvider) DeleteTXT(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	if err := p.post(ctx, "/clear-txt", map[string]string{"host": challenge.TXTHandle.RecordRef}); err != nil {
		return err
	}
	p.mu.Lock()
	delete(p.dnsActive, challenge.TXTHandle.RecordRef+"\x00"+challenge.ExactValue)
	p.mu.Unlock()
	return nil
}

func (p *challengeProvider) clean() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.httpActive) == 0 && len(p.dnsActive) == 0
}

func (p *challengeProvider) post(ctx context.Context, path string, payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.managementURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("challenge management status %d", response.StatusCode)
	}
	return nil
}
