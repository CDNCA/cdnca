package acmeworker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme"
)

type Worker struct {
	config Config
	deps   Dependencies
	owners ownerLocks
}

// ownerLocks serializes DNS-01 challenges of one TXT owner within this worker
// (FX03③): apex and *. share _acme-challenge.<domain>, which some providers
// (Huawei) keep as one record set; one challenge at a time keeps it single-valued.
type ownerLocks struct {
	mu    sync.Mutex
	locks map[string]*ownerLock
}

type ownerLock struct {
	sem   chan struct{}
	users int
}

func (locks *ownerLocks) acquire(ctx context.Context, owner string) (func(), error) {
	locks.mu.Lock()
	if locks.locks == nil {
		locks.locks = map[string]*ownerLock{}
	}
	lock := locks.locks[owner]
	if lock == nil {
		lock = &ownerLock{sem: make(chan struct{}, 1)}
		locks.locks[owner] = lock
	}
	lock.users++
	locks.mu.Unlock()
	leave := func() {
		locks.mu.Lock()
		if lock.users--; lock.users == 0 {
			delete(locks.locks, owner)
		}
		locks.mu.Unlock()
	}
	select {
	case lock.sem <- struct{}{}:
		return func() { <-lock.sem; leave() }, nil
	case <-ctx.Done():
		leave()
		return nil, contextFailure(ctx.Err())
	}
}

func New(config Config, dependencies Dependencies) (*Worker, error) {
	if err := validateConfig(config, dependencies); err != nil {
		return nil, err
	}
	return &Worker{config: config, deps: dependencies}, nil
}

// TerminalCleanupReady reports whether this worker was composed with the
// cleanup-only authority needed to remove artifacts after an order terminates.
func (w *Worker) TerminalCleanupReady() error {
	if w == nil || w.deps.Operations == nil {
		return failure(CodeChallengeUnavailable, nil)
	}
	if _, ok := w.deps.Operations.(TerminalChallengeCleanupStore); !ok {
		return failure(CodeChallengeUnavailable, nil)
	}
	return nil
}

// CleanupTerminalChallengeOnce deletes at most one exact persisted challenge
// artifact. It never invokes Issue or any OperationStore issuance mutation.
func (w *Worker) CleanupTerminalChallengeOnce(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, failure(CodeInvalidInput, nil)
	}
	if err := w.TerminalCleanupReady(); err != nil {
		return false, err
	}
	store := w.deps.Operations.(TerminalChallengeCleanupStore)
	lease, found, err := store.ClaimTerminalChallengeCleanup(ctx)
	if err != nil || !found {
		return found, err
	}
	if !validTerminalChallengeCleanupLease(lease) {
		return true, failure(CodeOperationConflict, nil)
	}
	if err := store.FenceTerminalChallengeCleanup(ctx, lease); err != nil {
		return true, err
	}

	cleanupCtx, cancel := context.WithTimeout(ctx, w.config.CleanupTimeout)
	switch lease.Challenge.ChallengeType {
	case ChallengeHTTP01:
		if w.deps.HTTP01 == nil {
			cancel()
			return true, failure(CodeChallengeUnavailable, nil)
		}
		err = w.deps.HTTP01.Delete(cleanupCtx, lease.Challenge)
	case ChallengeDNS01:
		if w.deps.DNS01 == nil {
			cancel()
			return true, failure(CodeChallengeUnavailable, nil)
		}
		err = w.deps.DNS01.DeleteTXT(cleanupCtx, lease.Challenge)
	default:
		err = failure(CodeChallengeUnavailable, nil)
	}
	cancel()
	if err != nil {
		return true, phaseFailure(CodeChallengeCleanupFailed, err)
	}

	completeCtx, completeCancel := context.WithTimeout(context.WithoutCancel(ctx), w.config.CleanupTimeout)
	defer completeCancel()
	if err := store.CompleteTerminalChallengeCleanup(completeCtx, lease); err != nil {
		return true, err
	}
	return true, nil
}

func validTerminalChallengeCleanupLease(lease TerminalChallengeCleanupLease) bool {
	request := lease.Request
	challenge := lease.Challenge
	operationLease := OperationLease{
		TenantID: request.TenantID, ScopeID: request.ScopeID,
		OperationID: request.OperationID, Request: request,
	}
	if lease.Token == uuid.Nil || lease.Revision < 1 || lease.ExpiresAt.IsZero() ||
		!validFrozenIssueRequest(request) || lease.RequestDigest != issueRequestDigest(request) ||
		!challengeMatchesRequest(challenge, operationLease) || challenge.AttemptID == uuid.Nil ||
		challenge.ChallengeType != request.ChallengeType || challenge.AuthorizationURL == "" ||
		challenge.ChallengeURL == "" || challenge.Identifier == "" || challenge.RecordName == "" ||
		challenge.Token == "" || challenge.ExactValue == "" || challenge.ZeroMatchCleanupClaimed ||
		lease.ChallengeSHA256 != terminalChallengeCleanupDigest(challenge) {
		return false
	}
	if challenge.ChallengeType == ChallengeDNS01 {
		return validateRemoteTXTHandle(challenge.TXTHandle, request.ProviderRef) == nil
	}
	return challenge.ChallengeType == ChallengeHTTP01 && challenge.TXTHandle == (RemoteTXTHandle{})
}

func (w *Worker) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	domains, err := normalizeIssueRequest(&request)
	if err != nil {
		return IssueResult{}, err
	}
	request.Domains = domains
	request.DirectoryURL = w.config.DirectoryURL
	requestDigest := issueRequestDigest(request)
	if (request.ChallengeType == ChallengeHTTP01 && w.deps.HTTP01 == nil) ||
		(request.ChallengeType == ChallengeDNS01 && w.deps.DNS01 == nil) {
		return IssueResult{}, failure(CodeChallengeUnavailable, nil)
	}

	issueCtx, cancel := context.WithTimeout(ctx, w.config.OrderTimeout)
	defer cancel()
	now := w.config.Clock().UTC()
	claim, err := w.deps.Operations.Claim(issueCtx, request, requestDigest, now, now.Add(w.config.LeaseDuration))
	if err != nil {
		return IssueResult{}, err
	}
	switch claim.State {
	case OperationBusy:
		return IssueResult{}, failure(CodeOperationBusy, nil)
	case OperationTerminal:
		return IssueResult{}, &Error{Code: claim.Lease.State.FailureCode, Terminal: true}
	case OperationDone:
		certificate, found, loadErr := w.deps.Certificates.Load(issueCtx, request.ScopeID, request.OperationID)
		if loadErr != nil || !found || certificate.RequestDigest != requestDigest ||
			certificate.CertificateKeyRef != request.CertificateKeyRef ||
			certificate.PublicKeySPKISHA256 != claim.Lease.State.CertificateSPKIDigest ||
			!validCompletedCertificateReplay(certificate, claim.Lease.State, request.Domains) {
			return IssueResult{}, failure(CodeCertificateStoreFailed, loadErr)
		}
		return IssueResult{
			AccountURI: claim.Lease.State.AccountURI, OrderURI: claim.Lease.State.OrderURL,
			Certificate: cloneCertificate(certificate), Reused: true,
		}, nil
	case OperationClaimed:
	default:
		return IssueResult{}, failure(CodeOperationStoreFailed, nil)
	}

	result, issueErr := w.execute(issueCtx, &claim.Lease, requestDigest)
	if issueErr == nil {
		return result, nil
	}
	originalErr := issueErr
	settleCode := ErrorCodeOf(originalErr)
	retry := retryableFailure(originalErr)
	if cleanupErr := w.cleanupOutstanding(context.WithoutCancel(issueCtx), claim.Lease); cleanupErr != nil {
		issueErr = errors.Join(originalErr, cleanupErr)
		settleCode = CodeChallengeCleanupFailed
		retry = true
	}
	settleCtx, settleCancel := context.WithTimeout(context.WithoutCancel(issueCtx), w.config.CleanupTimeout)
	defer settleCancel()
	if releaseErr := w.deps.Operations.Release(
		settleCtx, claim.Lease, settleCode, retry, w.config.Clock().UTC(),
		w.config.Clock().UTC().Add(w.config.RetryDelay),
	); releaseErr != nil {
		if ErrorCodeOf(releaseErr) != CodeLeaseLost {
			return result, releaseErr
		}
	} else if !retry {
		// The operation is now settled failed: every later claim returns
		// this code, so the caller must not keep retrying it (fix-certstuck).
		var workerErr *Error
		if errors.As(originalErr, &workerErr) {
			terminal := *workerErr
			terminal.Terminal = true
			return result, &terminal
		}
	}
	return result, issueErr
}

func validCompletedCertificateReplay(certificate IssuedCertificate, state OperationState, requestDomains []string) bool {
	if state.CertificateURL == "" || certificate.CertificateURL != state.CertificateURL ||
		state.LeafFingerprint == "" || certificate.LeafFingerprint != state.LeafFingerprint ||
		len(certificate.ChainDER) == 0 || len(certificate.ChainDER) > 5 ||
		!bytes.Equal(certificate.ChainDER[0], certificate.LeafDER) {
		return false
	}
	var leaf *x509.Certificate
	var previous *x509.Certificate
	var canonicalPEM bytes.Buffer
	for index, certificateDER := range certificate.ChainDER {
		parsed, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return false
		}
		if index == 0 {
			leaf = parsed
		} else if err := previous.CheckSignatureFrom(parsed); err != nil {
			return false
		}
		previous = parsed
		if err := pem.Encode(&canonicalPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}); err != nil {
			return false
		}
	}
	if !bytes.Equal(certificate.CertificatePEM, canonicalPEM.Bytes()) {
		return false
	}
	wantNames := slices.Clone(requestDomains)
	leafNames := slices.Clone(leaf.DNSNames)
	metadataNames := slices.Clone(certificate.DNSNames)
	slices.Sort(wantNames)
	slices.Sort(leafNames)
	slices.Sort(metadataNames)
	if leaf.SerialNumber == nil || certificate.SerialNumber != leaf.SerialNumber.String() ||
		!certificate.NotBefore.Equal(leaf.NotBefore) || !certificate.NotAfter.Equal(leaf.NotAfter) ||
		!slices.Equal(metadataNames, leafNames) || !slices.Equal(wantNames, leafNames) {
		return false
	}
	for _, domain := range requestDomains {
		if err := leaf.VerifyHostname(domain); err != nil {
			return false
		}
	}
	fingerprint := sha256.Sum256(certificate.LeafDER)
	if certificate.LeafFingerprint != fmt.Sprintf("sha256:%x", fingerprint) {
		return false
	}
	publicDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return false
	}
	publicDigest := sha256.Sum256(publicDER)
	return certificate.PublicKeySPKISHA256 == fmt.Sprintf("sha256:%x", publicDigest) &&
		certificate.PublicKeySPKISHA256 == state.CertificateSPKIDigest
}

func (w *Worker) execute(ctx context.Context, lease *OperationLease, requestDigest string) (IssueResult, error) {
	request := lease.Request
	result := IssueResult{AccountURI: lease.State.AccountURI, OrderURI: lease.State.OrderURL}
	if err := w.cleanupOutstanding(ctx, *lease); err != nil {
		return result, err
	}
	accountSigner, err := w.deps.Signers.Signer(ctx, request.AccountKeyRef)
	if err != nil || accountSigner == nil {
		return result, phaseFailure(CodeKeyUnavailable, err)
	}
	certificateSigner, err := w.deps.Signers.Signer(ctx, request.CertificateKeyRef)
	if err != nil || certificateSigner == nil {
		return result, phaseFailure(CodeKeyUnavailable, err)
	}

	client, orderLocations := w.acmeClient(accountSigner)
	if lease.State.AccountURI != "" {
		client.KID = acme.KeyID(lease.State.AccountURI)
	} else {
		account, accountErr := w.ensureAccount(ctx, client, request)
		if accountErr != nil {
			return result, accountErr
		}
		next := cloneOperationState(lease.State)
		next.AccountURI = account.URI
		if err := w.advance(ctx, lease, "account_registered", next); err != nil {
			return result, err
		}
		client.KID = acme.KeyID(account.URI)
	}
	result.AccountURI = lease.State.AccountURI

	var order *acme.Order
	if lease.State.OrderURL == "" {
		if lease.State.OrderIntentPending {
			return result, failure(CodeOrderUncertain, nil)
		}
		next := cloneOperationState(lease.State)
		next.OrderIntentPending = true
		if err := w.advance(ctx, lease, "order_intent", next); err != nil {
			return result, err
		}
		order, err = client.AuthorizeOrder(ctx, acme.DomainIDs(request.Domains...))
		if err != nil {
			if orderCreationDefinitelyRejected(err) {
				next = cloneOperationState(lease.State)
				next.OrderIntentPending = false
				if storeErr := w.advance(ctx, lease, "order_rejected", next); storeErr != nil {
					return result, storeErr
				}
				return result, acmeFailure(CodeOrderRejected, err, w.config.MaxRetryAfter)
			}
			return result, failure(CodeOrderUncertain, nil)
		}
		if err := validateNewOrder(order, request.Domains); err != nil {
			return result, failure(CodeOrderRejected, err)
		}
		next = cloneOperationState(lease.State)
		next.Phase = PhaseOrdered
		next.OrderIntentPending = false
		next.OrderURL = order.URI
		next.FinalizeURL = order.FinalizeURL
		next.AuthorizationURLs = slices.Clone(order.AuthzURLs)
		if err := w.advance(ctx, lease, "order_created", next); err != nil {
			return result, err
		}
	} else {
		order, err = client.GetOrder(ctx, lease.State.OrderURL)
		if err != nil {
			return result, acmeFailure(CodeOrderRejected, err, w.config.MaxRetryAfter)
		}
		if err := validateResumedOrder(order, lease.State, request.Domains); err != nil {
			return result, failure(CodeOrderRejected, err)
		}
	}
	result.OrderURI = lease.State.OrderURL
	orderLocations.Set(lease.State.FinalizeURL, lease.State.OrderURL)

	if order.Status == acme.StatusPending {
		if phaseRank(lease.State.Phase) < phaseRank(PhaseAuthorizing) {
			next := cloneOperationState(lease.State)
			next.Phase = PhaseAuthorizing
			if err := w.advance(ctx, lease, "authorizing", next); err != nil {
				return result, err
			}
		}
		result.Authorizations = make([]AuthorizationProgress, len(lease.State.AuthorizationURLs))
		if err := w.authorizeAll(ctx, client, *lease, lease.State.AuthorizationURLs, result.Authorizations); err != nil {
			return result, err
		}
		order, err = client.WaitOrder(ctx, lease.State.OrderURL)
		if err != nil {
			return result, acmeFailure(CodeOrderRejected, err, w.config.MaxRetryAfter)
		}
	}
	if order.Status == acme.StatusInvalid {
		return result, failure(CodeOrderRejected, nil)
	}
	if order.Status == acme.StatusReady && phaseRank(lease.State.Phase) < phaseRank(PhaseReady) {
		next := cloneOperationState(lease.State)
		next.Phase = PhaseReady
		if err := w.advance(ctx, lease, "authorization_ready", next); err != nil {
			return result, err
		}
	}

	var chainDER [][]byte
	certificateURL := order.CertURL
	switch order.Status {
	case acme.StatusReady:
		if phaseRank(lease.State.Phase) < phaseRank(PhaseFinalizing) {
			next := cloneOperationState(lease.State)
			next.Phase = PhaseFinalizing
			if err := w.advance(ctx, lease, "finalize_intent", next); err != nil {
				return result, err
			}
		}
		csr, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{}, DNSNames: request.Domains,
		}, certificateSigner)
		if csrErr != nil {
			return result, failure(CodeFinalizeFailed, csrErr)
		}
		chainDER, certificateURL, err = client.CreateOrderCert(ctx, lease.State.FinalizeURL, csr, true)
		if err != nil {
			return result, acmeFailure(CodeFinalizeFailed, err, w.config.MaxRetryAfter)
		}
	case acme.StatusProcessing:
		if phaseRank(lease.State.Phase) < phaseRank(PhaseFinalizing) {
			next := cloneOperationState(lease.State)
			next.Phase = PhaseFinalizing
			if err := w.advance(ctx, lease, "finalize_intent", next); err != nil {
				return result, err
			}
		}
		order, err = client.WaitOrder(ctx, lease.State.OrderURL)
		if err != nil || order.Status != acme.StatusValid || order.CertURL == "" {
			return result, acmeFailure(CodeFinalizeFailed, err, w.config.MaxRetryAfter)
		}
		certificateURL = order.CertURL
		chainDER, err = client.FetchCert(ctx, certificateURL, true)
		if err != nil {
			return result, acmeFailure(CodeFinalizeFailed, err, w.config.MaxRetryAfter)
		}
	case acme.StatusValid:
		if certificateURL == "" {
			return result, failure(CodeCertificateInvalid, nil)
		}
		chainDER, err = client.FetchCert(ctx, certificateURL, true)
		if err != nil {
			return result, acmeFailure(CodeFinalizeFailed, err, w.config.MaxRetryAfter)
		}
	default:
		return result, failure(CodeOrderRejected, nil)
	}

	certificate, err := parseCertificateChain(chainDER, certificateURL, request.Domains, certificateSigner, w.config.Clock().UTC())
	if err != nil {
		return result, failure(CodeCertificateInvalid, err)
	}
	certificate.RequestDigest = requestDigest
	certificate.CertificateKeyRef = request.CertificateKeyRef
	publicDER, err := x509.MarshalPKIXPublicKey(certificateSigner.Public())
	if err != nil {
		return result, failure(CodeCertificateInvalid, err)
	}
	publicDigest := sha256.Sum256(publicDER)
	certificate.PublicKeySPKISHA256 = fmt.Sprintf("sha256:%x", publicDigest)
	if err := w.deps.Certificates.Save(ctx, *lease, certificate); err != nil {
		return result, failure(CodeCertificateStoreFailed, err)
	}
	next := cloneOperationState(lease.State)
	next.Phase = PhaseCertificateSaved
	next.CertificateURL = certificate.CertificateURL
	next.CertificateSPKIDigest = certificate.PublicKeySPKISHA256
	next.LeafFingerprint = certificate.LeafFingerprint
	if err := w.advance(ctx, lease, "certificate_saved", next); err != nil {
		return result, err
	}
	next = cloneOperationState(lease.State)
	next.Phase = PhaseCompleted
	next.Status = OperationCompleted
	if err := w.advance(ctx, lease, "completed", next); err != nil {
		return result, err
	}
	result.Certificate = cloneCertificate(certificate)
	return result, nil
}

func (w *Worker) advance(ctx context.Context, lease *OperationLease, eventType string, next OperationState) error {
	updated, err := w.deps.Operations.Advance(ctx, *lease, eventType, next, w.config.Clock().UTC())
	if err != nil {
		return err
	}
	*lease = updated
	return nil
}

func (w *Worker) ensureAccount(ctx context.Context, client *acme.Client, request IssueRequest) (AccountRegistration, error) {
	stored, found, err := w.deps.Accounts.LoadAccount(ctx, w.config.DirectoryURL, request.AccountKeyRef)
	if err != nil {
		return AccountRegistration{}, failure(CodeAccountUnavailable, err)
	}
	if found {
		if strings.TrimSpace(stored.URI) == "" {
			return AccountRegistration{}, failure(CodeAccountUnavailable, nil)
		}
		client.KID = acme.KeyID(stored.URI)
		return stored, nil
	}

	newAccount := &acme.Account{Contact: slices.Clone(request.Contacts)}
	if w.deps.EAB != nil {
		keyID, key, found, eabErr := w.deps.EAB.ExternalAccountBinding(ctx, w.config.DirectoryURL)
		if eabErr != nil {
			return AccountRegistration{}, failure(CodeAccountUnavailable, eabErr)
		}
		if found {
			defer clear(key)
			newAccount.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: keyID, Key: key}
		}
	}
	if newAccount.ExternalAccountBinding == nil {
		if directory, dirErr := client.Discover(ctx); dirErr == nil && directory.ExternalAccountRequired {
			return AccountRegistration{}, failure(CodeEABRequired, nil)
		}
	}
	registered, err := client.Register(ctx, newAccount, func(string) bool {
		return request.AcceptTerms
	})
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		registered, err = client.GetReg(ctx, "")
	}
	if newAccount.ExternalAccountBinding != nil && acmeProblem(err, "externalAccountRequired", "unauthorized", "malformed") {
		// The CA refused the binding: wrong or revoked credentials.
		return AccountRegistration{}, failure(CodeEABRequired, err)
	}
	if err != nil || registered == nil || registered.URI == "" {
		return AccountRegistration{}, acmeFailure(CodeAccountUnavailable, err, w.config.MaxRetryAfter)
	}
	// Let's Encrypt no longer echoes "contact" (2025-06), so the registration
	// records the contacts this worker submitted, never the CA's echo.
	account := AccountRegistration{URI: registered.URI, Contact: append([]string{}, newAccount.Contact...)}
	if err := w.deps.Accounts.SaveAccount(ctx, w.config.DirectoryURL, request.AccountKeyRef, account); err != nil {
		return AccountRegistration{}, failure(CodeAccountUnavailable, err)
	}
	return account, nil
}

func (w *Worker) authorizeAll(
	ctx context.Context,
	client *acme.Client,
	lease OperationLease,
	urls []string,
	progress []AuthorizationProgress,
) error {
	if w.config.MaxConcurrentAuthorizations == 1 {
		for index, authURL := range urls {
			item, err := w.authorize(ctx, client, lease, authURL)
			progress[index] = item
			if err != nil {
				return err
			}
		}
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, w.config.MaxConcurrentAuthorizations)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for index, authURL := range urls {
		index, authURL := index, authURL
		progress[index].URL = authURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				setFirstError(&errMu, &firstErr, contextFailure(ctx.Err()))
				return
			}
			item, err := w.authorize(ctx, client, lease, authURL)
			progress[index] = item
			if err != nil {
				setFirstError(&errMu, &firstErr, err)
				cancel()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func (w *Worker) authorize(
	ctx context.Context,
	client *acme.Client,
	lease OperationLease,
	authURL string,
) (progress AuthorizationProgress, resultErr error) {
	challengeType := lease.Request.ChallengeType
	progress.URL = authURL
	auth, err := client.GetAuthorization(ctx, authURL)
	if err != nil {
		resultErr = acmeFailure(CodeChallengeUnavailable, err, w.config.MaxRetryAfter)
		progress.ErrorCode = ErrorCodeOf(resultErr)
		return progress, resultErr
	}
	progress.Identifier = auth.Identifier.Value
	progress.Wildcard = auth.Wildcard
	progress.ChallengeType = challengeType
	progress.Status = auth.Status
	if auth.Identifier.Type != "dns" || !authorizationMatchesRequest(auth.Identifier.Value, auth.Wildcard, lease.Request.Domains) {
		resultErr = failure(CodeAuthorizationInvalid, nil)
		progress.ErrorCode = ErrorCodeOf(resultErr)
		return progress, resultErr
	}
	if auth.Status == acme.StatusValid {
		return progress, nil
	}
	challenge := findChallenge(auth, challengeType)
	if challenge == nil || (auth.Wildcard && challengeType != ChallengeDNS01) {
		resultErr = failure(CodeChallengeUnavailable, nil)
		progress.ErrorCode = ErrorCodeOf(resultErr)
		return progress, resultErr
	}

	identity := ChallengeIdentity{
		TenantID: lease.Request.TenantID, ScopeID: lease.Request.ScopeID,
		ProviderID: lease.Request.ProviderID, ZoneID: lease.Request.ZoneID,
		OperationID: lease.Request.OperationID, ProviderRef: lease.Request.ProviderRef, AuthorizationURL: authURL,
		ChallengeURL: challenge.URI, ChallengeType: challengeType,
		Identifier: auth.Identifier.Value, Wildcard: auth.Wildcard, Token: challenge.Token,
	}
	switch challengeType {
	case ChallengeHTTP01:
		response, responseErr := client.HTTP01ChallengeResponse(challenge.Token)
		if responseErr != nil {
			resultErr = failure(CodeChallengeUnavailable, responseErr)
			break
		}
		identity.RecordName = auth.Identifier.Value
		identity.ExactValue = response
		identity, resultErr = w.deps.Operations.PrepareChallenge(ctx, lease, identity, w.config.Clock().UTC())
		if resultErr != nil {
			break
		}
		publishTimeout := w.config.ChallengeTimeout
		if w.config.HTTP01PublishTimeout > 0 {
			publishTimeout = w.config.HTTP01PublishTimeout
		}
		publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
		resultErr = w.deps.HTTP01.Publish(publishCtx, identity)
		cancel()
		if resultErr != nil {
			resultErr = phaseFailure(CodeChallengePublishFailed, resultErr)
		} else {
			resultErr = w.deps.Operations.MarkChallenge(ctx, lease, identity, "published", w.config.Clock().UTC())
		}
	case ChallengeDNS01:
		value, responseErr := client.DNS01ChallengeRecord(challenge.Token)
		if responseErr != nil {
			resultErr = failure(CodeChallengeUnavailable, responseErr)
			break
		}
		fqdn := "_acme-challenge." + strings.TrimPrefix(auth.Identifier.Value, "*.") + "."
		// Held until authorize returns, i.e. through validation and cleanup.
		release, lockErr := w.owners.acquire(ctx, fqdn)
		if lockErr != nil {
			resultErr = lockErr
			break
		}
		defer release()
		identity.RecordName = fqdn
		identity.ExactValue = value
		identity, resultErr = w.deps.Operations.PrepareChallenge(ctx, lease, identity, w.config.Clock().UTC())
		if resultErr != nil {
			break
		}
		publishCtx, cancel := context.WithTimeout(ctx, w.config.ChallengeTimeout)
		handle, publishErr := w.deps.DNS01.PresentTXT(publishCtx, identity)
		cancel()
		if publishErr != nil && handle == (RemoteTXTHandle{}) {
			// No handle: keep the provider's own error (the handle check
			// below would replace it with "invalid remote TXT handle").
			resultErr = phaseFailure(CodeChallengePublishFailed, publishErr)
			break
		}
		if handleErr := validateRemoteTXTHandle(handle, identity.ProviderRef); handleErr != nil {
			resultErr = failure(CodeChallengePublishFailed, handleErr)
			break
		}
		published := identity
		published.TXTHandle = handle
		resultErr = w.deps.Operations.MarkChallenge(ctx, lease, published, "published", w.config.Clock().UTC())
		if resultErr != nil {
			break
		}
		identity = published
		if publishErr == nil {
			waitCtx, waitCancel := context.WithTimeout(ctx, w.config.PropagationTimeout)
			resultErr = w.deps.DNS01.ObserveTXT(waitCtx, identity)
			if resultErr == nil {
				resultErr = w.waitAuthoritativeTXT(waitCtx, identity)
			}
			waitCancel()
			if resultErr != nil {
				resultErr = phaseFailure(CodeChallengePropagationFailed, resultErr)
			}
		} else {
			resultErr = phaseFailure(CodeChallengePublishFailed, publishErr)
		}
	}

	if resultErr == nil {
		requestCtx, cancel := context.WithTimeout(ctx, w.config.ChallengeTimeout)
		_, acceptErr := client.Accept(requestCtx, challenge)
		cancel()
		if acceptErr != nil {
			resultErr = acmeFailure(CodeAuthorizationInvalid, acceptErr, w.config.MaxRetryAfter)
		}
	}
	if resultErr == nil {
		validated, waitErr := client.WaitAuthorization(ctx, authURL)
		if waitErr != nil {
			resultErr = acmeFailure(CodeAuthorizationInvalid, waitErr, w.config.MaxRetryAfter)
		} else {
			progress.Status = validated.Status
		}
	}
	if identity.AttemptID != uuid.Nil {
		cleanupErr := w.cleanupChallenge(context.WithoutCancel(ctx), lease, identity)
		if cleanupErr != nil {
			progress.CleanupErrorCode = CodeChallengeCleanupFailed
			if resultErr == nil {
				resultErr = phaseFailure(CodeChallengeCleanupFailed, cleanupErr)
			}
		}
	}
	if resultErr != nil {
		progress.ErrorCode = ErrorCodeOf(resultErr)
		if progress.Status != acme.StatusValid {
			progress.Status = acme.StatusInvalid
		}
	}
	return progress, resultErr
}

func (w *Worker) cleanupOutstanding(ctx context.Context, lease OperationLease) error {
	challenges, err := w.deps.Operations.OutstandingChallenges(ctx, lease, w.config.Clock().UTC())
	if err != nil {
		return err
	}
	var cleanupErr error
	var nodeAggregateRequired bool
	for _, challenge := range challenges {
		if err := w.cleanupChallenge(ctx, lease, challenge); err != nil {
			if cleanupErr == nil {
				cleanupErr = err
			}
			if ErrorCodeOf(err) == CodeHTTP01NodeAggregateRequired {
				nodeAggregateRequired = true
			}
		}
	}
	if nodeAggregateRequired {
		return failure(CodeHTTP01NodeAggregateRequired, nil)
	}
	if cleanupErr != nil {
		// Keep the first cause so the operator log says why cleanup failed.
		var inner *Error
		if errors.As(cleanupErr, &inner) && inner.Code == CodeChallengeCleanupFailed {
			return failure(CodeChallengeCleanupFailed, inner.cause)
		}
		return failure(CodeChallengeCleanupFailed, cleanupErr)
	}
	return nil
}

func (w *Worker) cleanupChallenge(ctx context.Context, lease OperationLease, challenge ChallengeIdentity) error {
	if !challengeMatchesRequest(challenge, lease) {
		return failure(CodeOperationConflict, nil)
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, w.config.CleanupTimeout)
	defer cancel()
	remoteTXTExists := true
	if challenge.ChallengeType == ChallengeDNS01 {
		if challenge.TXTHandle == (RemoteTXTHandle{}) {
			if challenge.ZeroMatchCleanupClaimed {
				remoteTXTExists = false
			} else {
				recovery, ok := w.deps.DNS01.(DNS01RecoveryProvider)
				if !ok {
					return phaseFailure(CodeChallengeCleanupFailed, nil)
				}
				handle, found, recoverErr := recovery.RecoverTXT(cleanupCtx, challenge)
				if recoverErr != nil {
					return phaseFailure(CodeChallengeCleanupFailed, recoverErr)
				}
				if !found {
					remoteTXTExists = false
				} else if handleErr := validateRemoteTXTHandle(handle, challenge.ProviderRef); handleErr != nil {
					return phaseFailure(CodeChallengeCleanupFailed, handleErr)
				} else {
					recovered := challenge
					recovered.TXTHandle = handle
					if err := w.deps.Operations.MarkChallenge(
						cleanupCtx, lease, recovered, "published", w.config.Clock().UTC(),
					); err != nil {
						return err
					}
					challenge = recovered
				}
			}
		}
		if remoteTXTExists {
			if handleErr := validateRemoteTXTHandle(challenge.TXTHandle, challenge.ProviderRef); handleErr != nil {
				return phaseFailure(CodeChallengeCleanupFailed, handleErr)
			}
		}
	}
	challenge.ZeroMatchCleanupClaimed = false
	claim, err := w.deps.Operations.ClaimChallengeCleanup(
		cleanupCtx, lease, challenge, w.config.Clock().UTC(),
	)
	if err != nil {
		return err
	}
	defer func() { _ = claim.Abort(context.Background()) }()
	switch challenge.ChallengeType {
	case ChallengeHTTP01:
		if w.deps.HTTP01 == nil {
			return failure(CodeChallengeUnavailable, nil)
		}
		err = w.deps.HTTP01.Delete(cleanupCtx, challenge)
	case ChallengeDNS01:
		if w.deps.DNS01 == nil {
			return failure(CodeChallengeUnavailable, nil)
		}
		if remoteTXTExists {
			err = w.deps.DNS01.DeleteTXT(cleanupCtx, challenge)
		}
	default:
		return failure(CodeChallengeUnavailable, nil)
	}
	if err != nil {
		return phaseFailure(CodeChallengeCleanupFailed, err)
	}
	if err := claim.Complete(cleanupCtx, w.config.Clock().UTC()); err != nil {
		return err
	}
	return nil
}

func (w *Worker) acmeClient(signer crypto.Signer) (*acme.Client, *orderLocationTransport) {
	base := w.config.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	httpClient := *base
	if httpClient.Timeout == 0 || httpClient.Timeout > w.config.RequestTimeout {
		httpClient.Timeout = w.config.RequestTimeout
	}
	baseTransport := httpClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	locations := &orderLocationTransport{base: baseTransport, orders: make(map[string]string)}
	httpClient.Transport = locations
	return &acme.Client{
		Key:          signer,
		HTTPClient:   &httpClient,
		DirectoryURL: w.config.DirectoryURL,
		UserAgent:    "cdnca-control-api-acme-worker/1",
		RetryBackoff: w.retryBackoff,
	}, locations
}

// RFC 8555 does not require Location on a finalize response. x/crypto/acme
// needs it while the order is processing, so retain the URL from newOrder and
// restore it only on the matching successful finalize response.
type orderLocationTransport struct {
	base   http.RoundTripper
	mu     sync.RWMutex
	orders map[string]string
}

func (t *orderLocationTransport) Set(finalizeURL, orderURL string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.orders[finalizeURL] = orderURL
}

func (t *orderLocationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || request.Method != http.MethodPost || response.StatusCode < 200 || response.StatusCode >= 300 ||
		response.Header.Get("Location") != "" {
		return response, err
	}
	t.mu.RLock()
	orderURL := t.orders[request.URL.String()]
	t.mu.RUnlock()
	if orderURL != "" {
		response.Header.Set("Location", orderURL)
	}
	return response, nil
}

func (w *Worker) retryBackoff(attempt int, _ *http.Request, response *http.Response) time.Duration {
	if attempt > w.config.MaxRetries {
		return -1
	}
	if response != nil {
		if delay := parseRetryAfter(response.Header.Get("Retry-After"), w.config.Clock().UTC()); delay > 0 {
			return min(delay, w.config.MaxRetryAfter)
		}
	}
	delay := w.config.RetryBase
	for index := 1; index < attempt && delay < w.config.MaxRetryAfter; index++ {
		delay *= 2
	}
	return min(delay, w.config.MaxRetryAfter)
}

// acmeProblem reports whether err is an ACME problem of one of the types
// (urn:ietf:params:acme:error:<type>).
func acmeProblem(err error, types ...string) bool {
	var problem *acme.Error
	if !errors.As(err, &problem) {
		return false
	}
	for _, kind := range types {
		if problem.ProblemType == "urn:ietf:params:acme:error:"+kind {
			return true
		}
	}
	return false
}

func validateConfig(config Config, deps Dependencies) error {
	const cleanupLeaseSafetyMargin = 5 * time.Second
	parsed, err := url.Parse(config.DirectoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || config.Clock == nil ||
		config.OrderTimeout <= 0 || config.RequestTimeout <= 0 || config.ChallengeTimeout <= 0 ||
		config.PropagationTimeout <= 0 || config.CleanupTimeout <= 0 || config.RetryBase <= 0 ||
		config.MaxRetryAfter <= 0 || config.MaxRetries < 0 || config.MaxRetries > 20 ||
		config.MaxConcurrentAuthorizations < 1 || config.MaxConcurrentAuthorizations > 100 ||
		config.LeaseDuration < config.OrderTimeout ||
		config.LeaseDuration-config.OrderTimeout < config.CleanupTimeout ||
		config.LeaseDuration-config.OrderTimeout-config.CleanupTimeout < cleanupLeaseSafetyMargin ||
		config.RetryDelay <= 0 ||
		deps.Signers == nil || deps.Accounts == nil || deps.Certificates == nil || deps.Operations == nil {
		return failure(CodeInvalidInput, err)
	}
	return nil
}

func normalizeIssueRequest(request *IssueRequest) ([]string, error) {
	providerValid := request.ProviderRef == "" && request.ProviderID == uuid.Nil && request.ZoneID == uuid.Nil
	if request.ChallengeType == ChallengeDNS01 {
		providerValid = request.ProviderID != uuid.Nil && request.ZoneID != uuid.Nil &&
			request.ProviderRef == request.ProviderID.String()
	}
	if request.TenantID == uuid.Nil || request.ScopeID == uuid.Nil ||
		request.CertificateOrderID == uuid.Nil || request.ActorUserID == uuid.Nil ||
		request.OperationID != request.CertificateOrderID.String() ||
		len(request.OperationID) < 1 || len(request.OperationID) > 200 ||
		!providerValid || len(request.ProviderRef) > 200 ||
		len(request.AccountKeyRef) < 1 || len(request.AccountKeyRef) > 200 ||
		len(request.CertificateKeyRef) < 1 || len(request.CertificateKeyRef) > 200 ||
		(request.ChallengeType != ChallengeHTTP01 && request.ChallengeType != ChallengeDNS01) ||
		len(request.Domains) < 1 || len(request.Domains) > 100 ||
		strings.ContainsAny(request.OperationID+request.ProviderRef+request.AccountKeyRef+request.CertificateKeyRef, "\r\n\x00") {
		return nil, failure(CodeInvalidInput, nil)
	}
	if len(request.Contacts) > 10 {
		return nil, failure(CodeInvalidInput, nil)
	}
	seenContacts := make(map[string]struct{}, len(request.Contacts))
	for _, contact := range request.Contacts {
		address := strings.TrimPrefix(contact, "mailto:")
		at := strings.IndexByte(address, '@')
		if len(contact) < 8 || len(contact) > 320 || !strings.HasPrefix(contact, "mailto:") ||
			contact != strings.TrimSpace(contact) || containsSpaceOrControl(contact) ||
			at < 1 || at == len(address)-1 {
			return nil, failure(CodeInvalidInput, nil)
		}
		if _, exists := seenContacts[contact]; exists {
			return nil, failure(CodeInvalidInput, nil)
		}
		seenContacts[contact] = struct{}{}
	}

	domains := make([]string, 0, len(request.Domains))
	seen := make(map[string]struct{}, len(request.Domains))
	for _, raw := range request.Domains {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		wildcard := strings.HasPrefix(domain, "*.")
		name := strings.TrimPrefix(domain, "*.")
		if !validDNSName(name) || (wildcard && request.ChallengeType != ChallengeDNS01) {
			return nil, failure(CodeInvalidInput, nil)
		}
		if _, exists := seen[domain]; exists {
			return nil, failure(CodeInvalidInput, nil)
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	return domains, nil
}

func validDNSName(name string) bool {
	if len(name) < 1 || len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func issueRequestDigest(request IssueRequest) string {
	hash := sha256.New()
	for _, value := range []string{
		request.TenantID.String(),
		request.ScopeID.String(),
		request.OperationID,
		request.CertificateOrderID.String(),
		request.ActorUserID.String(),
		request.DirectoryURL,
		request.ProviderID.String(),
		request.ZoneID.String(),
		request.ProviderRef,
		request.AccountKeyRef,
		request.CertificateKeyRef,
		string(request.ChallengeType),
		strings.Join(request.Contacts, "\x00"),
		strconv.FormatBool(request.AcceptTerms),
		strings.Join(request.Domains, "\x00"),
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0xff})
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func validFrozenIssueRequest(request IssueRequest) bool {
	normalized := request
	domains, err := normalizeIssueRequest(&normalized)
	if err != nil || !slices.Equal(domains, request.Domains) {
		return false
	}
	directory, err := url.Parse(request.DirectoryURL)
	return err == nil && directory.Scheme == "https" && directory.Host != ""
}

func issueRequestsEqual(left, right IssueRequest) bool {
	return left.TenantID == right.TenantID && left.ScopeID == right.ScopeID && left.OperationID == right.OperationID &&
		left.CertificateOrderID == right.CertificateOrderID && left.ActorUserID == right.ActorUserID &&
		left.ProviderID == right.ProviderID && left.ZoneID == right.ZoneID &&
		left.ProviderRef == right.ProviderRef && left.DirectoryURL == right.DirectoryURL &&
		left.AccountKeyRef == right.AccountKeyRef && left.CertificateKeyRef == right.CertificateKeyRef &&
		slices.Equal(left.Contacts, right.Contacts) && left.AcceptTerms == right.AcceptTerms &&
		slices.Equal(left.Domains, right.Domains) && left.ChallengeType == right.ChallengeType
}

func challengeMatchesRequest(challenge ChallengeIdentity, lease OperationLease) bool {
	request := lease.Request
	return lease.TenantID == request.TenantID && lease.ScopeID == request.ScopeID &&
		challenge.TenantID == request.TenantID && challenge.ScopeID == request.ScopeID &&
		challenge.OperationID == request.OperationID && challenge.OperationID == lease.OperationID &&
		challenge.ProviderID == request.ProviderID && challenge.ZoneID == request.ZoneID &&
		challenge.ProviderRef == request.ProviderRef
}

func validateRemoteTXTHandle(handle RemoteTXTHandle, providerRef string) error {
	if handle.ProviderRef != providerRef || len(handle.ProviderRef) < 1 || len(handle.ProviderRef) > 200 ||
		len(handle.RecordRef) < 1 || len(handle.RecordRef) > 2048 ||
		handle.ProviderRef != strings.TrimSpace(handle.ProviderRef) ||
		handle.RecordRef != strings.TrimSpace(handle.RecordRef) ||
		containsControl(handle.ProviderRef) || containsControl(handle.RecordRef) {
		return errors.New("invalid remote TXT handle")
	}
	return nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func containsSpaceOrControl(value string) bool {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func validateNewOrder(order *acme.Order, domains []string) error {
	if order == nil || order.URI == "" || order.FinalizeURL == "" || len(order.AuthzURLs) == 0 ||
		len(order.AuthzURLs) > 100 {
		return errors.New("ACME order omitted required URLs")
	}
	return validateOrderIdentifiers(order, domains)
}

func orderCreationDefinitelyRejected(err error) bool {
	var protocolError *acme.Error
	if errors.As(err, &protocolError) {
		return true
	}
	_, rateLimited := acme.RateLimit(err)
	return rateLimited
}

func validateResumedOrder(order *acme.Order, state OperationState, domains []string) error {
	if order == nil || state.OrderURL == "" || state.FinalizeURL == "" || len(state.AuthorizationURLs) == 0 {
		return errors.New("persisted ACME order is incomplete")
	}
	if order.URI != "" && order.URI != state.OrderURL ||
		order.FinalizeURL != "" && order.FinalizeURL != state.FinalizeURL ||
		len(order.AuthzURLs) > 0 && !slices.Equal(order.AuthzURLs, state.AuthorizationURLs) ||
		state.CertificateURL != "" && order.CertURL != "" && order.CertURL != state.CertificateURL {
		return errors.New("ACME order facts differ from persisted state")
	}
	return validateOrderIdentifiers(order, domains)
}

func validateOrderIdentifiers(order *acme.Order, domains []string) error {
	if len(order.Identifiers) == 0 {
		return errors.New("ACME order omitted identifiers")
	}
	got := make([]string, len(order.Identifiers))
	for index, identifier := range order.Identifiers {
		if identifier.Type != "dns" {
			return errors.New("ACME order contains a non-DNS identifier")
		}
		got[index] = identifier.Value
	}
	slices.Sort(got)
	if !slices.Equal(got, domains) {
		return errors.New("ACME order identifiers differ from request")
	}
	return nil
}

func authorizationMatchesRequest(identifier string, wildcard bool, domains []string) bool {
	if wildcard {
		identifier = "*." + identifier
	}
	return slices.Contains(domains, identifier)
}

func findChallenge(authorization *acme.Authorization, challengeType ChallengeType) *acme.Challenge {
	for _, challenge := range authorization.Challenges {
		if challenge.Type == string(challengeType) {
			return challenge
		}
	}
	return nil
}

func parseCertificateChain(
	chainDER [][]byte,
	certificateURL string,
	domains []string,
	signer crypto.Signer,
	now time.Time,
) (IssuedCertificate, error) {
	// Stable codes, so FailureDetail logs which check failed (fix-certstuck).
	if len(chainDER) == 0 || len(chainDER) > 5 || certificateURL == "" {
		return IssuedCertificate{}, errors.New("certificate_chain_invalid")
	}
	parsed := make([]*x509.Certificate, len(chainDER))
	for index, der := range chainDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return IssuedCertificate{}, err
		}
		parsed[index] = certificate
		if index > 0 {
			if err := parsed[index-1].CheckSignatureFrom(certificate); err != nil {
				return IssuedCertificate{}, err
			}
		}
	}
	leaf := parsed[0]
	if now.Before(leaf.NotBefore.Add(-time.Minute)) || !now.Before(leaf.NotAfter) {
		return IssuedCertificate{}, errors.New("certificate_validity_outside_now")
	}
	wantNames := slices.Clone(domains)
	gotNames := slices.Clone(leaf.DNSNames)
	slices.Sort(wantNames)
	slices.Sort(gotNames)
	if !slices.Equal(wantNames, gotNames) {
		return IssuedCertificate{}, errors.New("certificate_names_mismatch")
	}
	for _, domain := range domains {
		if err := leaf.VerifyHostname(domain); err != nil {
			return IssuedCertificate{}, err
		}
	}
	wantPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return IssuedCertificate{}, err
	}
	gotPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(wantPublic, gotPublic) {
		// Seen on 73: the CA reused this pending order for a same-name
		// request on the same account, which finalized it with its own key.
		return IssuedCertificate{}, errors.New("certificate_public_key_mismatch")
	}

	var certificatePEM bytes.Buffer
	clonedDER := make([][]byte, len(chainDER))
	for index, der := range chainDER {
		clonedDER[index] = bytes.Clone(der)
		if err := pem.Encode(&certificatePEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return IssuedCertificate{}, err
		}
	}
	fingerprint := sha256.Sum256(chainDER[0])
	return IssuedCertificate{
		LeafDER:         bytes.Clone(chainDER[0]),
		ChainDER:        clonedDER,
		CertificatePEM:  certificatePEM.Bytes(),
		SerialNumber:    leaf.SerialNumber.String(),
		DNSNames:        slices.Clone(domains),
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		CertificateURL:  certificateURL,
		LeafFingerprint: fmt.Sprintf("sha256:%x", fingerprint),
	}, nil
}

func cloneCertificate(input IssuedCertificate) IssuedCertificate {
	result := input
	result.LeafDER = bytes.Clone(input.LeafDER)
	result.CertificatePEM = bytes.Clone(input.CertificatePEM)
	result.DNSNames = slices.Clone(input.DNSNames)
	result.ChainDER = make([][]byte, len(input.ChainDER))
	for index := range input.ChainDER {
		result.ChainDER[index] = bytes.Clone(input.ChainDER[index])
	}
	return result
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	trimmed := strings.TrimSpace(value)
	const maximumDuration = time.Duration(1<<63 - 1)
	if seconds, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
		if seconds > uint64(maximumDuration/time.Second) {
			return maximumDuration
		}
		return time.Duration(seconds) * time.Second
	}
	digitsOnly := trimmed != ""
	for _, character := range trimmed {
		if character < '0' || character > '9' {
			digitsOnly = false
			break
		}
	}
	if digitsOnly {
		return maximumDuration
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	return max(date.Sub(now), 0)
}

func setFirstError(mu *sync.Mutex, target *error, err error) {
	mu.Lock()
	defer mu.Unlock()
	if *target == nil {
		*target = err
	}
}

// waitAuthoritativeTXT polls the zone's authoritative name servers until
// they all serve the challenge value. Running out of the propagation window
// is a retryable propagation failure, never an authorization the CA saw fail.
func (w *Worker) waitAuthoritativeTXT(ctx context.Context, identity ChallengeIdentity) error {
	if w.deps.AuthoritativeTXT == nil {
		return nil
	}
	interval := w.config.PropagationPollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		visible, err := w.deps.AuthoritativeTXT.TXTVisible(ctx, identity.RecordName, identity.ExactValue)
		if err == nil && visible {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if parentErr := context.Cause(ctx); errors.Is(parentErr, context.Canceled) {
				return contextFailure(parentErr)
			}
			return &Error{Code: CodeChallengePropagationFailed, Temporary: true}
		case <-timer.C:
		}
	}
}

func phaseFailure(code ErrorCode, cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return contextFailure(cause)
	}
	switch ErrorCodeOf(cause) {
	case CodeHTTP01NodeAggregateRequired, CodeHTTP01NodeUnsupported, CodeHTTP01NoServingNode:
		return failure(ErrorCodeOf(cause), nil)
	}
	return failure(code, cause)
}

func retryableFailure(err error) bool {
	var workerError *Error
	if errors.As(err, &workerError) {
		if workerError.Temporary {
			return true
		}
		switch workerError.Code {
		case CodeKeyUnavailable, CodeAccountUnavailable, CodeDirectoryUnavailable,
			CodeChallengePublishFailed, CodeChallengePropagationFailed,
			CodeChallengeCleanupFailed, CodeCertificateStoreFailed,
			CodeOperationStoreFailed, CodeTimeout, CodeCancelled:
			return true
		}
	}
	return false
}

func contextFailure(cause error) error {
	if errors.Is(cause, context.Canceled) {
		return &Error{Code: CodeCancelled}
	}
	return &Error{Code: CodeTimeout, Temporary: true}
}

func acmeFailure(fallback ErrorCode, cause error, maxRetryAfter time.Duration) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return contextFailure(cause)
	}
	if delay, ok := acme.RateLimit(cause); ok {
		return &Error{Code: CodeRateLimited, RetryAfter: min(max(delay, 0), maxRetryAfter), Temporary: true, cause: cause}
	}
	var protocolError *acme.Error
	if errors.As(cause, &protocolError) {
		problem := strings.ToLower(protocolError.ProblemType)
		if strings.HasSuffix(problem, ":unauthorized") || strings.HasSuffix(problem, ":rejectedidentifier") {
			return &Error{Code: CodeAuthorizationInvalid, cause: cause}
		}
		if protocolError.StatusCode >= 500 {
			return &Error{Code: fallback, Temporary: true, cause: cause}
		}
	}
	return failure(fallback, cause)
}

func failure(code ErrorCode, cause error) *Error {
	return &Error{Code: code, cause: cause}
}
