package dnsproviderlive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

const (
	EvidenceSchema = "cdnca.dns-provider-live-propagation.v1"

	StatusPass           = "pass"
	StatusFail           = "fail"
	StatusCleanupPending = "cleanup_pending"

	PhaseConfig        = "config"
	PhaseGuard         = "guard"
	PhaseSentinel      = "sentinel"
	PhaseTarget        = "target"
	PhaseProvider      = "provider"
	PhaseAuthoritative = "authoritative"
	PhasePublic        = "public"
	PhaseCleanup       = "cleanup"
	PhaseComplete      = "complete"

	ReasonInvalidConfig      = "invalid_config"
	ReasonGuardMismatch      = "guard_mismatch"
	ReasonEntropyUnavailable = "entropy_unavailable"
	ReasonPresentNotApplied  = "present_not_applied"
	ReasonRecoveryAmbiguous  = "recovery_ambiguous"
	ReasonRecoveryUnproven   = "recovery_unproven"
	ReasonProviderObserve    = "provider_observe_failed"
	ReasonPropagationTimeout = "propagation_timeout"
	ReasonCanceled           = "canceled"
	ReasonCleanupUnproven    = "cleanup_unproven"
	ReasonVerified           = "verified"
)

var backoffSchedule = [...]time.Duration{
	time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	15 * time.Second,
	30 * time.Second,
}

type Endpoint struct {
	Address netip.AddrPort
}

type TXTObservation struct {
	Authoritative bool
	Recursive     bool
	RCode         uint8
	Values        []string
}

type DNS interface {
	LookupTXT(context.Context, Endpoint, string) (TXTObservation, error)
}

type Provider interface {
	PresentTXT(context.Context, acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, error)
	RecoverTXT(context.Context, acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, bool, error)
	ObserveTXT(context.Context, acmeworker.ChallengeIdentity) error
	DeleteTXT(context.Context, acmeworker.ChallengeIdentity) error
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type Config struct {
	ProviderCode   string
	Zone           string
	GuardOwner     string
	GuardSHA256    [sha256.Size]byte
	Authoritative  []Endpoint
	Public         []Endpoint
	Timeout        time.Duration
	CleanupTimeout time.Duration
	TenantID       uuid.UUID
	ScopeID        uuid.UUID
	ProviderID     uuid.UUID
	ZoneID         uuid.UUID
}

// Evidence deliberately contains only bounded classifications and aggregate
// counts. Record identities, endpoints, credentials, handles, and raw errors
// never enter this value.
type Evidence struct {
	Schema             string `json:"schema"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Phase              string `json:"phase"`
	ProviderCode       string `json:"provider_code,omitempty"`
	AuthoritativeCount int    `json:"authoritative_count"`
	PublicCount        int    `json:"public_count"`
	CleanupAttempted   bool   `json:"cleanup_attempted"`
	CleanupComplete    bool   `json:"cleanup_complete"`
	ElapsedSeconds     int64  `json:"elapsed_seconds"`
}

type runState struct {
	config          Config
	provider        Provider
	dns             DNS
	clock           Clock
	start           time.Time
	sentinel        acmeworker.ChallengeIdentity
	target          acmeworker.ChallengeIdentity
	sentinelCreated bool
}

func Run(ctx context.Context, config Config, provider Provider, dns DNS, clock Clock, entropy io.Reader) (evidence Evidence) {
	evidence = Evidence{
		Schema:             EvidenceSchema,
		Status:             StatusFail,
		Reason:             ReasonInvalidConfig,
		Phase:              PhaseConfig,
		AuthoritativeCount: len(config.Authoritative),
		PublicCount:        len(config.Public),
	}
	if supportedProvider(config.ProviderCode) {
		evidence.ProviderCode = config.ProviderCode
	}
	if ctx == nil || provider == nil || dns == nil || clock == nil || entropy == nil || validateConfig(config) != nil {
		return evidence
	}
	runCtx, cancelRun := context.WithTimeout(ctx, config.Timeout)
	defer cancelRun()

	state := runState{config: config, provider: provider, dns: dns, clock: clock, start: clock.Now()}
	defer func() {
		elapsed := clock.Now().Sub(state.start)
		if elapsed > 0 {
			evidence.ElapsedSeconds = int64(elapsed / time.Second)
		}
	}()

	evidence.Phase = PhaseGuard
	if !state.guardValid(runCtx) {
		if runCtx.Err() != nil {
			evidence.Reason = runContextReason(runCtx)
		} else {
			evidence.Reason = ReasonGuardMismatch
		}
		return evidence
	}
	if runCtx.Err() != nil || clock.Now().Sub(state.start) >= config.Timeout {
		evidence.Reason = runContextReason(runCtx)
		if runCtx.Err() == nil {
			evidence.Reason = ReasonPropagationTimeout
		}
		return evidence
	}

	identities, err := buildIdentities(config, entropy)
	if err != nil {
		evidence.Reason = ReasonEntropyUnavailable
		return evidence
	}
	state.sentinel, state.target = identities[0], identities[1]
	evidence.CleanupAttempted = true
	operationSucceeded := false
	defer func() {
		evidence.Phase = PhaseCleanup
		evidence.CleanupComplete = state.cleanup()
		if !evidence.CleanupComplete {
			evidence.Status = StatusCleanupPending
			if operationSucceeded {
				evidence.Reason = ReasonCleanupUnproven
			}
			return
		}
		if operationSucceeded {
			evidence.Status = StatusPass
			evidence.Reason = ReasonVerified
			evidence.Phase = PhaseComplete
		}
	}()

	evidence.Phase = PhaseSentinel
	if ok, reason := state.present(runCtx, &state.sentinel); !ok {
		state.sentinelCreated = state.sentinel.TXTHandle != (acmeworker.RemoteTXTHandle{})
		evidence.Reason = reason
		return evidence
	}
	state.sentinelCreated = true
	evidence.Phase = PhaseTarget
	if ok, reason := state.present(runCtx, &state.target); !ok {
		evidence.Reason = reason
		return evidence
	}

	evidence.Phase = PhaseProvider
	if state.provider.ObserveTXT(runCtx, state.sentinel) != nil || state.provider.ObserveTXT(runCtx, state.target) != nil {
		if runCtx.Err() != nil {
			evidence.Reason = runContextReason(runCtx)
		} else {
			evidence.Reason = ReasonProviderObserve
		}
		return evidence
	}

	evidence.Phase = PhaseAuthoritative
	if !state.waitForPropagation(runCtx, &evidence) {
		return evidence
	}
	operationSucceeded = true
	return evidence
}

func (s *runState) guardValid(ctx context.Context) bool {
	valid := ctx.Err() == nil
	for _, endpoint := range s.config.Authoritative {
		observation, err := s.dns.LookupTXT(ctx, endpoint, s.config.GuardOwner)
		if err != nil || observation.RCode != 0 || !observation.Authoritative || len(observation.Values) != 1 ||
			sha256.Sum256([]byte(firstValue(observation.Values))) != s.config.GuardSHA256 {
			valid = false
		}
	}
	return valid
}

func (s *runState) present(ctx context.Context, challenge *acmeworker.ChallengeIdentity) (bool, string) {
	handle, err := s.provider.PresentTXT(ctx, *challenge)
	if err != nil {
		recovered, found, recoverErr := s.provider.RecoverTXT(ctx, *challenge)
		if recoverErr != nil {
			if dnsproviderremote.ErrorCodeOf(recoverErr) == dnsproviderremote.CodeRecordMismatch {
				return false, ReasonRecoveryAmbiguous
			}
			if ctx.Err() != nil {
				return false, runContextReason(ctx)
			}
			return false, ReasonRecoveryUnproven
		}
		if !found {
			return false, ReasonPresentNotApplied
		}
		handle = recovered
	}
	challenge.TXTHandle = handle
	if err := s.provider.ObserveTXT(ctx, *challenge); err != nil {
		if ctx.Err() != nil {
			return false, runContextReason(ctx)
		}
		return false, ReasonProviderObserve
	}
	return true, ""
}

func (s *runState) waitForPropagation(ctx context.Context, evidence *Evidence) bool {
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			evidence.Reason = runContextReason(ctx)
			return false
		}
		if s.clock.Now().Sub(s.start) >= s.config.Timeout {
			evidence.Reason = ReasonPropagationTimeout
			return false
		}

		expected := []string{s.sentinel.ExactValue, s.target.ExactValue}
		evidence.Phase = PhaseAuthoritative
		authoritative := s.allExact(ctx, s.config.Authoritative, s.target.RecordName, expected, true)
		if authoritative {
			evidence.Phase = PhasePublic
			if s.allExact(ctx, s.config.Public, s.target.RecordName, expected, false) {
				return true
			}
		}

		remaining := s.config.Timeout - s.clock.Now().Sub(s.start)
		if remaining <= 0 {
			evidence.Reason = ReasonPropagationTimeout
			return false
		}
		delay := backoff(attempt)
		if delay > remaining {
			delay = remaining
		}
		if err := s.clock.Sleep(ctx, delay); err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				evidence.Reason = runContextReason(ctx)
				if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
					evidence.Reason = ReasonPropagationTimeout
				}
			} else {
				evidence.Reason = ReasonPropagationTimeout
			}
			return false
		}
	}
}

func (s *runState) allExact(ctx context.Context, endpoints []Endpoint, owner string, expected []string, requireAuthoritative bool) bool {
	valid := ctx.Err() == nil
	for _, endpoint := range endpoints {
		observation, err := s.dns.LookupTXT(ctx, endpoint, owner)
		if err != nil || observation.RCode != 0 ||
			(requireAuthoritative && !observation.Authoritative) ||
			(!requireAuthoritative && (observation.Authoritative || !observation.Recursive)) ||
			!sameValues(observation.Values, expected) {
			valid = false
		}
	}
	return valid
}

func (s *runState) cleanup() bool {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.CleanupTimeout)
	defer cancel()
	started := s.clock.Now()

	targetAbsent := s.removeAndProveAbsent(ctx, &s.target)
	sentinelRetained := !s.sentinelCreated || s.provider.ObserveTXT(ctx, s.sentinel) == nil
	sentinelAbsent := s.removeAndProveAbsent(ctx, &s.sentinel)
	providerAbsent := targetAbsent && sentinelRetained && sentinelAbsent
	dnsAbsent := s.waitForAbsence(ctx, started)
	return providerAbsent && dnsAbsent
}

func (s *runState) removeAndProveAbsent(ctx context.Context, challenge *acmeworker.ChallengeIdentity) bool {
	if challenge.TXTHandle != (acmeworker.RemoteTXTHandle{}) {
		_ = s.provider.DeleteTXT(ctx, *challenge)
		if dnsproviderremote.ErrorCodeOf(s.provider.ObserveTXT(ctx, *challenge)) != dnsproviderremote.CodeRecordNotFound {
			return false
		}
	}
	handle, found, err := s.provider.RecoverTXT(ctx, *challenge)
	if err != nil {
		return false
	}
	if !found {
		return true
	}
	challenge.TXTHandle = handle
	_ = s.provider.DeleteTXT(ctx, *challenge)
	observedAbsent := dnsproviderremote.ErrorCodeOf(s.provider.ObserveTXT(ctx, *challenge)) == dnsproviderremote.CodeRecordNotFound
	_, found, err = s.provider.RecoverTXT(ctx, *challenge)
	return observedAbsent && err == nil && !found
}

func (s *runState) waitForAbsence(ctx context.Context, started time.Time) bool {
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil || s.clock.Now().Sub(started) >= s.config.CleanupTimeout {
			return false
		}
		if s.allAbsent(ctx, s.config.Authoritative, s.target.RecordName, true) &&
			s.allAbsent(ctx, s.config.Public, s.target.RecordName, false) {
			return true
		}
		remaining := s.config.CleanupTimeout - s.clock.Now().Sub(started)
		if remaining <= 0 {
			return false
		}
		delay := backoff(attempt)
		if delay > remaining {
			delay = remaining
		}
		if s.clock.Sleep(ctx, delay) != nil {
			return false
		}
	}
}

func (s *runState) allAbsent(ctx context.Context, endpoints []Endpoint, owner string, requireAuthoritative bool) bool {
	absent := ctx.Err() == nil
	for _, endpoint := range endpoints {
		observation, err := s.dns.LookupTXT(ctx, endpoint, owner)
		if err != nil || (observation.RCode != 0 && observation.RCode != 3) ||
			(requireAuthoritative && !observation.Authoritative) ||
			(!requireAuthoritative && (observation.Authoritative || !observation.Recursive)) ||
			len(observation.Values) != 0 {
			absent = false
		}
	}
	return absent
}

func buildIdentities(config Config, entropy io.Reader) ([2]acmeworker.ChallengeIdentity, error) {
	var raw [32]byte
	if _, err := io.ReadFull(entropy, raw[:]); err != nil {
		clear(raw[:])
		return [2]acmeworker.ChallengeIdentity{}, err
	}
	defer clear(raw[:])

	ownerToken := hex.EncodeToString(raw[:16])
	targetToken := hex.EncodeToString(raw[16:])
	sentinelDigest := sha256.Sum256(append([]byte("cdnca-dns-live-sentinel-v1:"), raw[16:]...))
	sentinelToken := hex.EncodeToString(sentinelDigest[:16])
	clear(sentinelDigest[:])
	attemptDigest := sha256.Sum256(append([]byte("cdnca-dns-live-attempt-v1:"), raw[:16]...))
	attemptDigest[6] = (attemptDigest[6] & 0x0f) | 0x40
	attemptDigest[8] = (attemptDigest[8] & 0x3f) | 0x80
	attemptID, err := uuid.FromBytes(attemptDigest[:16])
	clear(attemptDigest[:])
	if err != nil {
		return [2]acmeworker.ChallengeIdentity{}, err
	}

	owner := "_cdnca-live-" + ownerToken + "." + config.Zone + "."
	base := acmeworker.ChallengeIdentity{
		TenantID:         config.TenantID,
		ScopeID:          config.ScopeID,
		ProviderID:       config.ProviderID,
		ZoneID:           config.ZoneID,
		OperationID:      "dns-live-" + ownerToken,
		AttemptID:        attemptID,
		ProviderRef:      config.ProviderID.String(),
		AuthorizationURL: "https://dns-live.invalid/authorization/" + ownerToken,
		ChallengeURL:     "https://dns-live.invalid/challenge/" + ownerToken,
		ChallengeType:    acmeworker.ChallengeDNS01,
		Identifier:       config.Zone,
		Token:            ownerToken,
		RecordName:       owner,
	}
	sentinel := base
	sentinel.ExactValue = "cdnca-live-sentinel-" + sentinelToken
	target := base
	target.ExactValue = "cdnca-live-target-" + targetToken
	return [2]acmeworker.ChallengeIdentity{sentinel, target}, nil
}

func validateConfig(config Config) error {
	if !supportedProvider(config.ProviderCode) || !validDNSName(config.Zone, false, false) ||
		!validDNSName(config.GuardOwner, true, true) || !strings.HasSuffix(config.GuardOwner, "."+config.Zone+".") ||
		config.GuardSHA256 == ([sha256.Size]byte{}) || config.Timeout < 60*time.Second || config.Timeout > 1800*time.Second ||
		config.CleanupTimeout <= 0 || config.CleanupTimeout > 1800*time.Second || config.TenantID == uuid.Nil ||
		config.ScopeID == uuid.Nil || config.TenantID == config.ScopeID || config.ProviderID == uuid.Nil || config.ZoneID == uuid.Nil ||
		len(config.Authoritative) == 0 || len(config.Public) == 0 {
		return errors.New(ReasonInvalidConfig)
	}
	seen := make(map[netip.AddrPort]struct{}, len(config.Authoritative)+len(config.Public))
	for _, endpoints := range [][]Endpoint{config.Authoritative, config.Public} {
		for _, endpoint := range endpoints {
			if !endpoint.Address.IsValid() || endpoint.Address.Port() == 0 {
				return errors.New(ReasonInvalidConfig)
			}
			if _, duplicate := seen[endpoint.Address]; duplicate {
				return errors.New(ReasonInvalidConfig)
			}
			seen[endpoint.Address] = struct{}{}
		}
	}
	return nil
}

func supportedProvider(provider string) bool {
	switch provider {
	case "aliyun", "cloudflare", "huawei", "dnspod_cn", "dns_com", "dns_la":
		return true
	default:
		return false
	}
}

func validDNSName(value string, trailingDot, allowUnderscore bool) bool {
	if value == "" || value != strings.ToLower(value) || strings.IndexFunc(value, func(r rune) bool { return r > 127 }) >= 0 {
		return false
	}
	if trailingDot {
		if !strings.HasSuffix(value, ".") {
			return false
		}
		value = strings.TrimSuffix(value, ".")
	} else if strings.HasSuffix(value, ".") {
		return false
	}
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || (allowUnderscore && char == '_') {
				continue
			}
			return false
		}
	}
	return true
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func sameValues(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func backoff(attempt int) time.Duration {
	if attempt >= len(backoffSchedule) {
		return backoffSchedule[len(backoffSchedule)-1]
	}
	return backoffSchedule[attempt]
}

func runContextReason(ctx context.Context) string {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ReasonPropagationTimeout
	}
	return ReasonCanceled
}

func WriteEvidence(path string, evidence Evidence) error {
	if !validEvidence(evidence) || path == "" || filepath.Base(path) == "." {
		return errors.New("dns live evidence invalid")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("dns live evidence target unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("dns live evidence target unavailable")
	}

	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return errors.New("dns live evidence encoding failed")
	}
	raw = append(raw, '\n')
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return errors.New("dns live evidence temporary file failed")
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("dns live evidence mode failed")
	}
	if _, err := file.Write(raw); err != nil {
		return errors.New("dns live evidence write failed")
	}
	clear(raw)
	if err := file.Sync(); err != nil {
		return errors.New("dns live evidence sync failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("dns live evidence close failed")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("dns live evidence target unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("dns live evidence target unavailable")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("dns live evidence replace failed")
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("dns live evidence directory unavailable")
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return errors.New("dns live evidence directory sync failed")
	}
	return nil
}

func validEvidence(evidence Evidence) bool {
	if evidence.Schema != EvidenceSchema || evidence.AuthoritativeCount < 0 || evidence.PublicCount < 0 || evidence.ElapsedSeconds < 0 ||
		(evidence.ProviderCode != "" && !supportedProvider(evidence.ProviderCode)) {
		return false
	}
	switch evidence.Phase {
	case PhaseConfig, PhaseGuard, PhaseSentinel, PhaseTarget, PhaseProvider, PhaseAuthoritative, PhasePublic, PhaseCleanup, PhaseComplete:
	default:
		return false
	}
	switch evidence.Reason {
	case ReasonInvalidConfig, ReasonGuardMismatch, ReasonEntropyUnavailable, ReasonPresentNotApplied, ReasonRecoveryAmbiguous,
		ReasonRecoveryUnproven, ReasonProviderObserve, ReasonPropagationTimeout, ReasonCanceled, ReasonCleanupUnproven, ReasonVerified:
	default:
		return false
	}
	switch evidence.Status {
	case StatusPass:
		return evidence.Reason == ReasonVerified && evidence.Phase == PhaseComplete &&
			evidence.CleanupAttempted && evidence.CleanupComplete
	case StatusFail:
		return evidence.Reason != ReasonVerified
	case StatusCleanupPending:
		return evidence.Reason != ReasonVerified && evidence.CleanupAttempted && !evidence.CleanupComplete
	default:
		return false
	}
}
