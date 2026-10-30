package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderlive"
)

const (
	configSchema       = "cdnca:dns-provider-sandbox-e2e-config:v1"
	evidenceSchema     = "cdnca:dns-provider-sandbox-e2e-evidence:v1"
	requiredAck        = "round7-six-provider-disposable-zones"
	maximumConfigBytes = 1 << 20
	maximumSecretBytes = 64 << 10
)

var exactProviders = [...]string{
	"cloudflare", "aliyun", "huawei", "dnspod_cn", "dns_com", "dns_la",
}

type batchConfig struct {
	Schema       string          `json:"schema"`
	EvidencePath string          `json:"evidence_path"`
	Providers    []providerInput `json:"providers"`
}

type providerInput struct {
	Code                  string   `json:"code"`
	Zone                  string   `json:"zone"`
	GuardOwner            string   `json:"guard_owner"`
	GuardSHA256           string   `json:"guard_sha256"`
	Authoritative         []string `json:"authoritative"`
	PublicRecursive       []string `json:"public_recursive"`
	CredentialEnv         string   `json:"credential_env,omitempty"`
	CredentialFile        string   `json:"credential_file,omitempty"`
	InitialIPv4           string   `json:"initial_ipv4"`
	UpdatedIPv4           string   `json:"updated_ipv4"`
	InitialIPv6           string   `json:"initial_ipv6"`
	UpdatedIPv6           string   `json:"updated_ipv6"`
	CNAMETarget           string   `json:"cname_target"`
	UpdatedCNAMETarget    string   `json:"updated_cname_target"`
	TTL                   uint32   `json:"ttl"`
	UpdatedTTL            uint32   `json:"updated_ttl"`
	UpdateLine            string   `json:"update_line,omitempty"`
	UpdateWeight          uint32   `json:"update_weight,omitempty"`
	RateLimitMaximumReads int      `json:"rate_limit_maximum_reads"`
	RateLimitIntervalMS   int      `json:"rate_limit_interval_ms"`
	TimeoutSeconds        int      `json:"timeout_seconds"`
	CleanupTimeoutSeconds int      `json:"cleanup_timeout_seconds"`
}

type preparedBatch struct {
	evidencePath string
	providers    []preparedProvider
}

type preparedProvider struct {
	input     providerInput
	lease     *dnsproviderlive.CredentialLease
	guard     [sha256.Size]byte
	authority []dnsproviderlive.Endpoint
	public    []dnsproviderlive.Endpoint
}

func (batch *preparedBatch) close() {
	if batch == nil {
		return
	}
	for index := range batch.providers {
		batch.providers[index].lease.Close()
		batch.providers[index].lease = nil
	}
}

type batchEvidence struct {
	Schema      string             `json:"schema"`
	Status      string             `json:"status"`
	Reason      string             `json:"reason"`
	StartedAt   string             `json:"started_at"`
	CompletedAt string             `json:"completed_at,omitempty"`
	Providers   []providerEvidence `json:"providers"`
	Resources   []resourceEvidence `json:"resources"`
}

type providerEvidence struct {
	Code                     string         `json:"code"`
	Status                   string         `json:"status"`
	Reason                   string         `json:"reason"`
	Capabilities             capabilityFact `json:"capabilities"`
	Steps                    []stepEvidence `json:"steps"`
	CleanupAttempted         bool           `json:"cleanup_attempted"`
	CleanupComplete          bool           `json:"cleanup_complete"`
	AuthoritativeConverged   bool           `json:"authoritative_converged"`
	PublicRecursiveConverged bool           `json:"public_recursive_converged"`
}

type capabilityFact struct {
	RecordTypes []string `json:"record_types"`
	Line        bool     `json:"line"`
	Weight      bool     `json:"weight"`
	RetryAfter  bool     `json:"retry_after"`
}

type stepEvidence struct {
	Name                   string `json:"name"`
	Status                 string `json:"status"`
	Reason                 string `json:"reason"`
	ProviderRequestID      string `json:"provider_request_id,omitempty"`
	RetryAfterSeconds      int64  `json:"retry_after_seconds,omitempty"`
	Revision               uint64 `json:"revision,omitempty"`
	AuthoritativeConverged bool   `json:"authoritative_converged,omitempty"`
	PublicConverged        bool   `json:"public_recursive_converged,omitempty"`
}

type resourceEvidence struct {
	Provider               string `json:"provider"`
	Kind                   string `json:"kind"`
	IdentitySHA256         string `json:"identity_sha256"`
	ProviderIdentitySHA256 string `json:"provider_identity_sha256,omitempty"`
	Revision               uint64 `json:"revision"`
	State                  string `json:"state"`
}

type evidenceWriter struct{ path string }

func main() { os.Exit(realMain()) }

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Getenv("CDNCA_DNS_SANDBOX_MUTATION_ACK") != requiredAck {
		return stableExit(2, "config_rejected")
	}
	batch, err := preflightAll(os.Getenv("CDNCA_DNS_SANDBOX_CONFIG_FILE"))
	if err != nil {
		return stableExit(2, "preflight_rejected")
	}
	defer batch.close()

	evidence := newBatchEvidence(batch)
	writer := evidenceWriter{path: batch.evidencePath}
	if err := writer.write(evidence); err != nil {
		return stableExit(3, "evidence_write_failed")
	}
	evidence = runAll(ctx, batch, writer, evidence)
	evidence.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writer.write(evidence); err != nil {
		return stableExit(3, "evidence_write_failed")
	}
	if evidence.Status != "pass" {
		return stableExit(1, evidence.Reason)
	}
	return stableExit(0, "verified")
}

func stableExit(code int, reason string) int {
	if reason == "" {
		reason = "driver_failed"
	}
	_, _ = fmt.Fprintln(os.Stderr, reason)
	return code
}

func preflightAll(path string) (*preparedBatch, error) {
	if !validInputFile(path, maximumConfigBytes, false) {
		return nil, errors.New("invalid config")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maximumConfigBytes {
		return nil, errors.New("invalid config")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config batchConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, errors.New("invalid config")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) ||
		config.Schema != configSchema || len(config.Providers) != len(exactProviders) ||
		!validEvidencePath(config.EvidencePath) {
		return nil, errors.New("invalid config")
	}

	batch := &preparedBatch{evidencePath: config.EvidencePath, providers: make([]preparedProvider, 0, len(config.Providers))}
	zones := make(map[string]struct{}, len(config.Providers))
	for index, input := range config.Providers {
		if input.Code != exactProviders[index] || !validProviderInput(input) {
			batch.close()
			return nil, errors.New("invalid provider config")
		}
		if _, duplicate := zones[input.Zone]; duplicate {
			batch.close()
			return nil, errors.New("duplicate zone")
		}
		zones[input.Zone] = struct{}{}
		guard, err := parseDigest(input.GuardSHA256)
		if err != nil {
			batch.close()
			return nil, errors.New("invalid guard")
		}
		authority, public, err := parseEndpoints(input.Authoritative, input.PublicRecursive)
		if err != nil {
			batch.close()
			return nil, errors.New("invalid endpoints")
		}
		lease, err := loadCredential(input)
		if err != nil {
			batch.close()
			return nil, errors.New("credential unavailable")
		}
		batch.providers = append(batch.providers, preparedProvider{
			input: input, lease: lease, guard: guard, authority: authority, public: public,
		})
	}
	return batch, nil
}

func validProviderInput(input providerInput) bool {
	if !validDNSName(input.Zone, false, false) || !validDNSName(input.GuardOwner, true, true) ||
		!strings.HasSuffix(input.GuardOwner, "."+input.Zone+".") ||
		(input.CredentialEnv == "") == (input.CredentialFile == "") ||
		input.TTL < 60 || input.TTL > 86400 || input.UpdatedTTL < 60 || input.UpdatedTTL > 86400 ||
		input.TTL == input.UpdatedTTL || input.RateLimitMaximumReads < 1 || input.RateLimitMaximumReads > 30 ||
		input.RateLimitIntervalMS < 1000 || input.RateLimitIntervalMS > 60000 ||
		input.TimeoutSeconds < 60 || input.TimeoutSeconds > 1800 ||
		input.CleanupTimeoutSeconds < 60 || input.CleanupTimeoutSeconds > 1800 {
		return false
	}
	initial, initialErr := netip.ParseAddr(input.InitialIPv4)
	updated, updatedErr := netip.ParseAddr(input.UpdatedIPv4)
	if initialErr != nil || updatedErr != nil || !initial.Is4() || !updated.Is4() || initial == updated ||
		initial.String() != input.InitialIPv4 || updated.String() != input.UpdatedIPv4 {
		return false
	}
	initial6, initial6Err := netip.ParseAddr(input.InitialIPv6)
	updated6, updated6Err := netip.ParseAddr(input.UpdatedIPv6)
	if initial6Err != nil || updated6Err != nil || !initial6.Is6() || initial6.Is4In6() ||
		!updated6.Is6() || updated6.Is4In6() || initial6 == updated6 ||
		initial6.String() != input.InitialIPv6 || updated6.String() != input.UpdatedIPv6 ||
		!validDNSName(input.CNAMETarget, true, false) ||
		!validDNSName(input.UpdatedCNAMETarget, true, false) ||
		input.CNAMETarget == input.UpdatedCNAMETarget {
		return false
	}
	if input.Code == "dnspod_cn" {
		return input.UpdateLine != "" && input.UpdateLine == strings.TrimSpace(input.UpdateLine) &&
			len(input.UpdateLine) <= 64 && input.UpdateWeight >= 1 && input.UpdateWeight <= 100
	}
	return input.UpdateLine == "" && input.UpdateWeight == 0
}

func loadCredential(input providerInput) (*dnsproviderlive.CredentialLease, error) {
	var raw []byte
	if input.CredentialEnv != "" {
		if input.CredentialEnv != credentialEnvironmentName(input.Code) {
			return nil, errors.New("invalid credential env")
		}
		value, ok := os.LookupEnv(input.CredentialEnv)
		if !ok || value == "" || len(value) > maximumSecretBytes {
			return nil, errors.New("credential unavailable")
		}
		raw = []byte(value)
		_ = os.Unsetenv(input.CredentialEnv)
	} else {
		if !validInputFile(input.CredentialFile, maximumSecretBytes, true) {
			return nil, errors.New("invalid credential file")
		}
		var err error
		raw, err = os.ReadFile(input.CredentialFile)
		if err != nil || len(raw) == 0 || len(raw) > maximumSecretBytes {
			clear(raw)
			return nil, errors.New("credential unavailable")
		}
	}
	reader := func(_, _ string) ([]byte, error) {
		owned := raw
		raw = nil
		return owned, nil
	}
	lease, err := dnsproviderlive.LoadCredential(reader, input.Code, "sandbox", "sandbox")
	clear(raw)
	return lease, err
}

func credentialEnvironmentName(code string) string {
	return "CDNCA_DNS_SANDBOX_" + strings.ToUpper(code) + "_CREDENTIALS_JSON"
}

func parseEndpoints(authoritative, public []string) ([]dnsproviderlive.Endpoint, []dnsproviderlive.Endpoint, error) {
	if len(authoritative) == 0 || len(authoritative) > 16 || len(public) < 2 || len(public) > 16 {
		return nil, nil, errors.New("invalid endpoints")
	}
	seen := make(map[netip.AddrPort]struct{}, len(authoritative)+len(public))
	parse := func(values []string) ([]dnsproviderlive.Endpoint, error) {
		result := make([]dnsproviderlive.Endpoint, 0, len(values))
		for _, value := range values {
			endpoint, err := netip.ParseAddrPort(value)
			if err != nil || endpoint.String() != value || endpoint.Port() == 0 ||
				endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
				return nil, errors.New("invalid endpoint")
			}
			if _, duplicate := seen[endpoint]; duplicate {
				return nil, errors.New("duplicate endpoint")
			}
			seen[endpoint] = struct{}{}
			result = append(result, dnsproviderlive.Endpoint{Address: endpoint})
		}
		return result, nil
	}
	authorityResult, err := parse(authoritative)
	if err != nil {
		return nil, nil, err
	}
	publicResult, err := parse(public)
	return authorityResult, publicResult, err
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(result)) || value != strings.ToLower(value) {
		return result, errors.New("invalid digest")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		clear(decoded)
		return result, errors.New("invalid digest")
	}
	copy(result[:], decoded)
	clear(decoded)
	if result == ([sha256.Size]byte{}) {
		return result, errors.New("invalid digest")
	}
	return result, nil
}

func validInputFile(path string, maximum int64, secret bool) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return false
	}
	return !secret || info.Mode().Perm()&0o077 == 0
}

func validEvidencePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return false
	}
	info, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist) || err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func validDNSName(value string, trailingDot, allowUnderscore bool) bool {
	if value == "" || value != strings.ToLower(value) || value != strings.TrimSpace(value) {
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
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
				character == '-' || allowUnderscore && character == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func newBatchEvidence(batch *preparedBatch) batchEvidence {
	evidence := batchEvidence{
		Schema: evidenceSchema, Status: "running", Reason: "running",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Providers: make([]providerEvidence, len(batch.providers)),
	}
	for index, provider := range batch.providers {
		routing := provider.input.Code == "dnspod_cn"
		evidence.Providers[index] = providerEvidence{
			Code: provider.input.Code, Status: "pending", Reason: "pending",
			Capabilities: capabilityFact{
				RecordTypes: []string{"A", "AAAA", "CNAME", "TXT"},
				Line:        routing, Weight: routing, RetryAfter: true,
			},
		}
	}
	return evidence
}

func (writer evidenceWriter) write(evidence batchEvidence) error {
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	directory := filepath.Dir(writer.path)
	temporary, err := os.CreateTemp(directory, ".dns-provider-sandbox-evidence-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, writer.path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func stableRequestID(runID, provider, step string) string {
	digest := sha256.Sum256([]byte("cdnca:dns-provider-sandbox-e2e/request:v1\x00" + runID + "\x00" + provider + "\x00" + step))
	return "dns-sandbox-" + hex.EncodeToString(digest[:16])
}

func identityDigest(provider, kind, identity string) string {
	digest := sha256.Sum256([]byte("cdnca:dns-provider-sandbox-e2e/resource:v1\x00" + provider + "\x00" + kind + "\x00" + identity))
	return hex.EncodeToString(digest[:])
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
