package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

const maintenanceCandidateTimeout = 5 * time.Second
const maintenanceCandidateResponseLimit = 64 << 10

var errMaintenanceCandidateUnavailable = errors.New("maintenance upgrade candidate is unavailable")

type maintenanceUpgradeClient struct {
	mu             sync.RWMutex
	baseURL        string
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	trust          *entitlementguard.TrustStore
	http           *http.Client
	now            func() time.Time
}

func openMaintenanceUpgradeClient(cfg config.Config, trust *entitlementguard.TrustStore) (*maintenanceUpgradeClient, error) {
	if cfg.LicenseServiceURL == "" {
		return nil, nil
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errMaintenanceCandidateUnavailable
	}
	key, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, errMaintenanceCandidateUnavailable
	}
	defer clear(key)
	return newMaintenanceUpgradeClient(cfg.LicenseServiceURL, installationID, key, trust, nil, time.Now)
}

func newMaintenanceUpgradeClient(baseURL string, installationID uuid.UUID, privateKey ed25519.PrivateKey,
	trust *entitlementguard.TrustStore, transport http.RoundTripper, now func() time.Time) (*maintenanceUpgradeClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		installationID == uuid.Nil || len(privateKey) != ed25519.PrivateKeySize || trust == nil || now == nil {
		return nil, errMaintenanceCandidateUnavailable
	}
	return &maintenanceUpgradeClient{baseURL: baseURL, installationID: installationID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), trust: trust, now: now,
		http: &http.Client{Transport: transport, Timeout: maintenanceCandidateTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (client *maintenanceUpgradeClient) Close() {
	if client == nil {
		return
	}
	client.mu.Lock()
	clear(client.privateKey)
	client.privateKey = nil
	client.mu.Unlock()
	client.http.CloseIdleConnections()
}

func (client *maintenanceUpgradeClient) ReadCandidate(ctx context.Context, component, currentVersion string, protocol int) (controlupgrade.MaintenanceCandidate, error) {
	if client == nil || ctx == nil {
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	body, err := entitlement.CanonicalUpgradeCandidateRequest(entitlement.UpgradeCandidateRequest{
		Schema: entitlement.UpgradeCandidateRequestSchema, Component: component, CurrentVersion: currentVersion, ProtocolVersion: protocol,
	})
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, err
	}
	requestID, requestedAt := uuid.NewString(), client.now().UTC().Unix()
	proofMessage, err := entitlement.UpgradeCandidateRequestProofMessage(client.installationID.String(), requestID, requestedAt, body)
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, err
	}
	client.mu.RLock()
	if len(client.privateKey) != ed25519.PrivateKeySize {
		client.mu.RUnlock()
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	proof := ed25519.Sign(client.privateKey, proofMessage)
	client.mu.RUnlock()
	ctx, cancel := context.WithTimeout(ctx, maintenanceCandidateTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+
		"/activation/v1/installations/"+client.installationID.String()+"/upgrade-candidates:resolve", bytes.NewReader(body))
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CDNCA-Installation-ID", client.installationID.String())
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("X-CDNCA-Requested-At", strconv.FormatInt(requestedAt, 10))
	request.Header.Set("X-CDNCA-Proof", base64.RawURLEncoding.EncodeToString(proof))
	response, err := client.http.Do(request)
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	defer response.Body.Close()
	contentType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || typeErr != nil || contentType != "application/json" ||
		response.ContentLength > maintenanceCandidateResponseLimit {
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maintenanceCandidateResponseLimit+1))
	if err != nil || len(encoded) > maintenanceCandidateResponseLimit {
		return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
	}
	signed, err := entitlement.DecodeUpgradeCandidate(encoded)
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, err
	}
	message, err := entitlement.UpgradeCandidateSigningMessage(signed)
	if err != nil {
		return controlupgrade.MaintenanceCandidate{}, err
	}
	type signatureEvidence struct {
		keyID, signature string
		message          []byte
		signedAt         int64
	}
	signatures := []signatureEvidence{{signed.KeyID, signed.Signature, message, signed.Snapshot.IssuedAt}}
	if artifact := signed.Snapshot.Candidate; artifact != nil {
		message, err = entitlement.UpgradeCandidateArtifactSigningMessage(*artifact)
		if err != nil {
			return controlupgrade.MaintenanceCandidate{}, err
		}
		signatures = append(signatures, signatureEvidence{artifact.SignatureKeyID, artifact.ManifestSignature, message, artifact.AttestedAt})
	}
	now := client.now().UTC()
	ring := entitlement.NewKeyRing()
	for _, signature := range signatures {
		decoded, err := base64.RawURLEncoding.DecodeString(signature.signature)
		if err != nil {
			return controlupgrade.MaintenanceCandidate{}, err
		}
		if err := client.trust.VerifyDetached(signature.keyID, signature.message, decoded, time.Unix(signature.signedAt, 0), now); err != nil {
			return controlupgrade.MaintenanceCandidate{}, err
		}
		key, found := client.trust.PublicKey(signature.keyID)
		if !found || ring.Add(signature.keyID, key) != nil {
			return controlupgrade.MaintenanceCandidate{}, errMaintenanceCandidateUnavailable
		}
	}
	if err := ring.VerifyUpgradeCandidate(signed, entitlement.UpgradeCandidateVerifyOptions{
		Now: now, ExpectedInstallationID: client.installationID.String(), ExpectedRequestID: requestID,
		ExpectedRequestSHA256: base64.RawURLEncoding.EncodeToString(proofMessage),
		ExpectedComponent:     component, ExpectedCurrentVersion: currentVersion, ExpectedProtocolVersion: protocol,
	}); err != nil {
		return controlupgrade.MaintenanceCandidate{}, err
	}
	// Envelope and embedded release manifest are both release-class artifacts;
	// each signer is checked independently against the verified revocation LKG.
	for _, signature := range signatures {
		if err := client.trust.CheckSignerRevocation(entitlementguard.SignerArtifactRelease, signature.keyID); err != nil {
			return controlupgrade.MaintenanceCandidate{}, err
		}
	}
	expiresAt := time.Unix(signed.Snapshot.ExpiresAt, 0).UTC()
	candidate := controlupgrade.MaintenanceCandidate{State: signed.Snapshot.Status, Reason: signed.Snapshot.Reason, ExpiresAt: &expiresAt}
	if signed.Snapshot.Candidate != nil {
		version := signed.Snapshot.Candidate.Manifest.Version
		candidate.Version = &version
		candidate.Channel = signed.Snapshot.Authority.Version.Channel
	}
	return candidate, nil
}
