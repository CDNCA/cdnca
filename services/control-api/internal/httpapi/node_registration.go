package httpapi

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
)

// Node self-registration: the console shows one reusable install command per
// scope; hosts call POST /v1/node-registrations with it and become pending
// ("待初始化") nodes. See node.Register for the dedupe rule.

const (
	registrationLimitPerSource = 10
	registrationLimitGlobal    = 120
	registrationLimitWindow    = time.Minute
)

// registrationLimiter is a fixed-window limiter per source IP plus a global
// ceiling. It is process-local: each control-api replica enforces its own
// window, which still bounds credential guessing and pending-node churn.
type registrationLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	windowStart time.Time
	global      int
	perSource   map[string]int
}

func newRegistrationLimiter(now func() time.Time) *registrationLimiter {
	if now == nil {
		now = time.Now
	}
	return &registrationLimiter{now: now, perSource: map[string]int{}}
}

func (l *registrationLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.windowStart) >= registrationLimitWindow || now.Before(l.windowStart) {
		l.windowStart, l.global, l.perSource = now, 0, map[string]int{}
	}
	if l.global >= registrationLimitGlobal || l.perSource[source] >= registrationLimitPerSource {
		return false
	}
	l.global++
	l.perSource[source]++
	return true
}

type nodeRegistrationRequest struct {
	Credential         string `json:"credential"`
	MachineFingerprint string `json:"machine_fingerprint"`
	Hostname           string `json:"hostname"`
	OSName             string `json:"os_name"`
	KernelVersion      string `json:"kernel_version"`
	Architecture       string `json:"architecture"`
	// PublicIP: detected by install-node.sh or typed by the operator
	// (optional; older installers do not send it).
	PublicIP string `json:"public_ip,omitempty"`
}

func (s *Server) handleGetNodeRegistrationCredential(w http.ResponseWriter, r *http.Request) {
	s.serveNodeRegistrationCredential(w, r, false)
}

func (s *Server) handleResetNodeRegistrationCredential(w http.ResponseWriter, r *http.Request) {
	s.serveNodeRegistrationCredential(w, r, true)
}

func (s *Server) serveNodeRegistrationCredential(w http.ResponseWriter, r *http.Request, reset bool) {
	principal, ok := s.requireNodePermission(w, r, "nodes.manage")
	if !ok {
		return
	}
	actor := node.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID}
	var (
		credential node.RegistrationCredential
		err        error
	)
	if reset {
		credential, err = s.nodes.ResetRegistrationCredential(r.Context(), actor, requestID(r.Context()))
	} else {
		credential, err = s.nodes.RegistrationCredential(r.Context(), actor, requestID(r.Context()))
	}
	if err != nil {
		s.writeNodeRegistrationError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusOK, credential)
}

func (s *Server) handleRegisterNode(w http.ResponseWriter, r *http.Request) {
	info := s.requestInfo(r)
	if !s.nodeRegistrationLimiter.allow(info.SourceIP) {
		w.Header().Set("Retry-After", "60")
		s.writeAPIError(w, r, http.StatusTooManyRequests, "node_registration_rate_limited", "too many node registration attempts")
		return
	}
	var body nodeRegistrationRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.nodes.Register(r.Context(), node.RegisterRequest{
		Credential: body.Credential, MachineFingerprint: body.MachineFingerprint,
		Hostname: body.Hostname, OSName: body.OSName, KernelVersion: body.KernelVersion,
		Architecture: body.Architecture, SourceIP: info.SourceIP, PublicIP: body.PublicIP, RequestID: info.RequestID,
	})
	if err != nil {
		s.writeNodeRegistrationError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusCreated
	if result.Reused {
		status = http.StatusOK
	}
	writeJSONStatus(w, status, result)
}

type nodeRegistrationIdentityRequest struct {
	Credential         string `json:"credential"`
	MachineFingerprint string `json:"machine_fingerprint"`
	CSRSHA256          string `json:"csr_sha256"`
}

// nodeRegistrationIdentityResponse uses the agent.v1.EnrollResponse JSON
// field names, so the Agent decodes it as the Gateway enrollment response.
type nodeRegistrationIdentityResponse struct {
	NodeID                  string                      `json:"node_id"`
	SelectedProtocolVersion nodeRegistrationProtocol    `json:"selected_protocol_version"`
	Certificate             nodeRegistrationCertificate `json:"certificate"`
	ArtifactEncryptionKeyID string                      `json:"artifact_encryption_key_id"`
}

type nodeRegistrationProtocol struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
}

type nodeRegistrationCertificate struct {
	LeafCertificatePEM []byte   `json:"leaf_certificate_pem"`
	IssuingChainPEM    [][]byte `json:"issuing_chain_pem"`
	SerialNumber       string   `json:"serial_number"`
	NotBeforeTime      string   `json:"not_before_time"`
	ExpirationTime     string   `json:"expiration_time"`
	RenewalTime        string   `json:"renewal_time"`
}

// handleRecoverNodeRegistrationIdentity lets an interrupted install fetch
// the certificate the Gateway enrollment already issued (fz-x13). Same
// credential and rate limit as registration; every miss is 404.
func (s *Server) handleRecoverNodeRegistrationIdentity(w http.ResponseWriter, r *http.Request) {
	info := s.requestInfo(r)
	if !s.nodeRegistrationLimiter.allow(info.SourceIP) {
		w.Header().Set("Retry-After", "60")
		s.writeAPIError(w, r, http.StatusTooManyRequests, "node_registration_rate_limited", "too many node registration attempts")
		return
	}
	var body nodeRegistrationIdentityRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	identity, err := s.nodes.RecoverRegisteredIdentity(r.Context(), node.RecoverIdentityRequest{
		Credential: body.Credential, MachineFingerprint: body.MachineFingerprint, CSRSHA256: body.CSRSHA256,
		SourceIP: info.SourceIP, RequestID: info.RequestID,
	})
	if err != nil {
		s.writeNodeRegistrationError(w, r, err)
		return
	}
	certificate := identity.Certificate
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusOK, nodeRegistrationIdentityResponse{
		NodeID:                  identity.NodeID.String(),
		SelectedProtocolVersion: nodeRegistrationProtocol{Major: identity.SelectedProtocolMajor, Minor: identity.SelectedProtocolMinor},
		ArtifactEncryptionKeyID: identity.ArtifactEncryptionKeyID,
		Certificate: nodeRegistrationCertificate{
			LeafCertificatePEM: certificate.LeafCertificatePEM, IssuingChainPEM: certificate.IssuingChainPEM,
			SerialNumber:   certificate.SerialNumber,
			NotBeforeTime:  certificate.NotBefore.UTC().Format(time.RFC3339Nano),
			ExpirationTime: certificate.NotAfter.UTC().Format(time.RFC3339Nano),
			RenewalTime:    certificate.RenewalAt.UTC().Format(time.RFC3339Nano),
		},
	})
}

func (s *Server) writeNodeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, node.ErrRegistrationUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_registration_unavailable", "node self-registration is not configured")
	case errors.Is(err, node.ErrInvalidRegistrationCredential):
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_registration_credential", "node registration credential is invalid or was reset")
	case errors.Is(err, node.ErrNodeAlreadyRegistered):
		s.writeAPIError(w, r, http.StatusConflict, "node_already_registered", "this machine is already registered")
	case errors.Is(err, node.ErrRegisteredIdentityNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "node_identity_not_found", "no issued identity matches this machine")
	case errors.Is(err, node.ErrRegistrationLimit):
		s.writeAPIError(w, r, http.StatusConflict, "node_registration_limit", "too many pending node registrations")
	default:
		s.writeError(w, r, err)
	}
}
