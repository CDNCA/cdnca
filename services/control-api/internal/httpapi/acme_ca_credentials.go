package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// ACME CA External Account Binding credentials:
// GET /v1/admin/acme-ca-credentials lists ZeroSSL and Google Trust
// Services; PUT /v1/admin/acme-ca-credentials/{ca} sets or clears one. The
// HMAC key is write-only.

type acmeCACredentialRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	KeyID            string `json:"eab_key_id"`
	HMACKey          string `json:"eab_hmac_key"`
	Clear            bool   `json:"clear"`
}

type zeroSSLEABEmailRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Email            string `json:"email"`
}

// handleFetchZeroSSLEAB (fix-certops): POST /v1/admin/acme-ca-credentials/zerossl/eab-from-email
// asks ZeroSSL for EAB credentials of an email and stores them like a manual
// save (sealed, audited as acme.ca_credential.update). The HMAC key is never
// returned.
func (s *Server) handleFetchZeroSSLEAB(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "system_configuration.manage")
	if !ok {
		return
	}
	var body zeroSSLEABEmailRequest
	if err := decodeJSON(w, r, &body); err != nil || !acmecacredentials.ValidEABEmail(body.Email) || body.ExpectedRevision < 0 {
		s.writeAPIError(w, r, http.StatusBadRequest, "acme_ca_credential_email_invalid", "a single ZeroSSL account email is required")
		return
	}
	store, err := s.acmeCACredentialStore()
	if err == nil {
		fetcher := s.zeroSSLEABFetcher
		if fetcher == nil {
			fetcher = acmecacredentials.NewZeroSSLEABFetcher()
		}
		var keyID, hmacKey string
		if keyID, hmacKey, err = fetcher.Fetch(r.Context(), body.Email); err == nil {
			var view acmecacredentials.View
			view, err = store.Save(r.Context(), acmeCAActor(principal), acmecacredentials.SaveRequest{
				CA: acmecacredentials.CAZeroSSL, ExpectedRevision: body.ExpectedRevision, KeyID: keyID,
				HMACKey: hmacKey, RequestID: requestID(r.Context()),
			})
			if err == nil {
				writeJSON(w, http.StatusOK, view)
				return
			}
		}
	}
	s.writeACMECACredentialError(w, r, err)
}

func (s *Server) acmeCACredentialStore() (*acmecacredentials.Store, error) {
	if s.pool == nil || s.dnsCredentialCipher == nil {
		return nil, acmecacredentials.ErrUnavailable
	}
	return acmecacredentials.NewStore(s.pool, s.dnsCredentialCipher, audit.New(s.pool), time.Now)
}

func acmeCAActor(principal identity.Principal) acmecacredentials.Actor {
	return acmecacredentials.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func (s *Server) handleListACMECACredentials(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "system_configuration.read")
	if !ok {
		return
	}
	store, err := s.acmeCACredentialStore()
	if err == nil {
		var items []acmecacredentials.View
		if items, err = store.List(r.Context(), acmeCAActor(principal)); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		}
	}
	s.writeACMECACredentialError(w, r, err)
}

func (s *Server) handlePutACMECACredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "system_configuration.manage")
	if !ok {
		return
	}
	var body acmeCACredentialRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	store, err := s.acmeCACredentialStore()
	if err == nil {
		var view acmecacredentials.View
		view, err = store.Save(r.Context(), acmeCAActor(principal), acmecacredentials.SaveRequest{
			CA: r.PathValue("ca"), ExpectedRevision: body.ExpectedRevision, KeyID: body.KeyID,
			HMACKey: body.HMACKey, Clear: body.Clear, RequestID: requestID(r.Context()),
		})
		if err == nil {
			writeJSON(w, http.StatusOK, view)
			return
		}
	}
	s.writeACMECACredentialError(w, r, err)
}

func (s *Server) writeACMECACredentialError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, acmecacredentials.ErrEABFetchFailed):
		s.writeAPIError(w, r, http.StatusBadGateway, "acme_ca_credential_eab_fetch_failed",
			"ZeroSSL did not issue EAB credentials for this email; check the email or paste the credentials manually")
	case errors.Is(err, acmecacredentials.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "acme_ca_credential_invalid",
			"EAB key ID and base64url HMAC key (at least 16 bytes) are required, or clear")
	case errors.Is(err, acmecacredentials.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "permission denied")
	case errors.Is(err, acmecacredentials.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "acme_ca_credential_revision_conflict", "credentials changed; refresh and retry")
	default:
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "acme_ca_credential_unavailable", "ACME CA credentials are unavailable")
	}
}
