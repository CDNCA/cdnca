package mfahttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
)

var (
	ErrInvalidService        = errors.New("invalid MFA HTTP service")
	ErrInvalidRequest        = errors.New("invalid MFA HTTP request")
	ErrUnauthenticated       = errors.New("MFA authentication required")
	ErrResponseTooLarge      = errors.New("MFA HTTP response too large")
	ErrInvalidServiceResult  = errors.New("MFA service returned invalid result")
	ErrRuntimeAlreadyRunning = errors.New("MFA HTTP runtime already running")
	ErrRuntimeClosed         = errors.New("MFA HTTP runtime closed")
	ErrRuntimeNotReady       = errors.New("MFA HTTP runtime not ready")
)

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type mfaService interface {
	Status(context.Context, mfa.Actor) (mfa.StatusResult, error)
	BeginEnrollment(context.Context, mfa.Actor, mfa.EnrollmentRequest) (mfa.EnrollmentResult, error)
	Activate(context.Context, mfa.Actor, mfa.ActivationRequest) (mfa.ActivationResult, error)
	CreateStepUp(context.Context, mfa.Actor, mfa.StepUpRequest) (mfa.StepUpResult, error)
	Disable(context.Context, mfa.Actor, mfa.DeactivateRequest) error
	Reset(context.Context, mfa.Actor, mfa.DeactivateRequest) error
}

type authenticationBody struct {
	Method string `json:"method"`
	Code   string `json:"code"`
}

type enrollmentBody struct {
	AccountLabel string `json:"account_label"`
}

type activationBody struct {
	Code string `json:"code"`
}

type stepUpBody struct {
	TenantID       string             `json:"tenant_id"`
	Audience       string             `json:"audience"`
	Action         string             `json:"action"`
	Authentication authenticationBody `json:"authentication"`
	TTLSeconds     int                `json:"ttl_seconds"`
	MaxUses        int                `json:"max_uses"`
}

type deactivateBody struct {
	Authentication authenticationBody `json:"authentication"`
	Reason         string             `json:"reason"`
}

type statusView struct {
	Status              string     `json:"status"`
	CredentialID        *uuid.UUID `json:"credential_id,omitempty"`
	Method              string     `json:"method,omitempty"`
	EnrollmentExpiresAt *time.Time `json:"enrollment_expires_at,omitempty"`
}

type enrollmentView struct {
	CredentialID    uuid.UUID `json:"credential_id"`
	Secret          *string   `json:"secret,omitempty"`
	ProvisioningURI *string   `json:"provisioning_uri,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	Replayed        bool      `json:"replayed"`
}

type activationView struct {
	CredentialID  uuid.UUID `json:"credential_id"`
	RecoveryCodes []string  `json:"recovery_codes,omitempty"`
	ActivatedAt   time.Time `json:"activated_at"`
	Replayed      bool      `json:"replayed"`
}

type stepUpView struct {
	ProofID   uuid.UUID `json:"proof_id"`
	Token     *string   `json:"token,omitempty"`
	Method    string    `json:"method"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	Replayed  bool      `json:"replayed"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}
