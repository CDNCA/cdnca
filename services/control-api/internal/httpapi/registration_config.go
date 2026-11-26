package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
)

// GET /v1/auth/registration-config tells every sign-up
// and password-reset page (console and website themes) what to show: which
// verifications the platform requires, whether each can actually be sent,
// and the human check that guards sending a code. A new endpoint, so the
// login-methods shape older front ends read is unchanged.

// RegistrationChannel is one verification channel of the sign-up form.
type RegistrationChannel struct {
	// Required: the platform asks for this verified contact.
	Required bool `json:"required"`
	// Available: a code can be sent now (sender configured and switched on).
	Available bool `json:"available"`
}

// RecoveryConfig is what the password-reset page offers.
type RecoveryConfig struct {
	Enabled bool `json:"enabled"`
	// Channels the reset link can be sent by ("email", "sms"), configured
	// and switched on.
	Channels []string `json:"channels"`
}

// RegistrationConfig is the public projection.
type RegistrationConfig struct {
	RegistrationEnabled bool `json:"registration_enabled"`
	// Mode: "builtin" (no Turnstile runtime), "verified" (Turnstile) or "closed".
	Mode string `json:"mode"`
	// HumanCheck guards sending a code: "builtin_captcha" or "turnstile".
	HumanCheck       string              `json:"human_check"`
	TurnstileSiteKey string              `json:"turnstile_site_key"`
	TermsVersion     string              `json:"terms_version"`
	Email            RegistrationChannel `json:"email"`
	SMS              RegistrationChannel `json:"sms"`
	EmailRequired    bool                `json:"email_required"`
	PhoneRequired    bool                `json:"phone_required"`
	// QQRequired: sign-up must give a QQ number.
	QQRequired bool `json:"qq_required"`
	// UsernameRequired: sign-up must give a username; false, it may be left
	// empty and the controller generates one.
	UsernameRequired bool `json:"username_required"`
	// Ready: every required verification can be sent (false: sign-up is on
	// but cannot complete until the operator configures the sender).
	Ready    bool           `json:"ready"`
	Recovery RecoveryConfig `json:"recovery"`
	// Reasons say what keeps sign-up verification from
	// being ready. Only a platform administrator's session (system
	// configuration read) receives them; visitors never see the field.
	Reasons []string `json:"reasons,omitempty"`

	// TermsPublished: the system settings page has terms of its own
	//; false, the sites link their own terms page and
	// GET /v1/auth/registration-terms answers 404. Sign-up stays open either way.
	TermsPublished bool `json:"terms_published"`
	// TermsRequired: sign-up must accept terms: some readable
	// terms exist (published ones, the site's own terms page or an agree link
	// it set), or the Turnstile flow is mounted. False: the pages show no
	// agreement line and POST /v1/auth/register neither checks nor records one.
	TermsRequired bool `json:"terms_required"`
}

// RegistrationConfigSource computes the projection per request.
type RegistrationConfigSource interface {
	RegistrationConfig(context.Context) (RegistrationConfig, error)
}

// RegistrationTerms is GET /v1/auth/registration-terms: the
// sign-up terms edited on the system settings page, as plain text, and the
// version registration-config reports (the one a sign-up must accept).
type RegistrationTerms struct {
	Title   string `json:"title"`
	Body    string `json:"body"`
	Version string `json:"version"`
}

// ErrRegistrationTermsNotConfigured: the settings page has no published
// terms; GET /v1/auth/registration-terms answers 404.
var ErrRegistrationTermsNotConfigured = errors.New("registration terms not configured")

// RegistrationTermsSource is implemented by a source that can show the terms.
type RegistrationTermsSource interface {
	RegistrationTerms(context.Context) (RegistrationTerms, error)
}

// RegistrationDiagnostics is implemented by a source that can explain a
// sign-up that is not ready (reason codes for administrators).
type RegistrationDiagnostics interface {
	RegistrationReasons(context.Context) ([]string, error)
}

// LoginMethodsRegistration projects Source onto GET /v1/auth/login-methods
// registration_enabled / registration_mode ("builtin" or empty), so both
// public endpoints answer 开放注册 alike whether or not the account login
// runtime is mounted. It is accountloginchallenge.RegistrationSource.
type LoginMethodsRegistration struct{ Source RegistrationConfigSource }

func (projection LoginMethodsRegistration) Registration(ctx context.Context) (bool, string, error) {
	if projection.Source == nil {
		return false, "", nil
	}
	config, err := projection.Source.RegistrationConfig(ctx)
	if err != nil || !config.RegistrationEnabled {
		return false, "", err
	}
	if config.Mode == "builtin" {
		return true, "builtin", nil
	}
	return true, "", nil
}

func (s *Server) handleRegistrationConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization")
	config := RegistrationConfig{Mode: "closed", HumanCheck: "builtin_captcha", Recovery: RecoveryConfig{Channels: []string{}}}
	if s.registrationConfig != nil {
		value, err := s.registrationConfig.RegistrationConfig(r.Context())
		if err != nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_unavailable", "registration settings are unavailable")
			return
		}
		config = value
		if config.Recovery.Channels == nil {
			config.Recovery.Channels = []string{}
		}
		config.Reasons = nil
		if diagnostics, ok := s.registrationConfig.(RegistrationDiagnostics); ok && s.registrationConfigAdministrator(r) {
			// a failed diagnosis only leaves the reasons out
			if reasons, err := diagnostics.RegistrationReasons(r.Context()); err == nil {
				config.Reasons = reasons
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": config})
}

func (s *Server) handleRegistrationTerms(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	source, ok := s.registrationConfig.(RegistrationTermsSource)
	if !ok {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_unavailable", "registration terms are unavailable")
		return
	}
	terms, err := source.RegistrationTerms(r.Context())
	if errors.Is(err, ErrRegistrationTermsNotConfigured) {
		s.writeAPIError(w, r, http.StatusNotFound, "registration_terms_not_configured", "no registration terms are published")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_unavailable", "registration terms are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": terms})
}

// registrationConfigAdministrator: the request carries a valid platform
// session allowed to read the system configuration. Anything else (no or a
// bad token, a tenant user) is a visitor; the endpoint never answers 401.
func (s *Server) registrationConfigAdministrator(r *http.Request) bool {
	if s.identity == nil || strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		return false
	}
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil || principal.ScopeKind != "platform" || principal.TenantID != nil {
		return false
	}
	return slices.Contains(principal.Permissions, "system_configuration.read") || slices.Contains(principal.Permissions, "platform.admin")
}

type builtInRegistrationSourceKey struct{}

// BuiltInRegistrationSource is the request source the built-in challenge
// handler binds a code to (set by handleBuiltInRegistrationChallenge).
func BuiltInRegistrationSource(ctx context.Context) string {
	source, _ := ctx.Value(builtInRegistrationSourceKey{}).(string)
	return source
}

func (s *Server) handleBuiltInRegistrationChallenge(w http.ResponseWriter, r *http.Request) {
	source := s.requestInfo(r).SourceIP
	if source == "" {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_challenge_unavailable", "registration is unavailable")
		return
	}
	ctx := withLoginCaptchaBinding(r)
	s.builtInRegistrationChallenges.ServeHTTP(w, r.WithContext(context.WithValue(ctx, builtInRegistrationSourceKey{}, source)))
}
