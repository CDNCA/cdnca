package httpapi

import (
	"context"
	"net/http"
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
	// Ready: every required verification can be sent (false: sign-up is on
	// but cannot complete until the operator configures the sender).
	Ready    bool           `json:"ready"`
	Recovery RecoveryConfig `json:"recovery"`
}

// RegistrationConfigSource computes the projection per request.
type RegistrationConfigSource interface {
	RegistrationConfig(context.Context) (RegistrationConfig, error)
}

func (s *Server) handleRegistrationConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": config})
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
	s.builtInRegistrationChallenges.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), builtInRegistrationSourceKey{}, source)))
}
