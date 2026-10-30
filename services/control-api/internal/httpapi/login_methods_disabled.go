package httpapi

import "net/http"

// handleLoginMethodsDisabled answers GET /v1/auth/login-methods when the
// account login runtime is not mounted: same shape as
// accountloginchallengehttp, every method off, so only password sign-in shows.
func handleLoginMethodsDisabled(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"registration_enabled": false,
		"email_enabled":        false, "sms_enabled": false,
		"email_anti_abuse_mode": "", "sms_anti_abuse_mode": "",
		"captcha_provider": "", "captcha_app_id": "",
	}})
}
