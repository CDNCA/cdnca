package accountregistrationproof

import (
	"errors"
	"net/http"
	"time"
)

const CookieName = "__Host-cdnca_registration_proof"

var ErrInvalidReference = errors.New("invalid account registration proof reference")

type CookieReferenceResolver struct{}

func (CookieReferenceResolver) ResolveProofReference(request *http.Request) (string, error) {
	if request == nil {
		return "", ErrInvalidReference
	}
	var reference string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == CookieName {
			count++
			reference = cookie.Value
		}
	}
	if count != 1 || !validReference(reference) {
		return "", ErrInvalidReference
	}
	return reference, nil
}

func NewReferenceCookie(reference string, expiresAt time.Time) (*http.Cookie, error) {
	if !validReference(reference) || expiresAt.IsZero() {
		return nil, ErrInvalidReference
	}
	return &http.Cookie{
		Name: CookieName, Value: reference, Path: "/", Expires: canonicalTime(expiresAt),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}, nil
}

func ClearReferenceCookie() *http.Cookie {
	return &http.Cookie{
		Name: CookieName, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	}
}

// several verifications can be required at once, so each
// verified channel gets its own cookie (CookieName + "_" + channel); the
// single legacy cookie is still read as a one-channel proof.

// ChannelCookieName is the proof cookie of one channel (email / sms).
func ChannelCookieName(channel string) string { return CookieName + "_" + channel }

// NewChannelReferenceCookie is NewReferenceCookie for one channel.
func NewChannelReferenceCookie(channel, reference string, expiresAt time.Time) (*http.Cookie, error) {
	if channel != "email" && channel != "sms" {
		return nil, ErrInvalidReference
	}
	cookie, err := NewReferenceCookie(reference, expiresAt)
	if err != nil {
		return nil, err
	}
	cookie.Name = ChannelCookieName(channel)
	return cookie, nil
}

// ResolveProofReferences returns the legacy reference ("" when absent) and
// the per-channel references. A duplicated or malformed cookie fails; no
// cookie at all fails too.
func (CookieReferenceResolver) ResolveProofReferences(request *http.Request) (string, map[string]string, error) {
	if request == nil {
		return "", nil, ErrInvalidReference
	}
	names := map[string]string{CookieName: "", ChannelCookieName("email"): "email", ChannelCookieName("sms"): "sms"}
	seen := map[string]int{}
	legacy, channels := "", map[string]string{}
	for _, cookie := range request.Cookies() {
		channel, known := names[cookie.Name]
		if !known {
			continue
		}
		if seen[cookie.Name]++; seen[cookie.Name] > 1 || !validReference(cookie.Value) {
			return "", nil, ErrInvalidReference
		}
		if channel == "" {
			legacy = cookie.Value
		} else {
			channels[channel] = cookie.Value
		}
	}
	if legacy == "" && len(channels) == 0 {
		return "", nil, ErrInvalidReference
	}
	return legacy, channels, nil
}
