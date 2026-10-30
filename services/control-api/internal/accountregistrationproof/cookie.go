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
