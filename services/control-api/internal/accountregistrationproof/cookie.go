package accountregistrationproof

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
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
// verified channel gets its own cookie; the single legacy cookie is still
// read as a one-channel proof. the cookie is
// also per challenge (CookieName + "_" + channel + "_" + challenge id), so
// two sign-up tabs of one browser keep their own proofs, and registration
// names the challenge of each channel. The per-channel name without a
// challenge (issued before) is still read.

// ChannelCookieName is the proof cookie of one verified challenge.
func ChannelCookieName(channel string, challengeID uuid.UUID) string {
	return CookieName + "_" + channel + "_" + challengeID.String()
}

// NewChannelReferenceCookie is NewReferenceCookie for one verified challenge.
func NewChannelReferenceCookie(channel string, challengeID uuid.UUID, reference string, expiresAt time.Time) (*http.Cookie, error) {
	if channel != "email" && channel != "sms" || challengeID == uuid.Nil {
		return nil, ErrInvalidReference
	}
	cookie, err := NewReferenceCookie(reference, expiresAt)
	if err != nil {
		return nil, err
	}
	cookie.Name = ChannelCookieName(channel, challengeID)
	return cookie, nil
}

// channelCookie parses a per-channel proof cookie name: its channel and
// challenge id ("" for the name without one).
func channelCookie(name string) (channel, challenge string, ok bool) {
	rest, found := strings.CutPrefix(name, CookieName+"_")
	if !found {
		return "", "", false
	}
	channel, challenge, _ = strings.Cut(rest, "_")
	if channel != "email" && channel != "sms" {
		return "", "", false
	}
	if challenge != "" {
		id, err := uuid.Parse(challenge)
		if err != nil || id == uuid.Nil || id.String() != challenge {
			return "", "", false
		}
	}
	return channel, challenge, true
}

// ResolveProofReferences returns the legacy reference ("" when absent) and
// the per-channel references. A channel named in challenges takes the cookie
// of that challenge only; a channel not named takes its one cookie, none
// when the browser holds several (another tab's). A duplicated or malformed
// cookie fails; no cookie at all fails too.
func (CookieReferenceResolver) ResolveProofReferences(request *http.Request, challenges map[string]uuid.UUID) (string, map[string]string, error) {
	if request == nil {
		return "", nil, ErrInvalidReference
	}
	seen := map[string]bool{}
	legacy, named, unnamed := "", map[string]string{}, map[string][]string{}
	for _, cookie := range request.Cookies() {
		channel, challenge, known := channelCookie(cookie.Name)
		if !known && cookie.Name != CookieName {
			continue
		}
		if seen[cookie.Name] || !validReference(cookie.Value) {
			return "", nil, ErrInvalidReference
		}
		seen[cookie.Name] = true
		switch want, ok := challenges[channel]; {
		case !known:
			legacy = cookie.Value
		case ok:
			if challenge == want.String() {
				named[channel] = cookie.Value
			}
		default:
			unnamed[channel] = append(unnamed[channel], cookie.Value)
		}
	}
	channels := named
	for channel, references := range unnamed {
		if len(references) == 1 {
			channels[channel] = references[0]
		}
	}
	if legacy == "" && len(channels) == 0 {
		return "", nil, ErrInvalidReference
	}
	return legacy, channels, nil
}

// ValidChallengeIDs: the verification_challenge_ids of a registration name
// only email / sms, each a challenge id.
func ValidChallengeIDs(challenges map[string]uuid.UUID) bool {
	for channel, id := range challenges {
		if channel != "email" && channel != "sms" || id == uuid.Nil {
			return false
		}
	}
	return true
}
