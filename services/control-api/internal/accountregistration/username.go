package accountregistration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// while the platform does not require a username, a sign-up
// may leave it empty and the controller names the account. The name is
// derived from the normalized email (its local part) or phone and keyed by
// the registration digest key, so every step that binds the username (the
// challenge subject, the proofs, the request digest, the stored user and an
// idempotent retry) computes the same one without storing it:
// "<base>-<8 hex of HMAC(key, email NUL phone)>". The suffix keeps it apart
// from names chosen by hand and from other accounts with the same base; the
// account signs in with it, its email or its phone.

const usernameBaseMax = 32

// DerivedUsername is the generated username for a normalized email (lower
// case) and phone (E.164); email wins as the base when both are given.
func DerivedUsername(key []byte, email, phone string) string {
	base := ""
	if local, _, ok := strings.Cut(email, "@"); ok && email != "" {
		base = usernameBase(local)
	} else if phone != "" {
		base = usernameBase("u" + strings.TrimPrefix(phone, "+"))
	}
	if base == "" {
		base = "user"
	}
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte("cdnca-registration-username\x00" + email + "\x00" + phone))
	return base + "-" + hex.EncodeToString(digest.Sum(nil))[:8]
}

// usernameBase keeps the characters a username allows (a-z 0-9 . _ -),
// starting with a letter or digit, at most usernameBaseMax long.
func usernameBase(value string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(value) {
		if builder.Len() >= usernameBaseMax {
			break
		}
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
			(char == '.' || char == '_' || char == '-') && builder.Len() > 0 {
			builder.WriteRune(char)
		}
	}
	return strings.TrimRight(builder.String(), "._-")
}

// ResolveUsername returns the username a registration step binds: the one
// given, or, when it is empty and the platform does not require one, the
// derived one (DerivedUsername of the normalized contacts; a contact that
// does not normalize leaves it empty, refused later as invalid input).
// generated reports the latter.
func ResolveUsername(key []byte, policy systemusersettings.PublicSettings, username, email, phone, phoneCode string) (string, bool) {
	if strings.TrimSpace(username) != "" || policy.UsernameRequired {
		return username, false
	}
	email = strings.ToLower(strings.TrimSpace(email))
	phone = strings.TrimSpace(phone)
	if phone != "" {
		normalized, err := phonenumber.Normalize(phone, phoneCode)
		if err != nil {
			return username, false
		}
		phone = normalized
	}
	if email == "" && phone == "" {
		return username, false
	}
	return DerivedUsername(key, email, phone), true
}

// fillUsername sets a registration's username (ResolveUsername) and, for a
// generated one, the display name when none was given.
func fillUsername(input *RegisterInput, key []byte, policy systemusersettings.PublicSettings, phoneCode string) bool {
	username, generated := ResolveUsername(key, policy, input.Username, input.Email, input.Phone, phoneCode)
	if generated {
		input.Username = username
		if strings.TrimSpace(input.DisplayName) == "" {
			input.DisplayName = username
		}
	}
	return generated
}
