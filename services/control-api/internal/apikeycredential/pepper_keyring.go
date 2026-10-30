package apikeycredential

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"regexp"
)

const LegacyPepperVersion = "legacy-v1"

var pepperVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type PepperKeyringConfig struct {
	ActiveVersion   string
	Active          []byte
	PreviousVersion string
	Previous        []byte
}

type pepperKey struct {
	version string
	secret  []byte
}

type PepperKeyring struct {
	active   pepperKey
	previous pepperKey
}

func NewPepperKeyring(config PepperKeyringConfig) (PepperKeyring, error) {
	if !pepperVersionPattern.MatchString(config.ActiveVersion) || len(config.Active) < sha256.Size {
		return PepperKeyring{}, ErrInvalidConfig
	}
	hasPreviousVersion := config.PreviousVersion != ""
	hasPreviousSecret := len(config.Previous) != 0
	if hasPreviousVersion != hasPreviousSecret || hasPreviousVersion &&
		(!pepperVersionPattern.MatchString(config.PreviousVersion) || len(config.Previous) < sha256.Size ||
			config.PreviousVersion == config.ActiveVersion || hmac.Equal(config.Previous, config.Active)) {
		return PepperKeyring{}, ErrInvalidConfig
	}
	return PepperKeyring{
		active:   pepperKey{version: config.ActiveVersion, secret: append([]byte(nil), config.Active...)},
		previous: pepperKey{version: config.PreviousVersion, secret: append([]byte(nil), config.Previous...)},
	}, nil
}

func (keyring PepperKeyring) Configured() bool {
	return pepperVersionPattern.MatchString(keyring.active.version) && len(keyring.active.secret) >= sha256.Size
}

func (keyring PepperKeyring) ActiveVersion() string {
	if !keyring.Configured() {
		return ""
	}
	return keyring.active.version
}

func (keyring PepperKeyring) SignActive(domain string, parts ...[]byte) (string, [32]byte, bool) {
	if !keyring.Configured() {
		return "", [32]byte{}, false
	}
	return keyring.active.version, signPepper(keyring.active.secret, domain, parts...), true
}

func (keyring PepperKeyring) Sign(version, domain string, parts ...[]byte) ([32]byte, bool) {
	key, ok := keyring.key(version)
	if !ok {
		return [32]byte{}, false
	}
	return signPepper(key.secret, domain, parts...), true
}

func (keyring PepperKeyring) VerifyAny(signature []byte, domain string, parts ...[]byte) bool {
	if !keyring.Configured() || len(signature) != sha256.Size {
		return false
	}
	active := signPepper(keyring.active.secret, domain, parts...)
	matched := hmac.Equal(signature, active[:])
	if len(keyring.previous.secret) != 0 {
		previous := signPepper(keyring.previous.secret, domain, parts...)
		matched = hmac.Equal(signature, previous[:]) || matched
	}
	return matched
}

func (keyring PepperKeyring) key(version string) (pepperKey, bool) {
	if !keyring.Configured() {
		return pepperKey{}, false
	}
	if version == keyring.active.version {
		return keyring.active, true
	}
	if version != "" && version == keyring.previous.version && len(keyring.previous.secret) >= sha256.Size {
		return keyring.previous, true
	}
	return pepperKey{}, false
}

func signPepper(secret []byte, domain string, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(domain))
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (PepperKeyring) String() string   { return "PepperKeyring{secret:[REDACTED]}" }
func (PepperKeyring) GoString() string { return "apikeycredential.PepperKeyring{secret:[REDACTED]}" }

var _ fmt.Stringer = PepperKeyring{}
