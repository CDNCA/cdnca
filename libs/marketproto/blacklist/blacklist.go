// Package blacklist is the market-signed platform blacklist feed. Leaf
// controllers pull it and remove matching sites themselves, so a takedown does
// not depend on relaying a command per site (docs/marketplace/06-compliance.md §4).
package blacklist

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const Domain = "cdnca.market.blacklist/v1\n"

var (
	ErrUnknownKey = errors.New("blacklist feed signing key unknown")
	ErrSignature  = errors.New("blacklist feed signature rejected")
	ErrInvalid    = errors.New("invalid blacklist feed")
)

type Entry struct {
	Kind  string `json:"kind"` // domain | root_domain | keyword
	Value string `json:"value"`
}

type Feed struct {
	Entries  []Entry `json:"entries"`
	IssuedAt int64   `json:"issued_at"`
}

// Matches reports whether a normalised hostname with registrable root is
// blacklisted by this feed.
func (f Feed) Matches(host, root string) bool {
	for _, e := range f.Entries {
		switch e.Kind {
		case "domain":
			if host == e.Value {
				return true
			}
		case "root_domain":
			if root == e.Value || host == e.Value || strings.HasSuffix(host, "."+e.Value) {
				return true
			}
		case "keyword":
			if e.Value != "" && strings.Contains(host, e.Value) {
				return true
			}
		}
	}
	return false
}

type Signed struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(f Feed, keyID string, key ed25519.PrivateKey) (Signed, error) {
	payload, err := json.Marshal(f)
	if err != nil {
		return Signed{}, err
	}
	return Signed{KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), payload...)))}, nil
}

func Verify(keys map[string]ed25519.PublicKey, s Signed) (Feed, error) {
	public, ok := keys[s.KeyID]
	if !ok || len(public) != ed25519.PublicKeySize {
		return Feed{}, ErrUnknownKey
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil {
		return Feed{}, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(Domain), payload...), signature) {
		return Feed{}, ErrSignature
	}
	var f Feed
	if err := json.Unmarshal(payload, &f); err != nil || f.IssuedAt <= 0 {
		return Feed{}, ErrInvalid
	}
	return f, nil
}
