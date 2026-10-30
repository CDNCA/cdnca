package edgepublishhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/google/uuid"
)

const (
	cursorVersion              = 1
	cursorMACBytes             = sha256.Size
	CursorResourcePublications = "publications"
	CursorResourceRollouts     = "rollouts"
	CursorResourceDeployments  = "deployments"
)

var cursorKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type CursorCodec interface {
	Encode(CursorBinding, string) (string, error)
	Decode(CursorBinding, string) (string, error)
}

type CursorBinding struct {
	Audience     string
	ScopeID      uuid.UUID
	ResourceKind string
	ResourceID   *uuid.UUID
}

type CursorKey struct {
	ID     string
	Secret []byte
}

type HMACCursorCodec struct {
	activeKeyID string
	keys        map[string][]byte
}

type cursorEnvelope struct {
	Version      int    `json:"v"`
	KeyID        string `json:"kid"`
	Audience     string `json:"aud"`
	ScopeID      string `json:"sid"`
	ResourceKind string `json:"res"`
	ResourceID   string `json:"rid,omitempty"`
	Inner        string `json:"cur"`
}

func NewHMACCursorCodec(active CursorKey, verificationKeys ...CursorKey) (*HMACCursorCodec, error) {
	keys := make(map[string][]byte, len(verificationKeys)+1)
	for _, key := range append([]CursorKey{active}, verificationKeys...) {
		if !validCursorKey(key) {
			return nil, ErrInvalidRequest
		}
		if _, exists := keys[key.ID]; exists {
			return nil, ErrInvalidRequest
		}
		keys[key.ID] = bytes.Clone(key.Secret)
	}
	return &HMACCursorCodec{activeKeyID: active.ID, keys: keys}, nil
}

func (c *HMACCursorCodec) Encode(binding CursorBinding, inner string) (string, error) {
	if inner == "" {
		return "", nil
	}
	if c == nil || !validCursorBinding(binding) || !validDomainCursor(inner) {
		return "", ErrInvalidRequest
	}
	secret, exists := c.keys[c.activeKeyID]
	if !exists {
		return "", ErrInvalidRequest
	}
	envelope := cursorEnvelope{
		Version: cursorVersion, KeyID: c.activeKeyID, Audience: binding.Audience,
		ScopeID: binding.ScopeID.String(), ResourceKind: binding.ResourceKind, Inner: inner,
	}
	if binding.ResourceID != nil {
		envelope.ResourceID = binding.ResourceID.String()
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return "", ErrInvalidRequest
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	token := base64.RawURLEncoding.EncodeToString(append(payload, mac.Sum(nil)...))
	if len(token) > maxCursorBytes {
		return "", ErrInvalidRequest
	}
	return token, nil
}

func (c *HMACCursorCodec) Decode(binding CursorBinding, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if c == nil || !validCursorBinding(binding) || len(token) > maxCursorBytes {
		return "", ErrInvalidRequest
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) <= cursorMACBytes {
		return "", ErrInvalidRequest
	}
	payload, signature := decoded[:len(decoded)-cursorMACBytes], decoded[len(decoded)-cursorMACBytes:]
	var envelope cursorEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", ErrInvalidRequest
	}
	secret, exists := c.keys[envelope.KeyID]
	if !exists {
		return "", ErrInvalidRequest
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", ErrInvalidRequest
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, payload) || envelope.Version != cursorVersion ||
		envelope.Audience != binding.Audience || envelope.ScopeID != binding.ScopeID.String() ||
		envelope.ResourceKind != binding.ResourceKind || envelope.ResourceID != bindingResourceID(binding) ||
		!validDomainCursor(envelope.Inner) || envelope.Inner == "" {
		return "", ErrInvalidRequest
	}
	return envelope.Inner, nil
}

func validCursorKey(key CursorKey) bool {
	return cursorKeyIDPattern.MatchString(key.ID) && len(key.Secret) >= 32 && len(key.Secret) <= 128
}

func validCursorBinding(binding CursorBinding) bool {
	if (binding.Audience != AudiencePlatform && binding.Audience != AudienceTenant) || binding.ScopeID == uuid.Nil {
		return false
	}
	switch binding.ResourceKind {
	case CursorResourcePublications, CursorResourceRollouts:
		return binding.ResourceID == nil
	case CursorResourceDeployments:
		return binding.ResourceID != nil && *binding.ResourceID != uuid.Nil
	default:
		return false
	}
}

func bindingResourceID(binding CursorBinding) string {
	if binding.ResourceID == nil {
		return ""
	}
	return binding.ResourceID.String()
}

var _ CursorCodec = (*HMACCursorCodec)(nil)
