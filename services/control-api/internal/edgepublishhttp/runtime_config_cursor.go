package edgepublishhttp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

const maxCursorKeyringKeys = 8

// NewCursorRuntimeConfig converts a strict, versioned keyring into the runtime
// handoff used by NewRuntimeHandler. The JSON object maps key IDs to canonical
// padded base64 secrets; the selected active key signs and all other keys only
// verify cursors issued before rotation.
func NewCursorRuntimeConfig(enabled bool, activeKeyID, encodedKeyring string) (RuntimeConfig, error) {
	if !enabled {
		if activeKeyID != "" || encodedKeyring != "" {
			return RuntimeConfig{}, ErrInvalidRuntimeConfig
		}
		return RuntimeConfig{}, nil
	}
	if !cursorKeyIDPattern.MatchString(activeKeyID) || encodedKeyring == "" {
		return RuntimeConfig{}, ErrInvalidRuntimeConfig
	}
	keys, err := decodeCursorKeyring(encodedKeyring)
	if err != nil {
		return RuntimeConfig{}, ErrInvalidRuntimeConfig
	}
	return newCursorRuntimeConfigFromKeys(activeKeyID, keys)
}

func newCursorRuntimeConfigFromKeys(activeKeyID string, keys []CursorKey) (RuntimeConfig, error) {
	handoffComplete := false
	defer func() {
		if !handoffComplete {
			clearCursorKeys(keys)
		}
	}()
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	config := RuntimeConfig{Enabled: true}
	for _, key := range keys {
		if key.ID == activeKeyID {
			config.CursorActiveKey = key
			continue
		}
		config.CursorVerificationKeys = append(config.CursorVerificationKeys, key)
	}
	if config.CursorActiveKey.ID == "" {
		return RuntimeConfig{}, ErrInvalidRuntimeConfig
	}
	handoffComplete = true
	return config, nil
}

func decodeCursorKeyring(encodedKeyring string) ([]CursorKey, error) {
	decoder := json.NewDecoder(strings.NewReader(encodedKeyring))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, ErrInvalidRuntimeConfig
	}
	seen := make(map[string]struct{}, maxCursorKeyringKeys)
	keys := make([]CursorKey, 0, maxCursorKeyringKeys)
	complete := false
	defer func() {
		if !complete {
			clearCursorKeys(keys)
		}
	}()
	for decoder.More() {
		keyToken, err := decoder.Token()
		keyID, ok := keyToken.(string)
		if err != nil || !ok || !cursorKeyIDPattern.MatchString(keyID) || len(keys) >= maxCursorKeyringKeys {
			return nil, ErrInvalidRuntimeConfig
		}
		if _, duplicate := seen[keyID]; duplicate {
			return nil, ErrInvalidRuntimeConfig
		}
		seen[keyID] = struct{}{}
		var encodedSecret string
		if err := decoder.Decode(&encodedSecret); err != nil {
			return nil, ErrInvalidRuntimeConfig
		}
		secret, err := base64.StdEncoding.Strict().DecodeString(encodedSecret)
		if err != nil || base64.StdEncoding.EncodeToString(secret) != encodedSecret {
			clear(secret)
			return nil, ErrInvalidRuntimeConfig
		}
		key := CursorKey{ID: keyID, Secret: secret}
		if !validCursorKey(key) {
			clear(secret)
			return nil, ErrInvalidRuntimeConfig
		}
		keys = append(keys, key)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(keys) == 0 {
		return nil, ErrInvalidRuntimeConfig
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidRuntimeConfig
	}
	complete = true
	return keys, nil
}

func clearCursorKeys(keys []CursorKey) {
	for index := range keys {
		clear(keys[index].Secret)
	}
}
