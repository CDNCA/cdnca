package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateassethttp"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	certificatePublicationCursorActiveKeyIDEnv = "CERTIFICATE_PUBLICATION_CURSOR_ACTIVE_KEY_ID"
	certificatePublicationCursorKeysJSONEnv    = "CERTIFICATE_PUBLICATION_CURSOR_KEYS_JSON"
)

type certificatePublicationStatusRuntimeConfig struct {
	Enabled     bool
	ActiveKeyID string
	Keys        map[string][]byte
}

type certificatePublicationStatusRuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
}

func loadCertificatePublicationStatusRuntimeConfig(
	enabled bool,
) (certificatePublicationStatusRuntimeConfig, error) {
	return loadCertificatePublicationStatusRuntimeConfigFromLookup(enabled, os.LookupEnv)
}

func loadCertificatePublicationStatusRuntimeConfigFromLookup(
	enabled bool,
	lookup func(string) (string, bool),
) (certificatePublicationStatusRuntimeConfig, error) {
	if !enabled {
		return certificatePublicationStatusRuntimeConfig{}, nil
	}
	if lookup == nil {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor environment lookup is required")
	}
	activeKeyID, ok := lookup(certificatePublicationCursorActiveKeyIDEnv)
	if !ok || !validRuntimeKeyID(activeKeyID) || len(activeKeyID) > 64 {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor active key ID is invalid")
	}
	raw, ok := lookup(certificatePublicationCursorKeysJSONEnv)
	if !ok || raw == "" || strings.TrimSpace(raw) != raw || rejectDuplicateJSONKeys(raw) != nil {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor keys are invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	var encoded map[string]string
	if err := decoder.Decode(&encoded); err != nil {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor keys are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || len(encoded) < 1 || len(encoded) > 2 {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor keys are invalid")
	}

	keys := make(map[string][]byte, len(encoded))
	success := false
	defer func() {
		if success {
			return
		}
		for keyID, key := range keys {
			clear(key)
			delete(keys, keyID)
		}
	}()
	for keyID, value := range encoded {
		if !validRuntimeKeyID(keyID) || len(keyID) > 64 {
			return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor keys are invalid")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(key) < 32 || len(key) > 64 || base64.StdEncoding.EncodeToString(key) != value {
			clear(key)
			return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor keys are invalid")
		}
		keys[keyID] = key
	}
	if _, ok := keys[activeKeyID]; !ok {
		return certificatePublicationStatusRuntimeConfig{}, errors.New("certificate publication cursor active key is missing")
	}
	success = true
	return certificatePublicationStatusRuntimeConfig{
		Enabled: true, ActiveKeyID: activeKeyID, Keys: keys,
	}, nil
}

func (config *certificatePublicationStatusRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	for keyID, key := range config.Keys {
		clear(key)
		delete(config.Keys, keyID)
	}
}

func buildAndClearCertificatePublicationStatusHandlerFactory(
	config *certificatePublicationStatusRuntimeConfig,
	dependencies certificatePublicationStatusRuntimeDependencies,
) (httpapi.MountedHandlerFactory, error) {
	if config == nil {
		return nil, errors.New("certificate publication status runtime configuration is required")
	}
	defer config.clearSecrets()
	if !config.Enabled {
		return nil, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() {
		return nil, errors.New("certificate publication status runtime dependencies are not configured")
	}
	reader, err := certificateasset.NewPublicationStatusStore(dependencies.Pool)
	if err != nil {
		return nil, errors.New("initialize certificate publication status store")
	}
	codec, err := certificateasset.NewPublicationCursorCodec(certificateasset.PublicationCursorKeyring{
		ActiveKID: config.ActiveKeyID,
		Keys:      config.Keys,
	})
	if err != nil {
		return nil, errors.New("initialize certificate publication cursor codec")
	}
	handler, err := certificateassethttp.NewPublicationStatusHandler(
		certificateassethttp.PublicationStatusHTTPDependencies{
			Reader: reader, CursorCodec: codec,
			AuthenticateSession: dependencies.Identity.AuthenticateSession,
		},
	)
	if err != nil {
		return nil, errors.New("initialize certificate publication status handler")
	}
	return func() (http.Handler, error) { return handler, nil }, nil
}
