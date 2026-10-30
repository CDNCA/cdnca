package main

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/certificatepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	acmePreviousWrappingKeyIDEnv     = "ACME_WRAPPING_PREVIOUS_KEY_ID"
	acmePreviousWrappingKeyBase64Env = "ACME_WRAPPING_PREVIOUS_KEY_BASE64"
)

var errACMEPreviousWrappingKeyConfig = errors.New("ACME previous wrapping key configuration invalid")

func newConfiguredACMEKeyStore(pool *pgxpool.Pool, cfg config.Config) (*acmeruntime.KeyStore, error) {
	active := acmeruntime.WrappingKey{
		ID: cfg.ACMEWrappingKeyID, Key: append([]byte(nil), cfg.ACMEWrappingKey...),
	}
	previous, err := configuredACMEPreviousWrappingKeys()
	if err != nil {
		clear(active.Key)
		return nil, err
	}
	store, err := acmeruntime.NewKeyStoreWithKeyring(pool, active, previous...)
	clear(active.Key)
	for index := range previous {
		clear(previous[index].Key)
	}
	return store, err
}

func newConfiguredACMEPublicationResolverKeyring(
	cfg config.Config,
) (certificateasset.OpaquePublicationResolver, error) {
	publicationActive := certificatepublish.ACMEPublicationWrappingKey{
		ID: cfg.ACMEWrappingKeyID, Material: append([]byte(nil), cfg.ACMEWrappingKey...),
	}
	previous, err := configuredACMEPreviousWrappingKeys()
	if err != nil {
		clear(publicationActive.Material)
		return nil, err
	}
	publicationPrevious := make([]certificatepublish.ACMEPublicationWrappingKey, len(previous))
	for index := range previous {
		publicationPrevious[index] = certificatepublish.ACMEPublicationWrappingKey{
			ID: previous[index].ID, Material: append([]byte(nil), previous[index].Key...),
		}
		clear(previous[index].Key)
	}
	resolver, err := certificatepublish.NewACMEPublicationResolverKeyring(
		publicationActive, publicationPrevious...,
	)
	clear(publicationActive.Material)
	for index := range publicationPrevious {
		clear(publicationPrevious[index].Material)
	}
	return resolver, err
}

func configuredACMEPreviousWrappingKeys() ([]acmeruntime.WrappingKey, error) {
	keyID := os.Getenv(acmePreviousWrappingKeyIDEnv)
	encoded := os.Getenv(acmePreviousWrappingKeyBase64Env)
	if keyID == "" && encoded == "" {
		return nil, nil
	}
	if keyID == "" || encoded == "" {
		return nil, errACMEPreviousWrappingKeyConfig
	}
	material, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(material) != 32 || base64.StdEncoding.EncodeToString(material) != encoded {
		clear(material)
		return nil, errACMEPreviousWrappingKeyConfig
	}
	return []acmeruntime.WrappingKey{{ID: keyID, Key: material}}, nil
}
