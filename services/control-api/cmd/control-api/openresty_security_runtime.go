package main

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
)

const openRestySecuritySecretKeyEnvironment = "OPENRESTY_SECURITY_SECRET_KEY_BASE64"

func loadOpenRestySecuritySecretCipher() (*openrestysecurity.SecretCipher, error) {
	encoded := os.Getenv(openRestySecuritySecretKeyEnvironment)
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		clear(key)
		return nil, errors.New(openRestySecuritySecretKeyEnvironment + " must be canonical base64 encoding of exactly 32 bytes")
	}
	defer clear(key)
	return openrestysecurity.NewSecretCipher(key)
}
