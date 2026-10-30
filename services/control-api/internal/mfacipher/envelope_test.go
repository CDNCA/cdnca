package mfacipher_test

import (
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/mfacipher"
)

// An external test package: mfa reaches identity, which itself uses
// mfacipher for password reset results, so the in-package test cannot import it.
var _ mfa.EnvelopeCipher = (*mfacipher.Cipher)(nil)
