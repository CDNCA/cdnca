//go:build !darwin || !cgo

package dnsproviderlive

func ReadKeychain(_, _ string) ([]byte, error) {
	return nil, ErrCredentialUnavailable
}
