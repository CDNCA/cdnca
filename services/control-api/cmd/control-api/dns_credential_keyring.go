package main

import (
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

func newConfiguredDNSCredentialCipher(cfg config.Config) (*dnsacme.AESGCMCredentialCipher, error) {
	active := dnsacme.CredentialKey{
		ID: cfg.DNSCredentialKeyID, Material: append([]byte(nil), cfg.DNSCredentialKey...),
	}
	previous := make([]dnsacme.CredentialKey, 0, 1)
	if cfg.DNSCredentialPreviousKeyID != "" || len(cfg.DNSCredentialPreviousKey) != 0 {
		previous = append(previous, dnsacme.CredentialKey{
			ID:       cfg.DNSCredentialPreviousKeyID,
			Material: append([]byte(nil), cfg.DNSCredentialPreviousKey...),
		})
	}
	cipher, err := dnsacme.NewAESGCMCredentialKeyring(active, previous...)
	clear(active.Material)
	for index := range previous {
		clear(previous[index].Material)
	}
	return cipher, err
}
