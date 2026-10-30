package dnsproviderremote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ValidationTXTWriter publishes and removes TXT records a third-party CDN
// asks for (Cloudflare for SaaS ownership and certificate DCV, ADR 0008
// §4.1) in a zone of the site tenant's DNS provider, through the same
// provider code as DNS-01. The caller resolves the provider, holds its
// credential fence for the call and keeps the returned reference.
type ValidationTXTWriter struct{ adapter *Adapter }

func NewValidationTXTWriter() *ValidationTXTWriter {
	return &ValidationTXTWriter{adapter: newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)}
}

const validationRefPrefix = "txt1."

// ValidTXTValue reports whether value can be written: the DNS-01 value
// alphabet (letters, digits, "-", "_"), up to 255 bytes. Anything else is
// left for the member to add by hand.
func ValidTXTValue(value string) bool { return validExactValue(value) }

// Publish makes sure the exact TXT record owner=value exists and returns its
// reference; an existing exact record is adopted (no second write).
func (writer *ValidationTXTWriter) Publish(ctx context.Context, config ProviderConfig, owner, value string) (string, error) {
	provider, validated, canonical, relative, err := writer.prepare(ctx, config, owner, value)
	if err != nil {
		return "", err
	}
	matches, err := provider.lookupTXT(ctx, validated, canonical, relative, value)
	if err != nil {
		return "", err
	}
	if len(matches) > 1 {
		return "", failure(CodeRecordMismatch, false)
	}
	handle := recordHandle{}
	if len(matches) == 1 {
		handle = matches[0]
	} else if handle, err = provider.present(ctx, validated, canonical, relative, value); err != nil {
		return "", err
	}
	handle.Version = 1
	if err := validateRecordHandle(handle); err != nil {
		return "", malformedProviderResponse()
	}
	raw, err := json.Marshal(handle)
	if err != nil {
		return "", malformedProviderResponse()
	}
	return validationRefPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Remove deletes the record ref names if it still holds value; a record
// that is already gone is success, one changed by someone else is left
// alone (CodeRecordMismatch).
func (writer *ValidationTXTWriter) Remove(ctx context.Context, config ProviderConfig, ref, owner, value string) error {
	provider, validated, canonical, _, err := writer.prepare(ctx, config, owner, value)
	if err != nil {
		return err
	}
	encoded, found := strings.CutPrefix(ref, validationRefPrefix)
	raw, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
	var handle recordHandle
	if !found || decodeErr != nil || json.Unmarshal(raw, &handle) != nil || validateRecordHandle(handle) != nil ||
		handle.Provider != validated.ProviderType || handle.Zone != validated.ZoneName || handle.Owner != canonical {
		return failure(CodeInvalidInput, false)
	}
	record, exists, err := provider.get(ctx, validated, handle, value)
	if isCode(err, CodeRecordNotFound) || (err == nil && !exists) {
		return nil
	}
	if err != nil {
		return err
	}
	if !matchesRecord(record, handle, value) {
		return failure(CodeRecordMismatch, false)
	}
	return provider.delete(ctx, validated, handle)
}

func (writer *ValidationTXTWriter) prepare(ctx context.Context, config ProviderConfig, owner, value string) (
	remoteProvider, ProviderConfig, string, string, error) {
	if ctx == nil || writer == nil || writer.adapter == nil || !validExactValue(value) {
		return nil, ProviderConfig{}, "", "", failure(CodeInvalidInput, false)
	}
	canonical := canonicalDNSName(owner, true)
	if canonical == "" {
		return nil, ProviderConfig{}, "", "", failure(CodeInvalidInput, false)
	}
	validated, relative, err := validateConfig(config, canonical)
	if err != nil {
		return nil, ProviderConfig{}, "", "", err
	}
	if relative == "@" {
		return nil, ProviderConfig{}, "", "", failure(CodeInvalidInput, false) // never the zone apex
	}
	provider, err := writer.adapter.provider(validated.ProviderType)
	if err != nil {
		return nil, ProviderConfig{}, "", "", err
	}
	return provider, validated, canonical, relative, nil
}
