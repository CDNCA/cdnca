package siteconf

import (
	"bytes"
	"encoding/json"
	"slices"
)

// Site settings beyond protocols and origins (fix-mktsiteconf2, 1.0.35
// baseline): the HTTPS profile, IPv6, the cache switches and the site access
// settings (编辑网站 > 访问控制). The leaf writes each onto its own site; its
// site services do the final validation.

// TLSOptions is the HTTPS profile. Protocols nil is the baseline
// (TLSv1.2, TLSv1.3); CipherPreset "" is modern; PreferServerCiphers nil
// follows the preset.
type TLSOptions struct {
	Protocols           []string `json:"protocols,omitempty"`
	CipherPreset        string   `json:"cipher_preset,omitempty"`
	CipherSuites        []string `json:"cipher_suites,omitempty"`
	OCSPStapling        bool     `json:"ocsp_stapling,omitempty"`
	PreferServerCiphers *bool    `json:"prefer_server_ciphers,omitempty"`
	HTTP2Off            bool     `json:"http2_off,omitempty"`
}

var (
	tlsProtocolOrder = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
	baselineTLS      = []string{"TLSv1.2", "TLSv1.3"}
	cipherPresets    = []string{"", "modern", "compatible", "legacy", "custom"}
)

const (
	maxSiteAccessBytes = 256 << 10
	// maxWAFBytes bounds the waf block with its IP list contents (the market
	// relay accepts 6 MiB bodies).
	maxWAFBytes = 2 << 20
)

func (c *Config) normalizeSiteSettings() error {
	if t := c.TLS; t != nil {
		if len(c.HTTPSPorts) == 0 || len(t.Protocols) > len(tlsProtocolOrder) || !slices.Contains(cipherPresets, t.CipherPreset) ||
			(t.CipherPreset == "custom") != (len(t.CipherSuites) > 0) || len(t.CipherSuites) > maxListValues {
			return ErrInvalid
		}
		// An ascending contiguous range of known protocols.
		for i, p := range t.Protocols {
			at := slices.Index(tlsProtocolOrder, p)
			if at < 0 || i > 0 && at != slices.Index(tlsProtocolOrder, t.Protocols[i-1])+1 {
				return ErrInvalid
			}
		}
		for _, suite := range t.CipherSuites {
			if suite == "" || !validText(suite, 128) {
				return ErrInvalid
			}
		}
		if t.CipherPreset == "modern" {
			t.CipherPreset = ""
		}
		if slices.Equal(t.Protocols, baselineTLS) || len(t.Protocols) == 0 {
			t.Protocols = nil
		}
		if len(t.CipherSuites) == 0 {
			t.CipherSuites = nil
		}
		if t.Protocols == nil && t.CipherPreset == "" && !t.OCSPStapling && t.PreferServerCiphers == nil && !t.HTTP2Off {
			c.TLS = nil
		}
	}
	var err error
	if c.SiteAccess, err = canonicalObject(c.SiteAccess); err != nil {
		return err
	}
	// The waf block carries the contents of the IP lists its rules use.
	if c.WAF, err = canonicalObjectMax(c.WAF, maxWAFBytes); err != nil {
		return err
	}
	if c.CC, err = canonicalObject(c.CC); err != nil {
		return err
	}
	c.HTTPPolicy, err = canonicalObject(c.HTTPPolicy)
	return err
}

// canonicalObject writes a carried JSON object canonically (sorted keys,
// compact) so equal settings give equal digests; absent or {} is nil.
func canonicalObject(raw json.RawMessage) (json.RawMessage, error) {
	return canonicalObjectMax(raw, maxSiteAccessBytes)
}

func canonicalObjectMax(raw json.RawMessage, limit int) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > limit {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil || decoder.More() {
		return nil, ErrInvalid
	}
	if len(value) == 0 {
		return nil, nil
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	return canonical, nil
}
