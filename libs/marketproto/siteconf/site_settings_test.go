package siteconf

import (
	"encoding/json"
	"reflect"
	"testing"
)

// fix-mktsiteconf2 ①: the HTTPS profile, IPv6, cache switches, L2 off and the
// site access settings survive the relay and normalize to one digest.
func TestSiteSettingsRoundTrip(t *testing.T) {
	on := true
	c := sample()
	c.TLS = &TLSOptions{Protocols: []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}, CipherPreset: "custom",
		CipherSuites: []string{"ECDHE-RSA-AES128-GCM-SHA256"}, OCSPStapling: true, PreferServerCiphers: &on, HTTP2Off: true}
	c.IPv6, c.CacheSharedAcrossDomains, c.CacheStatusHeaderOff = true, true, true
	c.Forwarding = &Forwarding{L2Off: true}
	c.SiteAccess = json.RawMessage(`{"hsts":{"max_age_seconds":600},  "compression":{"enabled":true,"types":["text/html"]}}`)
	c.CC = json.RawMessage(`{"rules":[], "default_action":"allow"}`)
	c.HTTPPolicy = json.RawMessage(`{"max_upload_bytes":1048576, "cors":null}`)
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if string(c.SiteAccess) != `{"compression":{"enabled":true,"types":["text/html"]},"hsts":{"max_age_seconds":600}}` {
		t.Fatalf("site access not canonical: %s", c.SiteAccess)
	}
	if string(c.CC) != `{"default_action":"allow","rules":[]}` {
		t.Fatalf("cc not canonical: %s", c.CC)
	}
	if string(c.HTTPPolicy) != `{"cors":null,"max_upload_bytes":1048576}` {
		t.Fatalf("http policy not canonical: %s", c.HTTPPolicy)
	}
	raw, _ := json.Marshal(c)
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, back) || c.Digest() != back.Digest() {
		t.Fatalf("round trip changed the config:\n%+v\n%+v", c, back)
	}
}

func TestSiteSettingsDefaultsAreAbsent(t *testing.T) {
	c := sample()
	c.TLS = &TLSOptions{Protocols: []string{"TLSv1.2", "TLSv1.3"}, CipherPreset: "modern"}
	c.SiteAccess = json.RawMessage(`{}`)
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if c.TLS != nil || c.SiteAccess != nil {
		t.Fatalf("defaults kept: tls=%+v access=%s", c.TLS, c.SiteAccess)
	}
}

func TestSiteSettingsRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"tls without https":     func(c *Config) { c.HTTPSPorts = nil; c.Certificate = "none"; c.TLS = &TLSOptions{OCSPStapling: true} },
		"protocol gap":          func(c *Config) { c.TLS = &TLSOptions{Protocols: []string{"TLSv1.1", "TLSv1.3"}} },
		"unknown protocol":      func(c *Config) { c.TLS = &TLSOptions{Protocols: []string{"SSLv3"}} },
		"custom without suites": func(c *Config) { c.TLS = &TLSOptions{CipherPreset: "custom"} },
		"suites without custom": func(c *Config) { c.TLS = &TLSOptions{CipherSuites: []string{"X"}} },
		"access not object":     func(c *Config) { c.SiteAccess = json.RawMessage(`[1]`) },
		"access trailing":       func(c *Config) { c.SiteAccess = json.RawMessage(`{} {}`) },
		"cc with rate limit": func(c *Config) {
			c.CC = json.RawMessage(`{"default_action":"allow","rules":[]}`)
			c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":10,"max_requests":5}]}`)
		},
	} {
		c := sample()
		mutate(&c)
		if err := c.Normalize(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
