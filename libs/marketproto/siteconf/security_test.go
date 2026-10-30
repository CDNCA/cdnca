package siteconf

import (
	"encoding/json"
	"testing"
)

func TestSecurityBlocksAreCanonicalAndOptional(t *testing.T) {
	a, b := sample(), sample()
	a.Access = json.RawMessage(`{"default":"allow","rules":[{"cidr":"203.0.113.7/24","action":"block"}]}`)
	b.Access = json.RawMessage(`{ "rules":[{"action":"block","cidr":"203.0.113.0/24"}], "default":"allow" }`)
	a.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":60,"max_requests":100}]}`)
	b.RateLimit = json.RawMessage(`{"rules":[{"max_requests":100,"window_seconds":60,"on_exceed":"reject"}]}`)
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("same intent, different digest:\n%s %s\n%s %s", a.Access, a.RateLimit, b.Access, b.RateLimit)
	}
	access, err := a.DecodeAccess()
	if err != nil || access.Rules[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("access %+v %v", access, err)
	}
	limit, err := a.DecodeRateLimit()
	if err != nil || limit.Rules[0].OnExceed != "reject" {
		t.Fatalf("rate limit %+v %v", limit, err)
	}
	none := sample()
	none.Access, none.RateLimit = json.RawMessage(`null`), json.RawMessage(`null`)
	if err := none.Normalize(); err != nil || none.Access != nil || none.RateLimit != nil {
		t.Fatalf("null blocks = %s %s %v", none.Access, none.RateLimit, err)
	}
}

func TestSecurityBlocksReject(t *testing.T) {
	for name, set := range map[string]func(*Config){
		"access unknown field": func(c *Config) { c.Access = json.RawMessage(`{"default":"allow","rules":[],"geo":["cn"]}`) },
		"access no rules":      func(c *Config) { c.Access = json.RawMessage(`{"default":"block","rules":[]}`) },
		"access default": func(c *Config) {
			c.Access = json.RawMessage(`{"default":"drop","rules":[{"cidr":"1.2.3.0/24","action":"block"}]}`)
		},
		"access cidr": func(c *Config) {
			c.Access = json.RawMessage(`{"default":"allow","rules":[{"cidr":"1.2.3.4","action":"block"}]}`)
		},
		"access action": func(c *Config) {
			c.Access = json.RawMessage(`{"default":"allow","rules":[{"cidr":"1.2.3.0/24","action":"log"}]}`)
		},
		"limit unknown": func(c *Config) {
			c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":60,"max_requests":1,"key":"ip"}]}`)
		},
		"limit no rules": func(c *Config) { c.RateLimit = json.RawMessage(`{"rules":[]}`) },
		"limit window":   func(c *Config) { c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":0,"max_requests":1}]}`) },
		"limit path": func(c *Config) {
			c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":1,"max_requests":1,"path_prefix":"api"}]}`)
		},
		"ban without seconds": func(c *Config) {
			c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":1,"max_requests":1,"on_exceed":"ban"}]}`)
		},
		"seconds without ban": func(c *Config) {
			c.RateLimit = json.RawMessage(`{"rules":[{"window_seconds":1,"max_requests":1,"ban_seconds":60}]}`)
		},
	} {
		c := sample()
		set(&c)
		if err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
