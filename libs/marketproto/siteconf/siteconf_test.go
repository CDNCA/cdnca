package siteconf

import (
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
)

func sample() Config {
	return Config{Schema: SchemaV1, Domains: []string{"WWW.Example.com.", "例子.cn"},
		HTTPPorts: []int{80}, HTTPSPorts: []int{443, 443},
		Origins: []Origin{{Host: "203.0.113.9", Port: 80}, {Host: "origin.example.net", Port: 8080, Weight: 5}}}
}

func TestNormalizeIsCanonical(t *testing.T) {
	a, b := sample(), sample()
	b.Domains = []string{"例子.cn", "www.example.com"}
	b.Origins = []Origin{b.Origins[1], b.Origins[0]}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatal("same intent must give the same digest")
	}
	if a.Domains[0] != "www.example.com" || a.Domains[1] != "xn--fsqu00a.cn" || len(a.HTTPSPorts) != 1 {
		t.Fatalf("normalized = %+v", a)
	}
	b.WebSocket = true
	if a.Digest() == b.Digest() {
		t.Fatal("different config must give a different digest")
	}
}

func TestNormalizeRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"schema":        func(c *Config) { c.Schema = "x" },
		"no origins":    func(c *Config) { c.Origins = nil },
		"loopback":      func(c *Config) { c.Origins[0].Host = "127.0.0.1" },
		"port overlap":  func(c *Config) { c.HTTPPorts = []int{443} },
		"duplicate":     func(c *Config) { c.Domains = []string{"a.example.com", "A.example.com"} },
		"https no cert": func(c *Config) { c.Certificate = "none" },
		"bad scheme":    func(c *Config) { c.OriginScheme = "ftp" },
		"bare wildcard": func(c *Config) { c.Domains = []string{"*.com"} },
	} {
		c := sample()
		mutate(&c)
		if err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckAllocation(t *testing.T) {
	c := sample()
	c.WebSocket = true
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	two := spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}}
	if got := c.CheckAllocation(spec.Allocation{HTTPPorts: 2, WebSocket: true}, two); len(got) != 0 {
		t.Fatalf("fits but blocked: %+v", got)
	}
	if got := c.CheckAllocation(spec.Allocation{HTTPPorts: 2, WebSocket: true}, nil); len(got) != 0 {
		t.Fatalf("unselected domains limit must be unlimited: %+v", got)
	}
	one := spec.LimitSet{{Metric: spec.MetricDomains, Cap: 1, Action: spec.ActionRejectNew}}
	got := c.CheckAllocation(spec.Allocation{HTTPPorts: 1}, one)
	if len(got) != 3 || got[0].Code != "domain_limit" || got[1].Code != "port_limit" || got[2].Code != "websocket_not_allowed" {
		t.Fatalf("blockers = %+v", got)
	}
}
