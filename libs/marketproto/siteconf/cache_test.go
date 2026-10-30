package siteconf

import (
	"encoding/json"
	"testing"
)

func TestCacheIsCanonicalAndOptional(t *testing.T) {
	a, b := sample(), sample()
	a.Cache = json.RawMessage(`{"mode":"override","rules":[{"extensions":["jpg"],"action":"cache","ttl_seconds":3600}]}`)
	b.Cache = json.RawMessage(`{ "rules": [ {"ttl_seconds":3600, "action":"cache", "extensions":["jpg"]} ],
		"query_mode":"preserve", "mode":"override" }`)
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() || string(a.Cache) != string(b.Cache) {
		t.Fatalf("same cache intent, different digest:\n%s\n%s", a.Cache, b.Cache)
	}
	cache, err := a.DecodeCache()
	if err != nil || cache.Mode != "override" || cache.QueryMode != "preserve" || len(cache.Rules) != 1 ||
		cache.Rules[0].TTLSeconds != 3600 {
		t.Fatalf("decoded %+v %v", cache, err)
	}
	none := sample()
	none.Cache = json.RawMessage(`null`)
	if err := none.Normalize(); err != nil || none.Cache != nil {
		t.Fatalf("null cache = %s %v", none.Cache, err)
	}
	if cache, err := none.DecodeCache(); cache != nil || err != nil {
		t.Fatalf("absent cache decoded %+v %v", cache, err)
	}
	raw, _ := json.Marshal(none)
	if string(raw) == "" || json.Valid(raw) == false {
		t.Fatal("config without cache does not marshal")
	}
	var probe map[string]any
	_ = json.Unmarshal(raw, &probe)
	if _, present := probe["cache"]; present {
		t.Fatal("absent cache must stay absent on the wire")
	}
}

func TestCacheRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown field": `{"mode":"override","disk_quota_bytes":1}`,
		"mode":          `{"mode":"aggressive"}`,
		"no mode":       `{}`,
		"query mode":    `{"mode":"override","query_mode":"sorted"}`,
		"action":        `{"mode":"override","rules":[{"action":"purge"}]}`,
		"negative ttl":  `{"mode":"override","rules":[{"action":"cache","ttl_seconds":-1}]}`,
		"huge ttl":      `{"mode":"override","rules":[{"action":"cache","ttl_seconds":999999999999}]}`,
		"not object":    `[1]`,
		"trailing":      `{"mode":"override"}{}`,
	} {
		c := sample()
		c.Cache = json.RawMessage(raw)
		if err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
