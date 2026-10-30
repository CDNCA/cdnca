package siteschedule302

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalize(t *testing.T) {
	off, err := Normalize(Settings{Enabled: false, Target: "bogus", Extensions: []string{"x y"}})
	if err != nil || off.Enabled || off.Target != "address" || off.SignatureTTLSeconds != 60 {
		t.Fatalf("disabled settings: %+v %v", off, err)
	}
	on, err := Normalize(Settings{Enabled: true, Target: "hostname", SignatureTTLSeconds: 300,
		Extensions: []string{".ISO", "mp4", "iso"}, PathPrefixes: []string{"/dl/"}, MinSizeBytes: 10 << 20})
	if err != nil || !on.Enabled || len(on.Extensions) != 2 || on.Extensions[0] != "iso" || on.PathPrefixes[0] != "/dl/" {
		t.Fatalf("enabled settings: %+v %v", on, err)
	}
	for name, settings := range map[string]Settings{
		"target": {Enabled: true, Target: "ip", SignatureTTLSeconds: 60},
		"ttl":    {Enabled: true, Target: "address", SignatureTTLSeconds: 4000},
		"prefix": {Enabled: true, Target: "address", SignatureTTLSeconds: 60, PathPrefixes: []string{"dl"}},
		"size":   {Enabled: true, Target: "address", SignatureTTLSeconds: 60, MinSizeBytes: -5},
	} {
		if _, err := Normalize(settings); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSettingsChanges(t *testing.T) {
	off := DefaultSettings()
	on, _ := Normalize(Settings{Enabled: true, Target: "address", KeepPath: true, SignatureTTLSeconds: 60})
	changes := settingsChanges(off, on)
	if change, ok := changes["enabled"].(map[string]any); !ok || change["from"] != false || change["to"] != true {
		t.Fatalf("enabled change: %#v", changes)
	}
	later := on
	later.SignatureTTLSeconds = 120
	changes = settingsChanges(on, later)
	if len(changes) != 1 || changes["signature_ttl_seconds"] == nil {
		t.Fatalf("ttl change: %#v", changes)
	}
}

func TestUpdateRejectsInvalidRequests(t *testing.T) {
	service := NewService(nil)
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	for name, request := range map[string]UpdateRequest{
		"site":        {ExpectedRevision: 1, IdempotencyKey: "k", RequestID: "r"},
		"revision":    {SiteID: uuid.New(), IdempotencyKey: "k", RequestID: "r"},
		"idempotency": {SiteID: uuid.New(), ExpectedRevision: 1, IdempotencyKey: "bad key", RequestID: "r"},
		"settings": {SiteID: uuid.New(), ExpectedRevision: 1, IdempotencyKey: "k", RequestID: "r",
			Settings: Settings{Enabled: true, Target: "x", SignatureTTLSeconds: 60}},
	} {
		if _, err := service.Update(t.Context(), actor, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := service.Update(t.Context(), Actor{}, UpdateRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("no actor: %v", err)
	}
}
