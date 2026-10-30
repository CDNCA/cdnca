package pluginwebhookcontrol

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestSubscriptionAuthorizationRequirements(t *testing.T) {
	for name, test := range map[string]struct {
		events       []string
		wantScopes   []string
		wantTestOnly bool
		wantAllowed  bool
	}{
		"test only": {
			events: []string{EventTypeTest}, wantTestOnly: true, wantAllowed: true,
		},
		"deployment": {
			events:     []string{"io.cdnca.deployment.v1.status_changed"},
			wantScopes: []string{"events.deployment.read"}, wantAllowed: true,
		},
		"mixed sorted scopes": {
			events: []string{
				"io.cdnca.site.v1.updated",
				EventTypeTest,
				"io.cdnca.deployment.v1.status_changed",
				"io.cdnca.site.v1.updated",
			},
			wantScopes: []string{"events.deployment.read", "events.site.read"}, wantAllowed: true,
		},
		"dns changed has no formal permission": {
			events: []string{"io.cdnca.dns.v1.changed"},
		},
		"dns deleted has no formal permission": {
			events: []string{"io.cdnca.dns.v1.deleted"},
		},
		"unknown": {events: []string{"io.cdnca.unknown.v1.changed"}},
	} {
		t.Run(name, func(t *testing.T) {
			gotScopes, gotTestOnly, gotAllowed := subscriptionAuthorizationRequirements(test.events)
			if !reflect.DeepEqual(gotScopes, test.wantScopes) || gotTestOnly != test.wantTestOnly || gotAllowed != test.wantAllowed {
				t.Fatalf("requirements(%v) = %v,%t,%t; want %v,%t,%t", test.events, gotScopes, gotTestOnly, gotAllowed, test.wantScopes, test.wantTestOnly, test.wantAllowed)
			}
		})
	}
}

func TestCreateDigestBindsInstallationAuthorization(t *testing.T) {
	actor, err := NewActor(uuid.New(), uuid.New(), uuid.New(), ScopePlatform, "formal-session")
	if err != nil {
		t.Fatal(err)
	}
	authorizationID := uuid.New()
	base := canonicalCreate{Name: "deployment", TargetURL: "https://hooks.example.com/events", EventTypes: []string{"io.cdnca.deployment.v1.status_changed"}}
	bound := base
	bound.InstallationAuthorizationID = &authorizationID
	baseDigest, err := requestDigest(actor, opCreate, "create-1", base)
	if err != nil {
		t.Fatal(err)
	}
	boundDigest, err := requestDigest(actor, opCreate, "create-1", bound)
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == boundDigest {
		t.Fatal("create request digest did not bind installation authorization")
	}
}

func TestSubscriptionBindingJSONIsOptionalAndExplicit(t *testing.T) {
	unbound, err := json.Marshal(Subscription{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"installation_authorization_id", "installation_id", "plugin_id"} {
		if json.Valid(unbound) && string(unbound) != "" && containsJSONField(unbound, field) {
			t.Fatalf("unbound subscription unexpectedly exposes %s: %s", field, unbound)
		}
	}
	authorizationID, installationID, pluginID := uuid.New(), uuid.New(), "cdnca.example-plugin"
	bound, err := json.Marshal(Subscription{
		InstallationAuthorizationID: &authorizationID,
		InstallationID:              &installationID,
		PluginID:                    &pluginID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"installation_authorization_id", "installation_id", "plugin_id"} {
		if !containsJSONField(bound, field) {
			t.Fatalf("bound subscription omitted %s: %s", field, bound)
		}
	}
}

func containsJSONField(document []byte, field string) bool {
	var decoded map[string]any
	if json.Unmarshal(document, &decoded) != nil {
		return false
	}
	_, ok := decoded[field]
	return ok
}
