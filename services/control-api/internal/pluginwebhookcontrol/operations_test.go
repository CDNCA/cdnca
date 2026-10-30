package pluginwebhookcontrol

import (
	"reflect"
	"testing"
)

func TestNormalizeEventTypesAcceptsKnownVersionedEventsAndSorts(t *testing.T) {
	got, ok := NormalizeEventTypes([]string{
		"io.cdnca.site.v1.updated",
		EventTypeTest,
		"io.cdnca.deployment.v1.status_changed",
	})
	if !ok {
		t.Fatal("NormalizeEventTypes rejected known event types")
	}
	want := []string{
		"io.cdnca.deployment.v1.status_changed",
		"io.cdnca.site.v1.updated",
		EventTypeTest,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeEventTypes() = %#v, want %#v", got, want)
	}
}

func TestNormalizeEventTypesRejectsInvalidLists(t *testing.T) {
	tooMany := make([]string, maxSubscriptionEventTypes+1)
	for i := range tooMany {
		tooMany[i] = EventTypeTest
	}
	for name, input := range map[string][]string{
		"empty":       {},
		"duplicate":   {EventTypeTest, EventTypeTest},
		"unknown":     {"io.cdnca.unknown.v1.event"},
		"reserved":    {"io.cdnca.dns.v1.changed"},
		"bad version": {"io.cdnca.site.v0.updated"},
		"bad casing":  {"io.cdnca.Site.v1.updated"},
		"too many":    tooMany,
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := NormalizeEventTypes(input); ok || got != nil {
				t.Fatalf("NormalizeEventTypes(%#v) = %#v, %t; want nil, false", input, got, ok)
			}
		})
	}
}
