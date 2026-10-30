package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// testdata/site-updated.json is a canonical io.cdnca.site.v1.updated delivery
// for the vector tenant and subscription (data keys in the control plane's
// sorted order). tests/plugin-example/validate-contracts.mjs checks the same
// bytes against domain-event.schema.json.
const (
	siteEvent = "018cc251-f400-7def-8000-000000000101"
	siteID    = "018cc251-f400-7def-8000-000000000201"
)

var siteBody = func() string {
	raw, err := os.ReadFile("testdata/site-updated.json")
	if err != nil {
		panic(err)
	}
	return string(raw)
}()

func TestReceiverRecordsSiteUpdateOncePerEvent(t *testing.T) {
	receiver, journal := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	now := time.Unix(1704067200, 0)
	first := "018cc251-f400-7def-8000-000000000102"
	assertCode(t, receiver, signedRequest([]byte(siteBody), vectorKey, vectorKeyID, siteEvent, first, now), http.StatusAccepted, "accepted")
	// A retried attempt of the same delivery and an explicit replay (new delivery, same event) do not repeat the business record.
	assertCode(t, receiver, signedRequest([]byte(siteBody), vectorKey, vectorKeyID, siteEvent, first, now), http.StatusOK, "replay_accepted")
	assertCode(t, receiver, signedRequest([]byte(siteBody), vectorKey, vectorKeyID, siteEvent, "018cc251-f400-7def-8000-000000000103", now), http.StatusOK, "event_already_processed")
	contents, err := os.ReadFile(journal.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 2 {
		t.Fatalf("journal = %q", contents)
	}
	var entry journalEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil || entry.Site == nil ||
		entry.Site.SiteID != siteID || entry.Site.Change != "updated" || !slices.Equal(entry.Site.ChangedFields, []string{"origins"}) || entry.Site.SubjectSequence != 4 {
		t.Fatalf("site record = %+v err=%v", entry, err)
	}
	var replay journalEntry
	if err := json.Unmarshal([]byte(lines[1]), &replay); err != nil || replay.Site != nil {
		t.Fatalf("replay must not record the site change again: %s", lines[1])
	}
	// The journal reloads with the site record.
	_ = journal.Close()
	reopened, err := openJournal(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

func TestReceiverRejectsMalformedOrForeignSiteUpdates(t *testing.T) {
	receiver, _ := vectorReceiver(t, vectorKey, vectorKeyID, time.Time{})
	now := time.Unix(1704067200, 0)
	cases := []struct {
		name, from, to string
		status         int
		code           string
	}{
		{"other tenant", `"tenant_id":"` + vectorTenant, `"tenant_id":"018cc251-f400-7def-8000-000000000031`, http.StatusForbidden, "event_scope_denied"},
		{"other subscription", `"subscription_id":"` + vectorSubscription, `"subscription_id":"018cc251-f400-7def-8000-000000000019`, http.StatusForbidden, "event_scope_denied"},
		{"subject is not the site", `"subject":"site/` + siteID, `"subject":"site/018cc251-f400-7def-8000-000000000202`, http.StatusBadRequest, "event_invalid"},
		{"test schema", "domain-event.schema.json", "webhook-test-event.schema.json", http.StatusBadRequest, "event_invalid"},
		{"unknown change", `"change":"updated"`, `"change":"renamed"`, http.StatusBadRequest, "event_invalid"},
		{"unknown field", `"changed_fields":["origins"]`, `"changed_fields":["secret"]`, http.StatusBadRequest, "event_invalid"},
		{"extra data", `"change":"updated",`, `"change":"updated","x":1,`, http.StatusBadRequest, "event_invalid"},
		{"unsupported type", "io.cdnca.site.v1.updated", "io.cdnca.node.v1.status_changed", http.StatusBadRequest, "event_invalid"},
	}
	for index, test := range cases {
		body := strings.Replace(siteBody, test.from, test.to, 1)
		if body == siteBody {
			t.Fatalf("%s: replacement did not apply", test.name)
		}
		delivery := "018cc251-f400-7def-8000-0000000004" + string(rune('a'+index/10)) + string(rune('0'+index%10))
		response := serve(receiver, signedRequest([]byte(body), vectorKey, vectorKeyID, siteEvent, delivery, now))
		if response.Code != test.status || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"`+test.code+`"`)) {
			t.Fatalf("%s: %d %s", test.name, response.Code, response.Body.String())
		}
	}
}

// The manifest next to the receiver subscribes exactly to what it accepts.
func TestManifestMatchesReceiver(t *testing.T) {
	raw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Spec struct {
			Permissions   []string `json:"permissions"`
			Subscriptions []string `json:"subscriptions"`
			Entrypoint    struct {
				Type       string `json:"type"`
				HealthPath string `json:"health_path"`
			} `json:"entrypoint"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(manifest.Spec.Subscriptions, []string{siteEventType}) || !slices.Equal(manifest.Spec.Permissions, []string{"events.site.read"}) ||
		manifest.Spec.Entrypoint.Type != "external_https" || manifest.Spec.Entrypoint.HealthPath != healthPath {
		t.Fatalf("manifest = %+v", manifest.Spec)
	}
}
