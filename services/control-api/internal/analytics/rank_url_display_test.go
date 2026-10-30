package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Like the competitor, the domain ranking shows
// host:port and the hot URL ranking the full address scheme://host:port/path,
// so the rows carry host/port/path (URL also the site, for the scheme).

func rankClientReturning(t *testing.T, rows string) (*Client, *string) {
	t.Helper()
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		body = string(encoded)
		_, _ = io.WriteString(writer, rows)
	}))
	t.Cleanup(server.Close)
	return mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client()), &body
}

func TestRankByDomainGroupsByHostAndListenPort(t *testing.T) {
	client, body := rankClientReturning(t,
		`{"key":"a.example:443","request_count":3,"response_bytes":300,"host":"a.example","port":443}`+"\n"+
			`{"key":"a.example:80","request_count":2,"response_bytes":200,"host":"a.example","port":80}`+"\n")
	page, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByDomain, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := rankHostPortSQL("tupleElement(latest, 6)", "tupleElement(latest, 10)") + " AS key"; !strings.Contains(*body, want) {
		t.Fatalf("domain rank lacks %q:\n%s", want, *body)
	}
	if got := page.Items[1]; got.Key != "a.example:80" || got.Host != "a.example" || got.Port != 80 {
		t.Fatalf("item = %#v", got)
	}
}

func TestRankByURLGroupsByHostPortAndPath(t *testing.T) {
	client, body := rankClientReturning(t,
		`{"key":"a.example:443/x","request_count":3,"response_bytes":300,"host":"a.example","port":443,"path":"/x","site_id":"`+testSiteID+`"}`+"\n"+
			`{"key":"b.example:80/x","request_count":2,"response_bytes":200,"host":"b.example","port":80,"path":"/x","site_id":"`+testSiteID+`"}`+"\n")
	page, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByURL, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "concat(" + rankHostPortSQL("tupleElement(latest, 6)", "tupleElement(latest, 10)") + ", tupleElement(latest, 4)) AS key"
	if !strings.Contains(*body, want) {
		t.Fatalf("url rank lacks %q:\n%s", want, *body)
	}
	if got := page.Items[0]; got.Host != "a.example" || got.Port != 443 || got.Path != "/x" || got.SiteID != testSiteID {
		t.Fatalf("item = %#v", got)
	}
}

func TestRankKeyFitsHostPortAndLongestPath(t *testing.T) {
	key := strings.Repeat("h", 253) + ":65535/" + strings.Repeat("p", 4095)
	if !validRankKey(key) {
		t.Fatalf("a %d-byte host:port/path key is refused", len(key))
	}
}

type fakeHTTPSPorts struct {
	ports map[string][]uint16
	err   error
	asked []string
}

func (fake *fakeHTTPSPorts) SiteHTTPSPorts(_ context.Context, siteIDs []string) (map[string][]uint16, error) {
	fake.asked = siteIDs
	return fake.ports, fake.err
}

func TestServiceRankURLDerivesSchemeFromSiteHTTPSPorts(t *testing.T) {
	const otherSite = "20000000-0000-0000-0000-000000000009"
	store := &recordingQueryStore{rank: RankPage{Items: []RankItem{
		{Key: "a.example:443/x", RequestCount: 3, Host: "a.example", Port: 443, Path: "/x", SiteID: testSiteID},
		{Key: "a.example:80/x", RequestCount: 2, Host: "a.example", Port: 80, Path: "/x", SiteID: testSiteID},
		{Key: "b.example:8443/y", RequestCount: 1, Host: "b.example", Port: 8443, Path: "/y", SiteID: otherSite},
		{Key: "c.example/z", RequestCount: 1, Host: "c.example", Path: "/z", SiteID: otherSite},
	}}}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	ports := &fakeHTTPSPorts{ports: map[string][]uint16{testSiteID: {443}, otherSite: {8443}}}
	service.SetSiteHTTPSPortReader(ports)
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	page, err := service.Rank(context.Background(), actor, serviceQueryRequest(AudienceTenant), RankByURL, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https", "http", "https", ""}
	for index, item := range page.Items {
		if item.Scheme != want[index] || item.SiteID != "" {
			t.Fatalf("item %d = %#v, want scheme %q and no site", index, item, want[index])
		}
	}
	if len(ports.asked) != 2 {
		t.Fatalf("asked sites = %v", ports.asked)
	}

	// A failed lookup leaves the scheme unknown instead of failing the page.
	ports.err = errors.New("pg down")
	store.rank.Items[0].SiteID, store.rank.Items[0].Scheme = testSiteID, ""
	page, err = service.Rank(context.Background(), actor, serviceQueryRequest(AudienceTenant), RankByURL, 10, "")
	if err != nil || page.Items[0].Scheme != "" {
		t.Fatalf("lookup failure: err=%v item=%#v", err, page.Items[0])
	}
}

func TestHandlerRankEmitsAddressPartsButNotSite(t *testing.T) {
	encoded, err := json.Marshal(RankItem{Key: "a.example:443/x", RequestCount: 1, Host: "a.example", Port: 443, Path: "/x", Scheme: "https", SiteID: testSiteID})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"key":"a.example:443/x","request_count":1,"response_bytes":0,"host":"a.example","port":443,"path":"/x","scheme":"https"}`; got != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
	encoded, _ = json.Marshal(RankItem{Key: "JP", RequestCount: 1})
	if got, want := string(encoded), `{"key":"JP","request_count":1,"response_bytes":0}`; got != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}
