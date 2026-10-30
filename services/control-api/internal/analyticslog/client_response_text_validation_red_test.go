package analyticslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRejectsUnicodeControlTextFromClickHouse(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	row := accessTestRow("event-c1", now.Add(-time.Minute), "/c1")
	row.Carrier = "carrier-\u0080"
	server := rowServer(t, []accessRow{row})
	defer server.Close()

	client := newUnitClient(t, server, time.Second)
	_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, Filter{
		From: now.Add(-time.Hour), To: now,
	}, 10, "")
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want ErrInvalidResponse", err)
	}
}

func TestClientRejectsMalformedUTF8BeforeJSONDecode(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	row, err := json.Marshal(accessTestRow("event-invalid-utf8", now.Add(-time.Minute), "/invalid-utf8"))
	if err != nil {
		t.Fatal(err)
	}
	row = bytes.Replace(row, []byte(`"carrier-a"`), append([]byte(`"carrier-`), 0xff, byte('"')), 1)
	if bytes.IndexByte(row, 0xff) < 0 {
		t.Fatal("test response did not contain malformed UTF-8")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(append(row, '\n'))
	}))
	defer server.Close()

	client := newUnitClient(t, server, time.Second)
	_, err = client.ListAccess(context.Background(), scope{tenantID: tenantA}, Filter{
		From: now.Add(-time.Hour), To: now,
	}, 10, "")
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want ErrInvalidResponse", err)
	}
}
