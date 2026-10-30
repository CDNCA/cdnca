package installationban

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (fn doerFunc) Do(request *http.Request) (*http.Response, error) { return fn(request) }

// fix-ipswitch：授权端错误体是顶层 {"code": …}（httpapi.writeError），客户端原先只认
// {"error": {"code": …}}，取不到 master_ip_rebound。
func TestClientFetchDecodesLicenseServiceErrorCode(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, body := range map[string]string{
		"top level": `{"code":"master_ip_rebound","request_id":"r1"}`,
		"nested":    `{"error":{"code":"master_ip_rebound"}}`,
	} {
		client, err := NewClient("https://auth.cdnca.com", uuid.New(), key, doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Fetch(t.Context(), testNow)
		var httpError *HTTPError
		if !errors.As(err, &httpError) || httpError.Code != CodeMasterIPRebound || !isRebound(err) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}
