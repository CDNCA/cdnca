package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
)

// fp-cert2 补充：保存默认设置时签发机构不可用与建单时同一个 409 错误码。
func TestCertificateDefaultsIssuerUnavailableIsTheOrderConflict(t *testing.T) {
	codes := map[error]string{}
	for _, err := range []error{certdefaults.ErrIssuerUnavailable, dnsacme.ErrIssuerUnavailable} {
		recorder := httptest.NewRecorder()
		(&Server{}).writeError(recorder, httptest.NewRequest(http.MethodPatch, "/v1/certificate-defaults", nil), err)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(recorder.Body.Bytes(), &body) != nil || recorder.Code != http.StatusConflict {
			t.Fatalf("%v: status %d body %s", err, recorder.Code, recorder.Body.String())
		}
		codes[err] = body.Error.Code
	}
	if codes[certdefaults.ErrIssuerUnavailable] != "certificate_issuer_unavailable" ||
		codes[certdefaults.ErrIssuerUnavailable] != codes[dnsacme.ErrIssuerUnavailable] {
		t.Fatalf("codes %v", codes)
	}
}
