package dnsproviderremote

import (
	"encoding/hex"
	"net/url"
	"testing"
	"time"
)

// The worked example of the official 签名算法 page
// (docs.jdcloud.com/cn/common-declaration/api/authorization-rules, "签名步骤示例"):
// TESTAK / TESTSK, 20190214T104514Z, cn-north-1, service "test",
// POST /v1/resource:action?p1=p1&p0=p0&o=%&u=u, body "body data".
func TestJDCloudSignatureOfficialExample(t *testing.T) {
	at := time.Date(2019, time.February, 14, 10, 45, 14, 0, time.UTC)
	query := url.Values{"p1": {"p1"}, "p0": {"p0"}, "o": {"%"}, "u": {"u"}}
	if got := jdCloudCanonicalQuery(query); got != "o=%25&p0=p0&p1=p1&u=u" {
		t.Fatalf("canonical query = %q", got)
	}
	if got := jdCloudCanonicalPath("/v1/resource:action"); got != "/v1/resource%3Aaction" {
		t.Fatalf("canonical path = %q", got)
	}
	got := JDCloudSignature("TESTAK", "TESTSK", "cn-north-1", "test", "POST", "/v1/resource:action", query,
		map[string]string{"x-jdcloud-date": "20190214T104514Z", "x-jdcloud-nonce": "testnonce",
			"x-my-header": "test", "x-my-header_blank": " blank"}, []byte("body data"), at)
	want := "JDCLOUD2-HMAC-SHA256 Credential=TESTAK/20190214/cn-north-1/test/jdcloud2_request, " +
		"SignedHeaders=x-jdcloud-date;x-jdcloud-nonce;x-my-header;x-my-header_blank, " +
		"Signature=2a98f83c074e7bee260bfc8ef64f009c07595bd93f7f0c3f4e156bf6479ed9bf"
	if got != want {
		t.Fatalf("Authorization =\n %s\nwant\n %s", got, want)
	}
	// The derived key steps of the example (kDate, kSigning) in hex.
	key := jdCloudHMAC([]byte("JDCLOUD2TESTSK"), "20190214")
	if hexKey := hex.EncodeToString(key); hexKey != "dbbdee87f18afeedd6456923587f5323b90c3a77fbc6e381b243c90c672d5daf" {
		t.Fatalf("kDate = %s", hexKey)
	}
	for _, part := range []string{"cn-north-1", "test", "jdcloud2_request"} {
		key = jdCloudHMAC(key, part)
	}
	if hexKey := hex.EncodeToString(key); hexKey != "a4e50bcb6001be0008696b173c30172b5ce22a77db00d21c6a9d69de2ba33b7d" {
		t.Fatalf("kSigning = %s", hexKey)
	}
}
