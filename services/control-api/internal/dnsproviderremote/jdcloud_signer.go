package dnsproviderremote

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// JD Cloud OpenAPI signature JDCLOUD2-HMAC-SHA256, per the official
// 签名算法 page https://docs.jdcloud.com/cn/common-declaration/api/authorization-rules
// (read 2026-11-05; the worked TESTAK/TESTSK example there is the unit test)
// and jdcloud-sdk-go core/Signer.go:
//
//	CanonicalRequest = Method \n CanonicalURI \n CanonicalQuery \n
//	                   CanonicalHeaders(each "name:value\n") \n SignedHeaders \n hex(sha256(body))
//	StringToSign     = JDCLOUD2-HMAC-SHA256 \n YYYYMMDDTHHMMSSZ \n date/region/service/jdcloud2_request \n hex(sha256(CanonicalRequest))
//	kSigning         = HMAC(HMAC(HMAC(HMAC("JDCLOUD2"+secret, date), region), service), "jdcloud2_request")
//	Authorization    = JDCLOUD2-HMAC-SHA256 Credential=ak/scope, SignedHeaders=..., Signature=hex(HMAC(kSigning, StringToSign))
const (
	jdCloudAlgorithm  = "JDCLOUD2-HMAC-SHA256"
	jdCloudTimeLayout = "20060102T150405Z"
)

// jdCloudEscape percent-encodes all but the RFC 3986 unreserved characters
// (A-Z a-z 0-9 - _ . ~), upper-case hex: the canonical form of path
// segments, query names and values.
func jdCloudEscape(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '~' {
			builder.WriteByte(character)
		} else {
			fmt.Fprintf(&builder, "%%%02X", character)
		}
	}
	return builder.String()
}

// jdCloudCanonicalPath encodes each segment of a raw (unescaped) path.
func jdCloudCanonicalPath(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		segments[index] = jdCloudEscape(segment)
	}
	return strings.Join(segments, "/")
}

// jdCloudCanonicalQuery sorts by name, then value; it is also the query sent.
func jdCloudCanonicalQuery(query url.Values) string {
	pairs := make([]string, 0, len(query))
	for name, values := range query {
		for _, value := range values {
			pairs = append(pairs, jdCloudEscape(name)+"="+jdCloudEscape(value))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// JDCloudSignature returns the Authorization header value of one request.
// path is unescaped; headers are the signed headers (lower-case names).
func JDCloudSignature(accessKeyID, accessKeySecret, region, service, method, path string, query url.Values,
	headers map[string]string, body []byte, at time.Time) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	lowered := make(map[string]string, len(headers))
	for name, value := range headers {
		lowered[strings.ToLower(name)] = strings.Join(strings.Fields(value), " ")
	}
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + lowered[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	bodyDigest := sha256.Sum256(body)
	canonicalRequest := strings.Join([]string{method, jdCloudCanonicalPath(path), jdCloudCanonicalQuery(query),
		canonicalHeaders.String(), signedHeaders, hex.EncodeToString(bodyDigest[:])}, "\n")
	date := at.UTC().Format("20060102")
	scope := date + "/" + region + "/" + service + "/jdcloud2_request"
	requestDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := jdCloudAlgorithm + "\n" + at.UTC().Format(jdCloudTimeLayout) + "\n" + scope + "\n" +
		hex.EncodeToString(requestDigest[:])
	key := []byte("JDCLOUD2" + accessKeySecret)
	for _, part := range []string{date, region, service, "jdcloud2_request"} {
		key = jdCloudHMAC(key, part)
	}
	return jdCloudAlgorithm + " Credential=" + accessKeyID + "/" + scope + ", SignedHeaders=" + signedHeaders +
		", Signature=" + hex.EncodeToString(jdCloudHMAC(key, stringToSign))
}

func jdCloudHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}
