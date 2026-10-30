package originauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func signRequest(rule CompiledRule, request *http.Request, now time.Time) error {
	if request == nil || request.URL == nil || (request.Method != http.MethodGet && request.Method != http.MethodHead) {
		return reject("METHOD_NOT_ALLOWED")
	}
	if request.Body != nil && request.Body != http.NoBody {
		return reject("BODY_NOT_ALLOWED")
	}
	if request.URL.Scheme != "https" || strings.ToLower(request.URL.Hostname()) != rule.Endpoint.Host ||
		(request.URL.Port() != "" && request.URL.Port() != "443") ||
		(request.Host != "" && strings.ToLower(strings.TrimSuffix(request.Host, ":443")) != rule.Endpoint.Host) {
		return reject("ENDPOINT_MISMATCH")
	}
	for name := range request.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" || strings.HasPrefix(lower, "x-amz-") || strings.HasPrefix(lower, "x-oss-") || strings.HasPrefix(lower, "x-cos-") {
			return reject("AUTH_HEADER_CONFLICT")
		}
	}
	path, err := canonicalPath(request.URL.EscapedPath())
	if err != nil || !pathWithin(path, rule.PathPrefix) {
		return reject("PATH_NOT_ALLOWED")
	}
	query, err := parseQuery(request.URL.RawQuery)
	if err != nil {
		return err
	}
	rangeValue, err := validateRange(request.Header.Values("Range"))
	if err != nil {
		return err
	}
	key := rule.CurrentKey
	if rule.PreviousKey != nil && now.Unix() < rule.ActivateCurrentAtUnix {
		key = *rule.PreviousKey
	}
	credential, err := loadCredential(rule.Provider, key, now.Unix())
	if err != nil {
		return err
	}
	defer clearCredential(&credential)
	if credential.ExpiresAtUnix <= now.Unix()+int64(rule.SignatureTTLSeconds) {
		return reject("CREDENTIAL_EXPIRES_TOO_SOON")
	}
	headers, err := signedHeaders(rule, request.Method, path, query, rangeValue, credential, now)
	if err != nil {
		return err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.Host = rule.Endpoint.Host
	request.Header.Set("Host", rule.Endpoint.Host)
	return nil
}

func pathWithin(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return strings.HasPrefix(path, prefix)
}

func signedHeaders(rule CompiledRule, method, path string, query []queryPair, rangeValue string, credential Credential, now time.Time) (map[string]string, error) {
	switch rule.Provider {
	case ProviderS3:
		return signS3(rule, method, path, query, rangeValue, credential, now)
	case ProviderOSS:
		return signOSS(rule, method, path, query, rangeValue, credential, now)
	case ProviderCOS:
		return signCOS(rule, method, path, query, rangeValue, credential, now)
	default:
		return nil, reject("PROVIDER_UNKNOWN")
	}
}

func signS3(rule CompiledRule, method, path string, query []queryPair, rangeValue string, credential Credential, now time.Time) (map[string]string, error) {
	datetime := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	headers := map[string]string{"host": rule.Endpoint.Host, "x-amz-content-sha256": emptySHA256, "x-amz-date": datetime}
	if rangeValue != "" {
		headers["range"] = rangeValue
	}
	if credential.SessionToken != "" {
		headers["x-amz-security-token"] = credential.SessionToken
	}
	canonical, names, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	request := method + "\n" + path + "\n" + canonicalQuery(query) + "\n" + canonical + "\n" + names + "\n" + emptySHA256
	scope := date + "/" + rule.Region + "/" + rule.Service + "/aws4_request"
	stringToSign := AlgorithmS3Header + "\n" + datetime + "\n" + scope + "\n" + sha256Hex(request)
	key := hmacSHA256([]byte("AWS4"+credential.SecretAccessKey), date)
	key = hmacSHA256(key, rule.Region)
	key = hmacSHA256(key, rule.Service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))
	result := exportHeaders(headers)
	result["Authorization"] = AlgorithmS3Header + " Credential=" + credential.AccessKeyID + "/" + scope + ", SignedHeaders=" + names + ", Signature=" + signature
	return result, nil
}

const AlgorithmS3Header = "AWS4-HMAC-SHA256"

func signOSS(rule CompiledRule, method, path string, query []queryPair, rangeValue string, credential Credential, now time.Time) (map[string]string, error) {
	datetime := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	headers := map[string]string{"host": rule.Endpoint.Host, "x-oss-content-sha256": "UNSIGNED-PAYLOAD", "x-oss-date": datetime}
	additional := []string{"host"}
	if rangeValue != "" {
		headers["range"] = rangeValue
		additional = append(additional, "range")
	}
	if credential.SessionToken != "" {
		headers["x-oss-security-token"] = credential.SessionToken
	}
	canonical, _, err := canonicalHeaders(headers)
	if err != nil {
		return nil, err
	}
	ossPath := "/" + rule.Bucket + path
	request := method + "\n" + ossPath + "\n" + canonicalOSSQuery(query) + "\n" + canonical + "\n" + strings.Join(additional, ";") + "\nUNSIGNED-PAYLOAD"
	scope := date + "/" + rule.Region + "/" + rule.Service + "/aliyun_v4_request"
	stringToSign := "OSS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + sha256Hex(request)
	key := hmacSHA256([]byte("aliyun_v4"+credential.SecretAccessKey), date)
	key = hmacSHA256(key, rule.Region)
	key = hmacSHA256(key, rule.Service)
	key = hmacSHA256(key, "aliyun_v4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))
	result := exportHeaders(headers)
	result["Authorization"] = "OSS4-HMAC-SHA256 Credential=" + credential.AccessKeyID + "/" + scope + ",AdditionalHeaders=" + strings.Join(additional, ";") + ",Signature=" + signature
	return result, nil
}

func signCOS(rule CompiledRule, method, path string, query []queryPair, rangeValue string, credential Credential, now time.Time) (map[string]string, error) {
	headers := map[string]string{"host": rule.Endpoint.Host}
	if rangeValue != "" {
		headers["range"] = rangeValue
	}
	if credential.SessionToken != "" {
		headers["x-cos-security-token"] = credential.SessionToken
	}
	authorization, err := cosAuthorization(method, path, query, headers, credential, now, rule.SignatureTTLSeconds)
	if err != nil {
		return nil, err
	}
	result := exportHeaders(headers)
	result["Authorization"] = authorization
	return result, nil
}

func cosAuthorization(method, path string, query []queryPair, headers map[string]string, credential Credential, now time.Time, ttlSeconds uint32) (string, error) {
	start := now.Unix()
	end := start + int64(ttlSeconds)
	keyTime := fmt.Sprintf("%d;%d", start, end)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	formatted := make([]string, 0, len(names))
	for _, name := range names {
		value, err := normalizedHeaderValue(headers[name])
		if err != nil {
			return "", err
		}
		formatted = append(formatted, strings.ToLower(percentEncode(name, false))+"="+percentEncode(value, false))
	}
	queryString, queryNames := cosCanonicalQuery(query)
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", reject("PATH_INVALID")
	}
	formatString := strings.ToLower(method) + "\n" + decodedPath + "\n" + queryString + "\n" + strings.Join(formatted, "&") + "\n"
	stringToSign := "sha1\n" + keyTime + "\n" + sha1Hex(formatString) + "\n"
	signKey := hex.EncodeToString(hmacSHA1([]byte(credential.SecretAccessKey), keyTime))
	signature := hex.EncodeToString(hmacSHA1([]byte(signKey), stringToSign))
	authorization := "q-sign-algorithm=sha1&q-ak=" + credential.AccessKeyID + "&q-sign-time=" + keyTime + "&q-key-time=" + keyTime +
		"&q-header-list=" + strings.Join(names, ";") + "&q-url-param-list=" + queryNames + "&q-signature=" + signature
	return authorization, nil
}

func exportHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers)+1)
	for name, value := range headers {
		result[http.CanonicalHeaderKey(name)] = value
	}
	return result
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func sha1Hex(value string) string {
	digest := sha1.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}

func hmacSHA256(key []byte, value string) []byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(value))
	return digest.Sum(nil)
}

func hmacSHA1(key []byte, value string) []byte {
	digest := hmac.New(sha1.New, key)
	_, _ = digest.Write([]byte(value))
	return digest.Sum(nil)
}
