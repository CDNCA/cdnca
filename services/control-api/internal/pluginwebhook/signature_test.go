package pluginwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHMACSignatureVectorAndVerification(t *testing.T) {
	t.Parallel()
	secret := []byte("0123456789abcdef0123456789abcdef")
	deliveryID := uuid.MustParse("018cc251-f400-7def-8000-000000000001")
	timestamp := time.Unix(1704067200, 0).UTC()
	body := []byte(`{"type":"example","token":"do-not-log"}`)
	headers, err := Sign(secret, timestamp, deliveryID, body)
	if err != nil {
		t.Fatal(err)
	}
	if headers.Timestamp != "1704067200" || headers.DeliveryID != deliveryID.String() ||
		headers.ContentSHA256 != "3a99123acb55cd2f63b9413a1d5f1bc8834c445a2bde7d1a458b8ffbd30dbe91" ||
		headers.Signature != "v1=y4w2sGp3ebYtrKIK8-rl5t9k2TlyDog4b71ObJWgvw4" {
		t.Fatalf("signature vector = %#v", headers)
	}
	if err := Verify(secret, timestamp.Add(30*time.Second), time.Minute, headers, body); err != nil {
		t.Fatalf("verify: %v", err)
	}

	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-2] ^= 1
	if err := Verify(secret, timestamp, time.Minute, headers, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered error = %v", err)
	}
	if err := Verify(secret, timestamp.Add(2*time.Minute), time.Minute, headers, body); !errors.Is(err, ErrSignatureExpired) {
		t.Fatalf("expired error = %v", err)
	}
}

func TestHMACV2SignatureUsesExactCanonicalRequestInput(t *testing.T) {
	t.Parallel()
	secret := []byte("0123456789abcdef0123456789abcdef")
	eventID := uuid.MustParse("018cc251-f400-7def-8000-000000000010")
	deliveryID := uuid.MustParse("018cc251-f400-7def-8000-000000000011")
	secretVersionID := uuid.MustParse("018cc251-f400-7def-8000-000000000012")
	timestamp := time.Unix(1704067200, 0).UTC()
	body := []byte(`{"specversion":"1.0","data":{"test":true}}`)
	escapedPath := "/hooks/%7Etenant"
	headers, err := SignV2(secret, timestamp, escapedPath, eventID, deliveryID, secretVersionID, body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	payload := strings.Join([]string{
		"cdnca.webhook.signature/v2", "POST", escapedPath, strconv.FormatInt(timestamp.Unix(), 10),
		eventID.String(), deliveryID.String(), secretVersionID.String(), hex.EncodeToString(digest[:]),
	}, "\n")
	if strings.HasSuffix(payload, "\n") {
		t.Fatal("v2 signature payload has a trailing LF")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	wantSignature := "v2=" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if headers.Timestamp != "1704067200" || headers.EventID != eventID.String() ||
		headers.DeliveryID != deliveryID.String() || headers.SecretVersionID != secretVersionID.String() ||
		headers.ContentSHA256 != hex.EncodeToString(digest[:]) || headers.SignatureVersion != "v2" ||
		headers.Signature != wantSignature || len(strings.TrimPrefix(headers.Signature, "v2=")) != 43 {
		t.Fatalf("v2 signature = %#v want %q", headers, wantSignature)
	}
}

func TestHMACRejectsWeakSecretAndMalformedHeaders(t *testing.T) {
	t.Parallel()
	deliveryID := uuid.MustParse("018cc251-f400-7def-8000-000000000001")
	if _, err := Sign([]byte("short"), time.Now(), deliveryID, []byte(`{}`)); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("weak secret error = %v", err)
	}
	if _, err := Sign(make([]byte, MaximumSecretBytes+1), time.Now(), deliveryID, []byte(`{}`)); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("oversized secret error = %v", err)
	}
	headers := SignatureHeaders{Timestamp: "not-a-time", DeliveryID: deliveryID.String(), ContentSHA256: "bad", Signature: "v1=bad"}
	if err := Verify([]byte("0123456789abcdef0123456789abcdef"), time.Now(), time.Minute, headers, []byte(`{}`)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("malformed error = %v", err)
	}
}
