package pluginwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MinimumSecretBytes = 32
	MaximumSecretBytes = 4096
	SignatureVersion   = "v1"
	SignatureVersionV2 = "v2"
)

type SignatureHeaders struct {
	Timestamp     string
	DeliveryID    string
	ContentSHA256 string
	Signature     string
}

type SignatureV2Headers struct {
	Timestamp        string
	EventID          string
	DeliveryID       string
	SecretVersionID  string
	ContentSHA256    string
	SignatureVersion string
	Signature        string
}

func Sign(secret []byte, timestamp time.Time, deliveryID uuid.UUID, body []byte) (SignatureHeaders, error) {
	if len(secret) < MinimumSecretBytes || len(secret) > MaximumSecretBytes || deliveryID == uuid.Nil || timestamp.IsZero() {
		return SignatureHeaders{}, ErrInvalidSecret
	}
	digest := sha256.Sum256(body)
	headers := SignatureHeaders{
		Timestamp: strconv.FormatInt(timestamp.Unix(), 10), DeliveryID: deliveryID.String(),
		ContentSHA256: hex.EncodeToString(digest[:]),
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(signaturePayload(headers))
	headers.Signature = SignatureVersion + "=" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return headers, nil
}

func SignV2(secret []byte, timestamp time.Time, escapedPath string, eventID, deliveryID, secretVersionID uuid.UUID, body []byte) (SignatureV2Headers, error) {
	if len(secret) < MinimumSecretBytes || len(secret) > MaximumSecretBytes || timestamp.IsZero() ||
		eventID == uuid.Nil || deliveryID == uuid.Nil || secretVersionID == uuid.Nil ||
		!validSignaturePath(escapedPath) {
		return SignatureV2Headers{}, ErrInvalidSecret
	}
	digest := sha256.Sum256(body)
	headers := SignatureV2Headers{
		Timestamp: strconv.FormatInt(timestamp.Unix(), 10), EventID: eventID.String(),
		DeliveryID: deliveryID.String(), SecretVersionID: secretVersionID.String(),
		ContentSHA256: hex.EncodeToString(digest[:]), SignatureVersion: SignatureVersionV2,
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(signaturePayloadV2(escapedPath, headers))
	headers.Signature = SignatureVersionV2 + "=" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return headers, nil
}

func Verify(secret []byte, now time.Time, tolerance time.Duration, headers SignatureHeaders, body []byte) error {
	if len(secret) < MinimumSecretBytes || len(secret) > MaximumSecretBytes || now.IsZero() || tolerance <= 0 {
		return ErrInvalidSecret
	}
	timestamp, err := strconv.ParseInt(headers.Timestamp, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	deliveryID, err := uuid.Parse(headers.DeliveryID)
	if err != nil || deliveryID == uuid.Nil {
		return ErrInvalidSignature
	}
	providedDigest, err := hex.DecodeString(headers.ContentSHA256)
	if err != nil || len(providedDigest) != sha256.Size {
		return ErrInvalidSignature
	}
	digest := sha256.Sum256(body)
	if !hmac.Equal(providedDigest, digest[:]) {
		return ErrInvalidSignature
	}
	prefix, encodedSignature, ok := strings.Cut(headers.Signature, "=")
	if !ok || prefix != SignatureVersion {
		return ErrInvalidSignature
	}
	providedSignature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(providedSignature) != sha256.Size {
		return ErrInvalidSignature
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(signaturePayload(headers))
	if !hmac.Equal(providedSignature, mac.Sum(nil)) {
		return ErrInvalidSignature
	}
	signedAt := time.Unix(timestamp, 0)
	if signedAt.Before(now.Add(-tolerance)) || signedAt.After(now.Add(tolerance)) {
		return ErrSignatureExpired
	}
	return nil
}

func signaturePayload(headers SignatureHeaders) []byte {
	return []byte("cdnca.webhook.signature/v1\n" + headers.Timestamp + "\n" + headers.DeliveryID + "\n" + headers.ContentSHA256)
}

func signaturePayloadV2(escapedPath string, headers SignatureV2Headers) []byte {
	return []byte(strings.Join([]string{
		"cdnca.webhook.signature/v2", "POST", escapedPath, headers.Timestamp, headers.EventID,
		headers.DeliveryID, headers.SecretVersionID, headers.ContentSHA256,
	}, "\n"))
}

func validSignaturePath(value string) bool {
	if len(value) < 1 || len(value) > 512 || value[0] != '/' {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == '\\' {
			return false
		}
	}
	return true
}
