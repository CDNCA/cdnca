package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

const maximumProviderResponseBytes int64 = 64 << 10

var (
	providerExternalIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$`)
	providerEventIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$`)
	providerNoncePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)
	providerKeyIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	providerFailureCodePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	providerObjectVersionPattern = regexp.MustCompile(`^[!#-~]{1,512}$`)
	providerBucketPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	providerRegionPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
)

type HTTPSKYCProviderConfig struct {
	Name               string
	Endpoint           string
	APIKey             []byte
	CallbackKeyID      string
	CallbackHMACKey    []byte
	CallbackMaxAge     time.Duration
	CallbackFutureSkew time.Duration
	RequestTimeout     time.Duration
}

type HTTPSKYCProvider struct {
	mu            sync.RWMutex
	name          string
	endpoint      *url.URL
	apiKey        []byte
	callbackKeyID string
	callbackKey   []byte
	maxAge        time.Duration
	futureSkew    time.Duration
	client        *http.Client
	now           func() time.Time
	closed        bool
}

func NewHTTPSKYCProvider(config HTTPSKYCProviderConfig, client *http.Client, now func() time.Time) (*HTTPSKYCProvider, error) {
	endpoint, err := validateKYCProviderEndpoint(config.Endpoint)
	if err != nil || !resolverNamePattern.MatchString(config.Name) || len(config.APIKey) < 16 || len(config.APIKey) > 512 ||
		!providerKeyIDPattern.MatchString(config.CallbackKeyID) || len(config.CallbackHMACKey) < 32 || len(config.CallbackHMACKey) > 128 ||
		config.CallbackMaxAge <= 0 || config.CallbackMaxAge > time.Hour || config.CallbackFutureSkew < 0 || config.CallbackFutureSkew > 5*time.Minute || now == nil {
		return nil, ErrProviderInvalid
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > 30*time.Second {
		return nil, ErrProviderInvalid
	}
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.Timeout = config.RequestTimeout
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPSKYCProvider{name: config.Name, endpoint: endpoint, apiKey: bytes.Clone(config.APIKey),
		callbackKeyID: config.CallbackKeyID, callbackKey: bytes.Clone(config.CallbackHMACKey), maxAge: config.CallbackMaxAge,
		futureSkew: config.CallbackFutureSkew, client: &clone, now: now}, nil
}

func (provider *HTTPSKYCProvider) Configured() bool {
	if provider == nil {
		return false
	}
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	return provider != nil && !provider.closed &&
		provider.endpoint != nil && len(provider.apiKey) >= 16 && len(provider.callbackKey) >= 32 && provider.client != nil && provider.now != nil
}
func (provider *HTTPSKYCProvider) Name() string {
	if provider == nil {
		return ""
	}
	return provider.name
}
func (provider *HTTPSKYCProvider) Close() {
	if provider == nil {
		return
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	clear(provider.apiKey)
	clear(provider.callbackKey)
	provider.apiKey = nil
	provider.callbackKey = nil
	provider.closed = true
}

func (provider *HTTPSKYCProvider) CreateSession(ctx context.Context, request ProviderSessionCreate) (ProviderSessionCreated, error) {
	if !provider.Configured() || ctx == nil || request.LocalSessionID == uuid.Nil || request.TenantScopeID == uuid.Nil ||
		request.ActorUserID == uuid.Nil || !validKind(request.Kind) || !metadataPattern.MatchString(request.ProviderRequestID) || request.ExpiresAt.IsZero() {
		return ProviderSessionCreated{}, ErrProviderInvalid
	}
	payload := struct {
		SessionID     string `json:"session_id"`
		TenantScopeID string `json:"tenant_scope_id"`
		ActorUserID   string `json:"actor_user_id"`
		Kind          string `json:"kind"`
		RequestID     string `json:"request_id"`
		ExpiresAt     string `json:"expires_at"`
	}{
		request.LocalSessionID.String(), request.TenantScopeID.String(), request.ActorUserID.String(), request.Kind,
		request.ProviderRequestID, request.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	body, err := json.Marshal(payload)
	if err != nil {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	provider.mu.RLock()
	endpoint := *provider.endpoint
	apiKey := bytes.Clone(provider.apiKey)
	provider.mu.RUnlock()
	defer clear(apiKey)
	endpoint.Path = "/v1/sessions"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(apiKey))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Idempotency-Key", request.ProviderRequestID)
	httpRequest.Header.Set("Accept", "application/json")
	response, err := provider.client.Do(httpRequest)
	if err != nil {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Body, maximumProviderResponseBytes+1))
	if err != nil || len(wire) > int(maximumProviderResponseBytes) || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	if mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	_, signatureDigest, keyID, err := provider.verifySignedWire(response.Header, wire)
	if err != nil {
		return ProviderSessionCreated{}, err
	}
	var decoded struct {
		ExternalSessionID string `json:"external_session_id"`
		State             string `json:"state"`
	}
	if decodeStrictJSON(wire, &decoded) != nil || !providerExternalIDPattern.MatchString(decoded.ExternalSessionID) || decoded.State != ProviderSessionPending {
		return ProviderSessionCreated{}, ErrProviderUnavailable
	}
	return ProviderSessionCreated{ExternalSessionID: decoded.ExternalSessionID, State: decoded.State, ResponseSHA256: sha256.Sum256(wire),
		SignatureSHA256: signatureDigest, VerificationKeyID: keyID}, nil
}

func (provider *HTTPSKYCProvider) VerifyCallback(ctx context.Context, envelope ProviderCallbackEnvelope) (VerifiedProviderCallback, error) {
	if !provider.Configured() || ctx == nil || envelope.Provider != provider.name || len(envelope.Body) == 0 || len(envelope.Body) > int(maximumProviderResponseBytes) {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	mediaType, parameters, err := mime.ParseMediaType(envelope.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	_, signatureDigest, keyID, err := provider.verifySignedWire(envelope.Header, envelope.Body)
	if err != nil {
		return VerifiedProviderCallback{}, err
	}
	var body struct {
		EventID                string `json:"event_id"`
		SessionID              string `json:"session_id"`
		ExternalSessionID      string `json:"external_session_id"`
		State                  string `json:"state"`
		FailureCode            string `json:"failure_code"`
		OccurredAt             string `json:"occurred_at"`
		SubjectFingerprint     string `json:"subject_fingerprint"`
		OrganizationName       string `json:"organization_name"`
		LegalPersonFingerprint string `json:"legal_person_fingerprint"`
		AgentFingerprint       string `json:"agent_fingerprint"`
		AgentRelationship      string `json:"agent_relationship"`
	}
	if decodeStrictJSON(envelope.Body, &body) != nil {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	sessionID, err := uuid.Parse(body.SessionID)
	if err != nil || sessionID == uuid.Nil || sessionID.String() != body.SessionID {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, body.OccurredAt)
	if err != nil || occurredAt.Format(time.RFC3339Nano) != body.OccurredAt {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	nonce, ok := singleProviderHeader(envelope.Header, "X-KYC-Nonce")
	if !ok {
		return VerifiedProviderCallback{}, ErrProviderCallbackAuth
	}
	result := VerifiedProviderCallback{Provider: provider.name, EventID: body.EventID, Nonce: nonce, SessionID: sessionID,
		ExternalSessionID: body.ExternalSessionID, State: body.State, FailureCode: body.FailureCode, OccurredAt: occurredAt.UTC(),
		ReceivedAt: provider.now().UTC().Truncate(time.Microsecond), PayloadSHA256: sha256.Sum256(envelope.Body),
		SignatureSHA256: signatureDigest, VerificationKeyID: keyID, OrganizationName: body.OrganizationName, AgentRelationship: body.AgentRelationship}
	if result.SubjectFingerprint, err = decodeProviderDigest(body.SubjectFingerprint, body.State == ProviderSessionSucceeded); err != nil {
		return VerifiedProviderCallback{}, err
	}
	if result.LegalPersonFingerprint, err = decodeProviderDigest(body.LegalPersonFingerprint, false); err != nil {
		return VerifiedProviderCallback{}, err
	}
	if result.AgentFingerprint, err = decodeProviderDigest(body.AgentFingerprint, false); err != nil {
		return VerifiedProviderCallback{}, err
	}
	return result, nil
}

func (provider *HTTPSKYCProvider) verifySignedWire(header http.Header, body []byte) (time.Time, [sha256.Size]byte, string, error) {
	timestamp, ok := singleProviderHeader(header, "X-KYC-Timestamp")
	if !ok {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	nonce, ok := singleProviderHeader(header, "X-KYC-Nonce")
	if !ok || !providerNoncePattern.MatchString(nonce) {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	keyID, ok := singleProviderHeader(header, "X-KYC-Key-ID")
	if !ok || keyID != provider.callbackKeyID {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	rawSignature, ok := singleProviderHeader(header, "X-KYC-Signature")
	if !ok {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(rawSignature)
	if err != nil || len(signature) != sha256.Size || base64.StdEncoding.EncodeToString(signature) != rawSignature {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != timestamp {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	signedAt := time.Unix(seconds, 0).UTC()
	now := provider.now().UTC()
	if signedAt.Before(now.Add(-provider.maxAge)) || signedAt.After(now.Add(provider.futureSkew)) {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	provider.mu.RLock()
	key := bytes.Clone(provider.callbackKey)
	provider.mu.RUnlock()
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(timestamp + "\n" + nonce + "\n"))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return time.Time{}, [sha256.Size]byte{}, "", ErrProviderCallbackAuth
	}
	return signedAt, sha256.Sum256(signature), keyID, nil
}

func validateKYCProviderEndpoint(raw string) (*url.URL, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return nil, ErrProviderInvalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, ErrProviderInvalid
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		net.ParseIP(host) != nil || strings.Contains(host, "%") || strings.HasSuffix(host, ".") {
		return nil, ErrProviderInvalid
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return nil, ErrProviderInvalid
		}
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, ErrProviderInvalid
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed, nil
}

type S3PrivateObjectStoreConfig struct {
	Endpoint       string
	Region         string
	Bucket         string
	Prefix         string
	Credentials    aws.CredentialsProvider
	RequestTimeout time.Duration
	MaxAttempts    int
}
type kycS3API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}
type kycS3Presigner interface {
	PresignPutObject(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

type S3PrivateObjectStore struct {
	client       kycS3API
	presigner    kycS3Presigner
	bucket       string
	prefix       string
	endpointHost string
	now          func() time.Time
	configured   bool
}

func NewS3PrivateObjectStore(config S3PrivateObjectStoreConfig, client *http.Client, now func() time.Time) (*S3PrivateObjectStore, error) {
	endpoint, err := validateKYCProviderEndpoint(config.Endpoint)
	if err != nil || !providerRegionPattern.MatchString(config.Region) ||
		!validProviderBucket(config.Bucket) || !validProviderPrefix(config.Prefix) || config.Credentials == nil || now == nil {
		return nil, ErrProviderInvalid
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.RequestTimeout < time.Second || config.RequestTimeout > 30*time.Second {
		return nil, ErrProviderInvalid
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 3
	}
	if config.MaxAttempts < 1 || config.MaxAttempts > 5 {
		return nil, ErrProviderInvalid
	}
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.Timeout = config.RequestTimeout
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	awsConfig := aws.Config{Region: config.Region, Credentials: aws.NewCredentialsCache(config.Credentials), HTTPClient: &clone,
		Retryer: func() aws.Retryer {
			return awsretry.NewStandard(func(options *awsretry.StandardOptions) { options.MaxAttempts = config.MaxAttempts })
		}}
	s3Client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint.String())
		options.UsePathStyle = true
	})
	return &S3PrivateObjectStore{client: s3Client, presigner: s3.NewPresignClient(s3Client), bucket: config.Bucket,
		prefix: config.Prefix, endpointHost: endpoint.Host, now: now, configured: true}, nil
}
func (store *S3PrivateObjectStore) Configured() bool {
	return store != nil && store.configured && store.client != nil && store.presigner != nil && store.bucket != ""
}
func (store *S3PrivateObjectStore) PresignPut(ctx context.Context, request PrivateObjectPresignRequest) (PrivateObjectPresignResult, error) {
	if !store.Configured() || ctx == nil || !validPrivateObjectPresign(request, store.now()) {
		return PrivateObjectPresignResult{}, ErrProviderInvalid
	}
	key, err := store.key(request.ObjectKey)
	if err != nil {
		return PrivateObjectPresignResult{}, err
	}
	checksum := base64.StdEncoding.EncodeToString(request.SHA256[:])
	expires := request.ExpiresAt.Sub(store.now())
	if expires <= 0 || expires > time.Hour {
		return PrivateObjectPresignResult{}, ErrProviderInvalid
	}
	output, err := store.presigner.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key),
		ContentLength: aws.Int64(request.SizeBytes), ContentType: aws.String(request.ContentType), ChecksumSHA256: aws.String(checksum),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(request.EncryptionKeyID),
		Metadata: map[string]string{"cdnca-object-key": request.ObjectKey, "cdnca-sha256": fmt.Sprintf("%x", request.SHA256),
			"cdnca-size": strconv.FormatInt(request.SizeBytes, 10), "cdnca-content-type": request.ContentType,
			"cdnca-encryption-key-id": request.EncryptionKeyID}}, func(options *s3.PresignOptions) { options.Expires = expires })
	if err != nil || output == nil {
		return PrivateObjectPresignResult{}, ErrProviderObjectUnavailable
	}
	parsed, err := url.Parse(output.URL)
	if err != nil || parsed.Scheme != "https" || !strings.EqualFold(parsed.Host, store.endpointHost) {
		return PrivateObjectPresignResult{}, ErrProviderObjectUnavailable
	}
	headers := make(map[string]string, len(output.SignedHeader))
	for name, values := range output.SignedHeader {
		if len(values) != 1 {
			return PrivateObjectPresignResult{}, ErrProviderObjectUnavailable
		}
		headers[name] = values[0]
	}
	return PrivateObjectPresignResult{URL: output.URL, RequiredHeaders: headers}, nil
}
func (store *S3PrivateObjectStore) Stat(ctx context.Context, objectKey string) (PrivateObjectReference, error) {
	if !store.Configured() || ctx == nil {
		return PrivateObjectReference{}, ErrProviderObjectUnavailable
	}
	key, err := store.key(objectKey)
	if err != nil {
		return PrivateObjectReference{}, err
	}
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil || output == nil {
		return PrivateObjectReference{}, mapProviderS3Error(err)
	}
	if output.VersionId == nil || !providerObjectVersionPattern.MatchString(*output.VersionId) || output.ChecksumSHA256 == nil || output.ContentLength == nil || output.ContentType == nil {
		return PrivateObjectReference{}, ErrProviderObjectMismatch
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(*output.ChecksumSHA256)
	if err != nil || len(digest) != sha256.Size {
		return PrivateObjectReference{}, ErrProviderObjectMismatch
	}
	metadata := output.Metadata
	if metadata["cdnca-object-key"] != objectKey || metadata["cdnca-content-type"] != *output.ContentType ||
		metadata["cdnca-size"] != strconv.FormatInt(*output.ContentLength, 10) || metadata["cdnca-encryption-key-id"] == "" ||
		metadata["cdnca-sha256"] != fmt.Sprintf("%x", digest) {
		return PrivateObjectReference{}, ErrProviderObjectMismatch
	}
	return PrivateObjectReference{ObjectKey: objectKey, ObjectVersion: *output.VersionId, SHA256: bytesToDigest(digest),
		SizeBytes: *output.ContentLength, ContentType: *output.ContentType, EncryptionKeyID: metadata["cdnca-encryption-key-id"]}, nil
}
func (store *S3PrivateObjectStore) Delete(ctx context.Context, reference PrivateObjectReference) (PrivateObjectDeleteReceipt, error) {
	if !store.Configured() || ctx == nil || reference.ObjectVersion == "" {
		return PrivateObjectDeleteReceipt{}, ErrProviderInvalid
	}
	key, err := store.key(reference.ObjectKey)
	if err != nil {
		return PrivateObjectDeleteReceipt{}, err
	}
	output, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key), VersionId: aws.String(reference.ObjectVersion)})
	if err != nil {
		return PrivateObjectDeleteReceipt{}, mapProviderS3Error(err)
	}
	if output == nil {
		return PrivateObjectDeleteReceipt{}, ErrProviderObjectUnavailable
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(reference.ObjectKey))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(reference.ObjectVersion))
	if output.VersionId != nil {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(*output.VersionId))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return PrivateObjectDeleteReceipt{ReceiptSHA256: digest}, nil
}
func (store *S3PrivateObjectStore) key(objectKey string) (string, error) {
	if !validProviderObjectKey(objectKey) {
		return "", ErrProviderInvalid
	}
	if store.prefix == "" {
		return objectKey, nil
	}
	return store.prefix + "/" + objectKey, nil
}

func validPrivateObjectPresign(request PrivateObjectPresignRequest, now time.Time) bool {
	return validProviderObjectKey(request.ObjectKey) && request.SHA256 != ([sha256.Size]byte{}) &&
		request.SizeBytes > 0 && request.SizeBytes <= maximumProviderMaterialBytes && validMIME(request.ContentType) && evidenceKeyIDPattern.MatchString(request.EncryptionKeyID) && request.ExpiresAt.After(now)
}
func validProviderObjectKey(value string) bool {
	if len(value) < 1 || len(value) > 512 || strings.ContainsAny(value, "\\%?#\x00") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return strings.HasPrefix(value, "identity-verification/")
}
func validProviderBucket(value string) bool {
	if !providerBucketPattern.MatchString(value) || strings.Contains(value, "..") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
func validProviderPrefix(value string) bool {
	return value == "" || validProviderObjectKey("identity-verification/"+value) && !strings.Contains(value, "/")
}
func mapProviderS3Error(err error) error {
	if err == nil {
		return ErrProviderObjectUnavailable
	}
	var response interface{ HTTPStatusCode() int }
	if errors.As(err, &response) {
		if response.HTTPStatusCode() == http.StatusNotFound {
			return ErrProviderObjectMismatch
		}
	}
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "NoSuchKey" {
		return ErrProviderObjectMismatch
	}
	return ErrProviderObjectUnavailable
}
func singleProviderHeader(header http.Header, name string) (string, bool) {
	values := make([]string, 0, 1)
	for candidate, candidateValues := range header {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != "" && len(returnValue) <= 1024 && strings.TrimSpace(returnValue) == returnValue
}
func decodeStrictJSON(value []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrProviderInvalid
	}
	return nil
}
func decodeProviderDigest(raw string, required bool) ([sha256.Size]byte, error) {
	if raw == "" && !required {
		return [sha256.Size]byte{}, nil
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return [sha256.Size]byte{}, ErrProviderCallbackAuth
	}
	return bytesToDigest(decoded), nil
}
