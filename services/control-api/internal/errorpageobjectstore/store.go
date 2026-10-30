package errorpageobjectstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

const (
	metadataSHA256        = "cdnca-sha256"
	metadataSize          = "cdnca-size"
	metadataMIME          = "cdnca-mime"
	metadataToken         = "cdnca-token"
	metadataObjectKey     = "cdnca-object-key"
	metadataSourceID      = "cdnca-source-id"
	metadataSourceKey     = "cdnca-source-key"
	metadataSourceETag    = "cdnca-source-etag"
	metadataSourceVersion = "cdnca-source-version"
)

var (
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	etagPattern    = regexp.MustCompile(`^"[a-fA-F0-9]{32}"$`)
	versionPattern = regexp.MustCompile(`^[\x21-\x7e]+$`)

	errCredentials = errors.New("explicit object store credentials unavailable")
)

type s3API interface {
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
}

type Store struct {
	client         s3API
	bucket         string
	prefix         string
	maxSize        int64
	cleanupTimeout time.Duration
	ready          atomic.Bool
	readyMu        sync.Mutex
}

var _ errorpagecontrol.ContentStore = (*Store)(nil)

func New(ctx context.Context, config Config) (*Store, error) {
	validated, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	awsConfig := aws.Config{
		Region:      validated.Region,
		Credentials: aws.NewCredentialsCache(validatingCredentials{provider: validated.Credentials}),
		Retryer: func() aws.Retryer {
			return awsretry.NewStandard(func(options *awsretry.StandardOptions) {
				options.MaxAttempts = validated.MaxAttempts
			})
		},
	}
	httpClient := newHTTPClient(validated)
	awsConfig.HTTPClient = httpClient
	client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(validated.endpoint.String())
		options.UsePathStyle = true
	})
	store := &Store{
		client: client, bucket: validated.Bucket, prefix: validated.Prefix,
		maxSize: validated.MaxObjectSize, cleanupTimeout: validated.RequestTimeout,
	}
	if err := store.Ready(ctx); err != nil {
		httpClient.CloseIdleConnections()
		return nil, err
	}
	return store, nil
}

func (store *Store) Capabilities() errorpagecontrol.ObjectStoreCapabilities {
	if store == nil || !store.ready.Load() {
		return errorpagecontrol.ObjectStoreCapabilities{}
	}
	return errorpagecontrol.ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
}

func (store *Store) Ready(ctx context.Context) error {
	if store == nil {
		return fmt.Errorf("ready: %w", errorpagecontrol.ErrUnavailable)
	}
	store.readyMu.Lock()
	defer store.readyMu.Unlock()
	store.ready.Store(false)
	if contextErr := contextError(ctx.Err()); contextErr != nil {
		return contextErr
	}
	if store.client == nil {
		return fmt.Errorf("ready: %w", errorpagecontrol.ErrUnavailable)
	}
	versioning, err := store.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(store.bucket)})
	if contextErr := contextError(ctx.Err()); contextErr != nil {
		return contextErr
	}
	if err != nil {
		return mapS3Error("verify bucket versioning", err)
	}
	if versioning == nil || versioning.Status != types.BucketVersioningStatusEnabled {
		return fmt.Errorf("verify bucket versioning: %w", errorpagecontrol.ErrUnavailable)
	}
	if err := store.probe(ctx); err != nil {
		return err
	}
	store.ready.Store(true)
	return nil
}

func (store *Store) PutStaging(ctx context.Context, ref errorpagecontrol.ObjectRef, body []byte, mimeType string) (errorpagecontrol.ObjectInfo, error) {
	if err := store.requireReady(); err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	return store.putStaging(ctx, ref, body, mimeType)
}

func (store *Store) Open(ctx context.Context, ref errorpagecontrol.ObjectRef, immutableToken string) (io.ReadCloser, error) {
	if contextErr := contextError(ctx.Err()); contextErr != nil {
		return nil, contextErr
	}
	if err := store.requireReady(); err != nil {
		return nil, err
	}
	return store.open(ctx, ref, immutableToken)
}

func (store *Store) Finalize(ctx context.Context, stagingRef, objectRef errorpagecontrol.ObjectRef, expected errorpagecontrol.ObjectInfo) (errorpagecontrol.ObjectInfo, error) {
	if err := store.requireReady(); err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	return store.finalize(ctx, stagingRef, objectRef, expected)
}

func (store *Store) Stat(ctx context.Context, ref errorpagecontrol.ObjectRef) (errorpagecontrol.ObjectInfo, error) {
	if err := store.requireReady(); err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	state, err := store.stat(ctx, ref)
	return state.info, err
}

func (store *Store) Delete(ctx context.Context, ref errorpagecontrol.ObjectRef) error {
	if err := store.requireReady(); err != nil {
		return err
	}
	return store.delete(ctx, ref)
}

func (store *Store) putStaging(ctx context.Context, ref errorpagecontrol.ObjectRef, body []byte, mimeType string) (errorpagecontrol.ObjectInfo, error) {
	fullKey, err := store.canonicalKey(ref)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	expected, checksum, err := store.objectInfo(body, mimeType)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	sourceID, err := randomSourceID()
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, fmt.Errorf("create staging identity: %w", errorpagecontrol.ErrUnavailable)
	}
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(fullKey), Body: bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String(mimeType),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(checksum),
		IfNoneMatch: aws.String("*"), Metadata: objectMetadata(expected, fullKey, objectSource{id: sourceID}),
	})
	if err != nil {
		mapped := mapS3Error("put immutable staging object", err)
		if !errors.Is(mapped, errorpagecontrol.ErrConflict) {
			return errorpagecontrol.ObjectInfo{}, mapped
		}
	}
	state, statErr := store.statKey(ctx, fullKey)
	if statErr != nil {
		if err != nil && errors.Is(statErr, errorpagecontrol.ErrObjectNotFound) {
			return errorpagecontrol.ObjectInfo{}, fmt.Errorf("put immutable staging object: %w", errorpagecontrol.ErrConflict)
		}
		return errorpagecontrol.ObjectInfo{}, statErr
	}
	if state.info != expected {
		return errorpagecontrol.ObjectInfo{}, fmt.Errorf("put immutable staging object: %w", errorpagecontrol.ErrConflict)
	}
	return state.info, nil
}

func (store *Store) open(ctx context.Context, ref errorpagecontrol.ObjectRef, immutableToken string) (io.ReadCloser, error) {
	fullKey, err := store.canonicalKey(ref)
	if err != nil {
		return nil, err
	}
	if !validToken(immutableToken) {
		return nil, fmt.Errorf("open immutable object: %w", errorpagecontrol.ErrConflict)
	}
	state, err := store.statKey(ctx, fullKey)
	if err != nil {
		return nil, err
	}
	if state.info.ImmutableToken != immutableToken {
		return nil, fmt.Errorf("open immutable object: %w", errorpagecontrol.ErrConflict)
	}
	output, err := store.getBoundObject(ctx, fullKey, state, "get immutable object")
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()
	returned, err := stateFromGet(output, store.maxSize, fullKey)
	if err != nil || returned != state {
		return nil, fmt.Errorf("get immutable object metadata: %w", errorpagecontrol.ErrConflict)
	}
	body, readErr := io.ReadAll(io.LimitReader(output.Body, state.info.Size+1))
	if contextErr := contextError(readErr); contextErr != nil {
		return nil, contextErr
	}
	digest := sha256.Sum256(body)
	if int64(len(body)) != state.info.Size || hex.EncodeToString(digest[:]) != state.info.SHA256 {
		return nil, fmt.Errorf("read immutable object: %w", errorpagecontrol.ErrConflict)
	}
	if readErr != nil {
		return nil, fmt.Errorf("read immutable object: %w", errorpagecontrol.ErrUnavailable)
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (store *Store) finalize(ctx context.Context, stagingRef, objectRef errorpagecontrol.ObjectRef, expected errorpagecontrol.ObjectInfo) (errorpagecontrol.ObjectInfo, error) {
	stagingKey, err := store.canonicalKey(stagingRef)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	objectKey, err := store.canonicalKey(objectRef)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	if stagingKey == objectKey || !sameObjectScope(stagingRef, objectRef) || !validObjectInfo(expected, store.maxSize) {
		return errorpagecontrol.ObjectInfo{}, ErrInvalidObject
	}
	staging, err := store.statKey(ctx, stagingKey)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	if staging.info != expected {
		return errorpagecontrol.ObjectInfo{}, fmt.Errorf("finalize staging metadata: %w", errorpagecontrol.ErrConflict)
	}
	source := staging.source
	source.key, source.versionID, source.etag = stagingKey, staging.versionID, staging.etag
	body, err := store.readStateContent(ctx, stagingKey, staging)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, err
	}
	checksum, err := checksumFromSHA256(expected.SHA256)
	if err != nil {
		return errorpagecontrol.ObjectInfo{}, ErrInvalidObject
	}
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(objectKey), Body: bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String(expected.MIMEType),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(checksum),
		IfNoneMatch: aws.String("*"), Metadata: objectMetadata(expected, objectKey, source),
	})
	if err != nil {
		mapped := mapS3Error("conditionally create finalized object", err)
		if !errors.Is(mapped, errorpagecontrol.ErrConflict) {
			return errorpagecontrol.ObjectInfo{}, mapped
		}
	}
	final, finalErr := store.statKey(ctx, objectKey)
	if finalErr != nil {
		if err != nil && errors.Is(finalErr, errorpagecontrol.ErrObjectNotFound) {
			return errorpagecontrol.ObjectInfo{}, fmt.Errorf("conditionally create finalized object: %w", errorpagecontrol.ErrConflict)
		}
		return errorpagecontrol.ObjectInfo{}, finalErr
	}
	if final.info != expected || final.source != source {
		return errorpagecontrol.ObjectInfo{}, fmt.Errorf("finalized object metadata: %w", errorpagecontrol.ErrConflict)
	}
	stagingAfter, err := store.statKey(ctx, stagingKey)
	if err != nil || stagingAfter != staging {
		return errorpagecontrol.ObjectInfo{}, fmt.Errorf("verify preserved staging alias: %w", errorpagecontrol.ErrConflict)
	}
	return final.info, nil
}

func (store *Store) stat(ctx context.Context, ref errorpagecontrol.ObjectRef) (objectState, error) {
	key, err := store.canonicalKey(ref)
	if err != nil {
		return objectState{}, err
	}
	return store.statKey(ctx, key)
}

func (store *Store) statKey(ctx context.Context, key string) (objectState, error) {
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		return objectState{}, mapS3Error("stat object", err)
	}
	if output == nil {
		return objectState{}, fmt.Errorf("stat object metadata: %w", errorpagecontrol.ErrConflict)
	}
	if aws.ToString(output.ChecksumSHA256) == "" {
		return store.statKeyByContent(ctx, key, output)
	}
	state, err := stateFromHead(output, store.maxSize, key)
	if err != nil {
		return objectState{}, fmt.Errorf("stat object metadata: %w", errorpagecontrol.ErrConflict)
	}
	return state, nil
}

func (store *Store) statKeyByContent(ctx context.Context, key string, head *s3.HeadObjectOutput) (objectState, error) {
	checksum, err := checksumFromMetadata(head.Metadata)
	if err != nil {
		return objectState{}, fmt.Errorf("stat object metadata: %w", errorpagecontrol.ErrConflict)
	}
	state, err := makeObjectState(aws.ToInt64(head.ContentLength), aws.ToString(head.ContentType), head.Metadata,
		checksum, aws.ToString(head.ETag), aws.ToString(head.VersionId), store.maxSize, key)
	if err != nil {
		return objectState{}, fmt.Errorf("stat object metadata: %w", errorpagecontrol.ErrConflict)
	}
	if _, err := store.readStateContent(ctx, key, state); err != nil {
		return objectState{}, err
	}
	return state, nil
}

func (store *Store) readStateContent(ctx context.Context, key string, state objectState) ([]byte, error) {
	checksum, err := checksumFromSHA256(state.info.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify object metadata: %w", errorpagecontrol.ErrConflict)
	}
	output, err := store.getBoundObject(ctx, key, state, "verify object content")
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()
	returnedChecksum := aws.ToString(output.ChecksumSHA256)
	if returnedChecksum == "" {
		returnedChecksum = checksum
	}
	returned, err := makeObjectState(aws.ToInt64(output.ContentLength), aws.ToString(output.ContentType), output.Metadata,
		returnedChecksum, aws.ToString(output.ETag), aws.ToString(output.VersionId), store.maxSize, key)
	if err != nil || returned != state {
		return nil, fmt.Errorf("verify object metadata: %w", errorpagecontrol.ErrConflict)
	}
	body, readErr := io.ReadAll(io.LimitReader(output.Body, state.info.Size+1))
	if contextErr := contextError(readErr); contextErr != nil {
		return nil, contextErr
	}
	digest := sha256.Sum256(body)
	if int64(len(body)) != state.info.Size || hex.EncodeToString(digest[:]) != state.info.SHA256 {
		return nil, fmt.Errorf("verify object content: %w", errorpagecontrol.ErrConflict)
	}
	if readErr != nil {
		return nil, fmt.Errorf("verify object content: %w", errorpagecontrol.ErrUnavailable)
	}
	return body, nil
}

func (store *Store) getBoundObject(ctx context.Context, key string, state objectState, operation string) (*s3.GetObjectOutput, error) {
	output, err := store.client.GetObject(ctx, store.boundGetInput(key, state))
	if contextErr := contextError(ctx.Err()); contextErr != nil {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		return nil, contextErr
	}
	if err != nil {
		return nil, mapS3Error(operation, err)
	}
	if output == nil || output.Body == nil {
		return nil, fmt.Errorf("%s: %w", operation, errorpagecontrol.ErrConflict)
	}
	return output, nil
}

func (store *Store) boundGetInput(key string, state objectState) *s3.GetObjectInput {
	return &s3.GetObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key), VersionId: aws.String(state.versionID),
		IfMatch: aws.String(state.etag), ChecksumMode: types.ChecksumModeEnabled,
	}
}

func checksumFromMetadata(metadata map[string]string) (string, error) {
	return checksumFromSHA256(metadata[metadataSHA256])
}

func checksumFromSHA256(sha string) (string, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != sha256.Size {
		return "", ErrInvalidObject
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}

func (store *Store) delete(ctx context.Context, ref errorpagecontrol.ObjectRef) error {
	key, err := store.canonicalKey(ref)
	if err != nil {
		return err
	}
	if _, err := store.statKey(ctx, key); err != nil {
		return err
	}
	_, err = store.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		mapped := mapS3Error("delete object", err)
		if contextError(mapped) != nil {
			return mapped
		}
		if _, statErr := store.statKey(ctx, key); errors.Is(statErr, errorpagecontrol.ErrObjectNotFound) {
			return nil
		}
		return mapped
	}
	if _, err := store.statKey(ctx, key); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		if err != nil {
			return err
		}
		return fmt.Errorf("delete object: %w", errorpagecontrol.ErrConflict)
	}
	return nil
}

func (store *Store) probe(ctx context.Context) (resultErr error) {
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return fmt.Errorf("generate readiness probe: %w", errorpagecontrol.ErrUnavailable)
	}
	tenantID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("generate readiness tenant: %w", errorpagecontrol.ErrUnavailable)
	}
	scopeID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("generate readiness scope: %w", errorpagecontrol.ErrUnavailable)
	}
	base := "ready/" + hex.EncodeToString(identifier)
	ref := func(name string) errorpagecontrol.ObjectRef {
		return errorpagecontrol.ObjectRef{TenantID: &tenantID, ScopeID: scopeID, LogicalKey: base + "/" + name}
	}
	stagingA, stagingB := ref("staging-a"), ref("staging-b")
	finalRef, raceRef := ref("final"), ref("race-final")
	probeRefs := []errorpagecontrol.ObjectRef{stagingA, stagingB, finalRef, raceRef}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), store.cleanupTimeout)
		defer cancel()
		if err := store.cleanupProbe(cleanupContext, probeRefs); err != nil {
			cleanupErr := fmt.Errorf("clean readiness probe: %w", err)
			if resultErr == nil {
				resultErr = cleanupErr
			} else {
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}
	}()
	body := []byte("cdnca-error-page-object-store-ready-v1")
	stagedA, err := store.putStaging(ctx, stagingA, body, "text/plain")
	if err != nil {
		return probeError("probe immutable staging", err)
	}
	if replayed, err := store.putStaging(ctx, stagingA, body, "text/plain"); err != nil {
		return probeError("probe idempotent staging", err)
	} else if replayed != stagedA {
		return probeError("probe idempotent staging", nil)
	}
	if _, err := store.putStaging(ctx, stagingA, []byte("different"), "text/plain"); !errors.Is(err, errorpagecontrol.ErrConflict) {
		return probeError("probe staging conflict", err)
	}
	stagedB, err := store.putStaging(ctx, stagingB, body, "text/plain")
	if err != nil {
		return probeError("probe independent staging source", err)
	}
	reader, err := store.open(ctx, stagingA, stagedA.ImmutableToken)
	if err != nil {
		return probeError("probe immutable read", err)
	}
	opened, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return probeError("probe immutable read", readErr)
	}
	if closeErr != nil {
		return probeError("probe immutable read", closeErr)
	}
	if !bytes.Equal(opened, body) {
		return probeError("probe immutable read", nil)
	}
	final, err := store.finalize(ctx, stagingA, finalRef, stagedA)
	if err != nil {
		return probeError("probe conditional finalize", err)
	}
	if final != stagedA {
		return probeError("probe conditional finalize", nil)
	}
	finalBeforeReplay, err := store.stat(ctx, finalRef)
	if err != nil {
		return probeError("probe finalized version", err)
	}
	if _, err := store.finalize(ctx, stagingA, finalRef, stagedA); err != nil {
		return probeError("probe idempotent finalize", err)
	}
	finalAfterReplay, err := store.stat(ctx, finalRef)
	if err != nil {
		return probeError("probe stable destination version", err)
	}
	if finalAfterReplay != finalBeforeReplay {
		return probeError("probe stable destination version", nil)
	}
	if _, err := store.finalize(ctx, stagingB, finalRef, stagedB); !errors.Is(err, errorpagecontrol.ErrConflict) {
		return probeError("probe different source rejection", err)
	}
	finalAfterConflict, err := store.stat(ctx, finalRef)
	if err != nil {
		return probeError("probe rejected copy immutability", err)
	}
	if finalAfterConflict != finalBeforeReplay {
		return probeError("probe rejected copy immutability", nil)
	}
	stagingState, err := store.stat(ctx, stagingA)
	if err != nil {
		return probeError("probe source identity", err)
	}
	stagingKey, err := store.canonicalKey(stagingA)
	if err != nil {
		return probeError("probe source key", err)
	}
	wrongVersion := stagingState
	wrongVersion.versionID = uuid.NewString()
	if err := store.probeRejectedGet(ctx, stagingKey, wrongVersion); err != nil {
		return probeError("probe source version condition", err)
	}
	wrongETag := stagingState
	wrongETag.etag = `"00000000000000000000000000000000"`
	if err := store.probeRejectedGet(ctx, stagingKey, wrongETag); err != nil {
		return probeError("probe source etag condition", err)
	}
	type finalizeResult struct{ err error }
	results := make(chan finalizeResult, 2)
	for _, source := range []struct {
		ref  errorpagecontrol.ObjectRef
		info errorpagecontrol.ObjectInfo
	}{{stagingA, stagedA}, {stagingB, stagedB}} {
		go func() {
			_, err := store.finalize(ctx, source.ref, raceRef, source.info)
			results <- finalizeResult{err: err}
		}()
	}
	successes, conflicts := 0, 0
	for range 2 {
		switch err := (<-results).err; {
		case err == nil:
			successes++
		case errors.Is(err, errorpagecontrol.ErrConflict):
			conflicts++
		default:
			return probeError("probe concurrent finalize", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		return probeError("probe concurrent single winner", nil)
	}
	return nil
}

func (store *Store) probeRejectedGet(ctx context.Context, key string, state objectState) error {
	output, err := store.client.GetObject(ctx, store.boundGetInput(key, state))
	if contextErr := contextError(ctx.Err()); contextErr != nil {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		return contextErr
	}
	if err == nil {
		if output != nil && output.Body != nil {
			_ = output.Body.Close()
		}
		return errorpagecontrol.ErrConflict
	}
	mapped := mapS3Error("probe rejected bound get", err)
	if !errors.Is(mapped, errorpagecontrol.ErrConflict) && !errors.Is(mapped, errorpagecontrol.ErrObjectNotFound) {
		return mapped
	}
	return nil
}

func (store *Store) cleanupProbe(ctx context.Context, refs []errorpagecontrol.ObjectRef) error {
	if len(refs) == 0 {
		return nil
	}
	keys := make(map[string]struct{}, len(refs))
	prefix := ""
	for _, ref := range refs {
		key, err := store.canonicalKey(ref)
		if err != nil {
			return errorpagecontrol.ErrUnavailable
		}
		if prefix == "" {
			separator := strings.LastIndexByte(key, '/')
			if separator < 0 {
				return errorpagecontrol.ErrUnavailable
			}
			prefix = key[:separator+1]
		} else if !strings.HasPrefix(key, prefix) {
			return errorpagecontrol.ErrUnavailable
		}
		keys[key] = struct{}{}
	}
	versions, err := store.listProbeVersions(ctx, prefix, keys)
	if err != nil {
		return cleanupProbeError("list readiness probe versions")
	}
	for _, version := range versions {
		_, err := store.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(store.bucket), Key: aws.String(version.key), VersionId: aws.String(version.versionID),
		})
		if err != nil {
			return cleanupProbeError("delete readiness probe version")
		}
	}
	remaining, err := store.listProbeVersions(ctx, prefix, keys)
	if err != nil {
		return cleanupProbeError("verify readiness probe cleanup")
	}
	if len(remaining) != 0 {
		return cleanupProbeError("verify readiness probe cleanup")
	}
	return nil
}

type probeVersion struct {
	key       string
	versionID string
}

func (store *Store) listProbeVersions(ctx context.Context, prefix string, keys map[string]struct{}) ([]probeVersion, error) {
	input := &s3.ListObjectVersionsInput{Bucket: aws.String(store.bucket), Prefix: aws.String(prefix)}
	versions := make([]probeVersion, 0, len(keys))
	type pageMarker struct{ key, versionID string }
	seenMarkers := make(map[pageMarker]struct{})
	for {
		marker := pageMarker{key: aws.ToString(input.KeyMarker), versionID: aws.ToString(input.VersionIdMarker)}
		if _, seen := seenMarkers[marker]; seen {
			return nil, errorpagecontrol.ErrUnavailable
		}
		seenMarkers[marker] = struct{}{}
		output, err := store.client.ListObjectVersions(ctx, input)
		if contextErr := contextError(err); contextErr != nil {
			return nil, contextErr
		}
		if contextErr := contextError(ctx.Err()); contextErr != nil {
			return nil, contextErr
		}
		if err != nil || output == nil {
			return nil, errorpagecontrol.ErrUnavailable
		}
		appendVersion := func(key, versionID string) error {
			if _, wanted := keys[key]; !wanted {
				return nil
			}
			if !validVersion(versionID) {
				return errorpagecontrol.ErrUnavailable
			}
			versions = append(versions, probeVersion{key: key, versionID: versionID})
			return nil
		}
		for _, version := range output.Versions {
			if err := appendVersion(aws.ToString(version.Key), aws.ToString(version.VersionId)); err != nil {
				return nil, err
			}
		}
		for _, marker := range output.DeleteMarkers {
			if err := appendVersion(aws.ToString(marker.Key), aws.ToString(marker.VersionId)); err != nil {
				return nil, err
			}
		}
		if !aws.ToBool(output.IsTruncated) {
			return versions, nil
		}
		nextKey, nextVersion := aws.ToString(output.NextKeyMarker), aws.ToString(output.NextVersionIdMarker)
		nextMarker := pageMarker{key: nextKey, versionID: nextVersion}
		if nextKey == "" || nextVersion == "" || nextMarker == marker {
			return nil, errorpagecontrol.ErrUnavailable
		}
		if _, seen := seenMarkers[nextMarker]; seen {
			return nil, errorpagecontrol.ErrUnavailable
		}
		input.KeyMarker = aws.String(nextKey)
		input.VersionIdMarker = aws.String(nextVersion)
	}
}

func (store *Store) objectInfo(body []byte, mimeType string) (errorpagecontrol.ObjectInfo, string, error) {
	if len(body) == 0 || int64(len(body)) > store.maxSize || !validMIME(mimeType) {
		return errorpagecontrol.ObjectInfo{}, "", ErrInvalidObject
	}
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	info := errorpagecontrol.ObjectInfo{
		Size: int64(len(body)), SHA256: digestHex, MIMEType: mimeType, ImmutableToken: "sha256:" + digestHex,
	}
	return info, base64.StdEncoding.EncodeToString(digest[:]), nil
}

func (store *Store) canonicalKey(ref errorpagecontrol.ObjectRef) (string, error) {
	if ref.ScopeID == uuid.Nil || ref.TenantID != nil && *ref.TenantID == uuid.Nil {
		return "", ErrInvalidObject
	}
	if err := validateObjectKey(ref.LogicalKey); err != nil {
		return "", err
	}
	owner := "platform/scopes/" + ref.ScopeID.String()
	if ref.TenantID != nil {
		owner = "tenants/" + ref.TenantID.String() + "/scopes/" + ref.ScopeID.String()
	}
	return store.prefix + "/" + owner + "/" + ref.LogicalKey, nil
}

func sameObjectScope(left, right errorpagecontrol.ObjectRef) bool {
	if left.ScopeID != right.ScopeID || left.TenantID == nil != (right.TenantID == nil) {
		return false
	}
	return left.TenantID == nil || *left.TenantID == *right.TenantID
}

func (store *Store) requireReady() error {
	if store == nil || !store.ready.Load() {
		return fmt.Errorf("object store not ready: %w", errorpagecontrol.ErrUnavailable)
	}
	return nil
}

type objectState struct {
	info      errorpagecontrol.ObjectInfo
	versionID string
	etag      string
	source    objectSource
}

type objectSource struct {
	id        string
	key       string
	versionID string
	etag      string
}

func stateFromHead(output *s3.HeadObjectOutput, maxSize int64, objectKey string) (objectState, error) {
	if output == nil {
		return objectState{}, ErrInvalidObject
	}
	return makeObjectState(aws.ToInt64(output.ContentLength), aws.ToString(output.ContentType), output.Metadata,
		aws.ToString(output.ChecksumSHA256), aws.ToString(output.ETag), aws.ToString(output.VersionId), maxSize, objectKey)
}

func stateFromGet(output *s3.GetObjectOutput, maxSize int64, objectKey string) (objectState, error) {
	if output == nil {
		return objectState{}, ErrInvalidObject
	}
	return makeObjectState(aws.ToInt64(output.ContentLength), aws.ToString(output.ContentType), output.Metadata,
		aws.ToString(output.ChecksumSHA256), aws.ToString(output.ETag), aws.ToString(output.VersionId), maxSize, objectKey)
}

func makeObjectState(
	size int64,
	mimeType string,
	metadata map[string]string,
	checksum, etag, versionID string,
	maxSize int64,
	objectKey string,
) (objectState, error) {
	sha := metadata[metadataSHA256]
	token := metadata[metadataToken]
	source := objectSource{
		id: metadata[metadataSourceID], key: metadata[metadataSourceKey],
		versionID: metadata[metadataSourceVersion], etag: metadata[metadataSourceETag],
	}
	metadataSize, err := strconv.ParseInt(metadata[metadataSize], 10, 64)
	decodedChecksum, checksumErr := base64.StdEncoding.Strict().DecodeString(checksum)
	if err != nil || checksumErr != nil || len(decodedChecksum) != sha256.Size || size < 1 || size > maxSize ||
		metadataSize != size || metadata[metadataMIME] != mimeType || !validMIME(mimeType) ||
		!digestPattern.MatchString(sha) || hex.EncodeToString(decodedChecksum) != sha || token != "sha256:"+sha ||
		metadata[metadataObjectKey] != objectKey || !digestPattern.MatchString(source.id) ||
		!etagPattern.MatchString(etag) || !validVersion(versionID) || !validSource(source) {
		return objectState{}, ErrInvalidObject
	}
	return objectState{
		info:      errorpagecontrol.ObjectInfo{Size: size, SHA256: sha, MIMEType: mimeType, ImmutableToken: token},
		versionID: versionID, etag: etag, source: source,
	}, nil
}

func objectMetadata(info errorpagecontrol.ObjectInfo, objectKey string, source objectSource) map[string]string {
	metadata := map[string]string{
		metadataSHA256: info.SHA256, metadataSize: strconv.FormatInt(info.Size, 10),
		metadataMIME: info.MIMEType, metadataToken: info.ImmutableToken,
		metadataObjectKey: objectKey, metadataSourceID: source.id,
	}
	if source.key != "" {
		metadata[metadataSourceKey] = source.key
		metadata[metadataSourceVersion] = source.versionID
		metadata[metadataSourceETag] = source.etag
	}
	return metadata
}

func validSource(source objectSource) bool {
	if source.key == "" && source.versionID == "" && source.etag == "" {
		return true
	}
	return source.key != "" && len(source.key) <= 1024 && validateKeySegments(source.key) == nil &&
		validVersion(source.versionID) && etagPattern.MatchString(source.etag)
}

func validVersion(versionID string) bool {
	return len(versionID) <= 1024 && versionPattern.MatchString(versionID) && versionID != "null"
}

func randomSourceID() (string, error) {
	value := make([]byte, sha256.Size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validObjectInfo(info errorpagecontrol.ObjectInfo, maxSize int64) bool {
	return info.Size > 0 && info.Size <= maxSize && digestPattern.MatchString(info.SHA256) &&
		validMIME(info.MIMEType) && info.ImmutableToken == "sha256:"+info.SHA256
}

func validToken(token string) bool {
	return len(token) == len("sha256:")+64 && strings.HasPrefix(token, "sha256:") && digestPattern.MatchString(strings.TrimPrefix(token, "sha256:"))
}

func validMIME(value string) bool {
	parsed, parameters, err := mime.ParseMediaType(value)
	if err != nil || len(parameters) != 0 || parsed != value {
		return false
	}
	switch value {
	case "text/html", "text/plain", "application/json",
		"image/png", "image/jpeg", "image/x-icon", "image/vnd.microsoft.icon":
		return true
	default:
		return false
	}
}

type validatingCredentials struct{ provider aws.CredentialsProvider }

func (provider validatingCredentials) Retrieve(ctx context.Context) (credentials aws.Credentials, resultErr error) {
	defer func() {
		if recover() != nil {
			credentials = aws.Credentials{}
			resultErr = errCredentials
		}
	}()
	credentials, err := provider.provider.Retrieve(ctx)
	if err != nil || !validCredential(credentials.AccessKeyID, 256) || !validCredential(credentials.SecretAccessKey, 1024) ||
		credentials.SessionToken != "" && !validCredential(credentials.SessionToken, 16<<10) {
		return aws.Credentials{}, errCredentials
	}
	credentials.Source = "explicit-redacted"
	return credentials, nil
}

func validCredential(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char == 0x7f {
			return false
		}
	}
	return true
}

func mapS3Error(operation string, err error) error {
	if err == nil {
		return nil
	}
	if contextErr := contextError(err); contextErr != nil {
		return contextErr
	}
	code := ""
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code = strings.ToLower(apiError.ErrorCode())
	}
	status := 0
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		status = responseError.HTTPStatusCode()
	}
	var mapped error
	switch {
	case code == "nosuchbucket":
		mapped = errorpagecontrol.ErrUnavailable
	case code == "nosuchkey" || code == "notfound" || status == http.StatusNotFound:
		mapped = errorpagecontrol.ErrObjectNotFound
	case code == "preconditionfailed" || code == "conditionalrequestconflict" || code == "operationaborted" ||
		status == http.StatusConflict || status == http.StatusPreconditionFailed:
		mapped = errorpagecontrol.ErrConflict
	default:
		mapped = errorpagecontrol.ErrUnavailable
	}
	return fmt.Errorf("%s: %w", operation, mapped)
}

func contextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func probeError(operation string, err error) error {
	if contextErr := contextError(err); contextErr != nil {
		return fmt.Errorf("%s: %w", operation, contextErr)
	}
	return fmt.Errorf("%s: %w", operation, errorpagecontrol.ErrUnavailable)
}

func cleanupProbeError(operation string) error {
	return fmt.Errorf("%s: %w", operation, errorpagecontrol.ErrUnavailable)
}
