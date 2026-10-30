package errorpageobjectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

const minIOSmokeImage = "minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"

func TestMinIOObjectStoreSmoke(t *testing.T) {
	if os.Getenv("ERRORPAGE_OBJECTSTORE_MINIO_SMOKE") != "1" {
		t.Skip("set ERRORPAGE_OBJECTSTORE_MINIO_SMOKE=1 to run the isolated MinIO smoke")
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	containerName := "cdnca-errorpage-minio-" + suffix[:16]
	bucket := "cdnca-errorpage-" + suffix[:20]
	accessKey := "smoke" + suffix[:16]
	secretKey := "smoke-secret-" + suffix
	run := exec.CommandContext(t.Context(), "docker", "run", "--detach", "--rm",
		"--name", containerName, "--publish", "127.0.0.1::9000",
		"--env", "MINIO_ROOT_USER="+accessKey, "--env", "MINIO_ROOT_PASSWORD="+secretKey,
		minIOSmokeImage, "server", "/data", "--address", ":9000")
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("start isolated MinIO: %v (%s)", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		cleanup := exec.Command("docker", "rm", "--force", containerName)
		_ = cleanup.Run()
	})

	portOutput, err := exec.CommandContext(t.Context(), "docker", "port", containerName, "9000/tcp").Output()
	if err != nil {
		t.Fatalf("resolve isolated MinIO port: %v", err)
	}
	endpoint := "http://" + strings.TrimSpace(string(portOutput))
	waitForMinIO(t, endpoint, containerName)

	provider := credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}, nil
	})
	type copyRequest struct {
		status                int
		ifNoneMatch           string
		copySource            string
		copySourceIfMatchETag string
	}
	var copyMu sync.Mutex
	copyRequests := make([]copyRequest, 0, 2)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	recorder := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, requestErr := transport.RoundTrip(request)
		if request.Header.Get("X-Amz-Copy-Source") != "" {
			status := 0
			if response != nil {
				status = response.StatusCode
			}
			copyMu.Lock()
			copyRequests = append(copyRequests, copyRequest{
				status: status, ifNoneMatch: request.Header.Get("If-None-Match"),
				copySource:            request.Header.Get("X-Amz-Copy-Source"),
				copySourceIfMatchETag: request.Header.Get("X-Amz-Copy-Source-If-Match"),
			})
			copyMu.Unlock()
		}
		return response, requestErr
	})
	client := newSmokeS3Client(endpoint, provider, &http.Client{Transport: recorder})
	if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create smoke bucket: %v", err)
	}
	t.Cleanup(func() { cleanupSmokeBucket(t, client, bucket) })
	if _, err := client.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{
		Bucket:                  aws.String(bucket),
		VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
	}); err != nil {
		t.Fatalf("enable smoke bucket versioning: %v", err)
	}
	protocolBody := []byte("minio conditional copy protocol")
	protocolDigest := sha256.Sum256(protocolBody)
	protocolSource := "protocol/" + suffix + "/source"
	protocolDestination := "protocol/" + suffix + "/destination"
	putOutput, err := client.PutObject(t.Context(), &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(protocolSource), Body: bytes.NewReader(protocolBody),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		ChecksumSHA256:    aws.String(base64.StdEncoding.EncodeToString(protocolDigest[:])),
		IfNoneMatch:       aws.String("*"),
	})
	if err != nil {
		t.Fatalf("put protocol source: %v", err)
	}
	sourceHead, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(protocolSource), ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		t.Fatalf("head protocol source: %v", err)
	}
	copySource := url.PathEscape(bucket+"/"+protocolSource) + "?versionId=" + url.QueryEscape(aws.ToString(putOutput.VersionId))
	protocolInfo := errorpagecontrol.ObjectInfo{
		Size: int64(len(protocolBody)), SHA256: hex.EncodeToString(protocolDigest[:]),
		MIMEType: "text/plain", ImmutableToken: "sha256:" + hex.EncodeToString(protocolDigest[:]),
	}
	protocolSourceState := objectSource{
		id: strings.Repeat("a", 64), key: protocolSource,
		versionID: aws.ToString(putOutput.VersionId), etag: aws.ToString(sourceHead.ETag),
	}
	copyInput := &s3.CopyObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(protocolDestination), CopySource: aws.String(copySource),
		CopySourceIfMatch: aws.String(aws.ToString(sourceHead.ETag)), IfNoneMatch: aws.String("*"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ContentType: aws.String(protocolInfo.MIMEType),
		MetadataDirective: types.MetadataDirectiveReplace,
		Metadata:          objectMetadata(protocolInfo, protocolDestination, protocolSourceState),
	}
	firstCopy, err := client.CopyObject(t.Context(), copyInput)
	if err != nil {
		t.Fatalf("first conditional protocol copy: %v", err)
	}
	firstHead, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(protocolDestination), ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		t.Fatalf("head first protocol copy: %v", err)
	}
	if aws.ToString(firstHead.ChecksumSHA256) != "" || aws.ToString(firstHead.ETag) == "" || aws.ToString(firstHead.VersionId) == "" ||
		firstHead.Metadata[metadataObjectKey] != protocolDestination || firstHead.Metadata[metadataSourceKey] != protocolSource ||
		firstHead.Metadata[metadataSourceVersion] != aws.ToString(putOutput.VersionId) ||
		firstHead.Metadata[metadataSourceETag] != aws.ToString(sourceHead.ETag) {
		t.Fatalf("checksum-omitting CopyObject HEAD = checksum:%q etag:%q version:%q metadata:%v",
			aws.ToString(firstHead.ChecksumSHA256), aws.ToString(firstHead.ETag), aws.ToString(firstHead.VersionId), firstHead.Metadata)
	}
	secondCopy, secondCopyErr := client.CopyObject(t.Context(), copyInput)
	secondHead, secondHeadErr := client.HeadObject(t.Context(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(protocolDestination), ChecksumMode: types.ChecksumModeEnabled,
	})
	secondCopyVersion := ""
	if secondCopy != nil {
		secondCopyVersion = aws.ToString(secondCopy.VersionId)
	}
	secondHeadVersion := ""
	if secondHead != nil {
		secondHeadVersion = aws.ToString(secondHead.VersionId)
	}
	copyMu.Lock()
	recordedCopies := append([]copyRequest(nil), copyRequests...)
	copyMu.Unlock()
	if len(recordedCopies) != 2 {
		t.Fatalf("conditional CopyObject requests = %d, want 2", len(recordedCopies))
	}
	for index, request := range recordedCopies {
		rawSource, decodeErr := url.PathUnescape(request.copySource)
		sourceURL, parseErr := url.Parse("/" + strings.TrimPrefix(rawSource, "/"))
		if request.status != http.StatusOK || request.ifNoneMatch != "*" || decodeErr != nil || parseErr != nil ||
			sourceURL.Query().Get("versionId") != aws.ToString(putOutput.VersionId) ||
			request.copySourceIfMatchETag != aws.ToString(sourceHead.ETag) {
			t.Fatalf("conditional CopyObject request %d = %+v decode=%v parse=%v", index, request, decodeErr, parseErr)
		}
	}
	t.Logf("conditional CopyObject status=[%d,%d] destination_if_none_match=%q source_version=%q source_if_match=%q first_version=%q first_result_version=%q first_head_checksum=%t replay_error=%v replay_result_version=%q replay_head_error=%v replay_head_version=%q",
		recordedCopies[0].status, recordedCopies[1].status, recordedCopies[0].ifNoneMatch,
		aws.ToString(putOutput.VersionId), recordedCopies[0].copySourceIfMatchETag,
		aws.ToString(firstHead.VersionId), aws.ToString(firstCopy.VersionId), aws.ToString(firstHead.ChecksumSHA256) != "", secondCopyErr,
		secondCopyVersion, secondHeadErr, secondHeadVersion)

	config := validConfig(endpoint)
	config.Bucket = bucket
	config.Prefix = "errorpage-smoke/" + suffix[:16]
	config.Credentials = provider
	config.RequestTimeout = 10 * time.Second
	store, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("construct MinIO-backed store: %v", err)
	}
	assertNoSmokeObjectVersions(t, client, bucket, config.Prefix+"/")
	if err := store.Ready(t.Context()); err != nil {
		t.Fatalf("repeat MinIO readiness probe: %v", err)
	}
	assertNoSmokeObjectVersions(t, client, bucket, config.Prefix+"/")
	tenantID, scopeID := uuid.New(), uuid.New()
	ref := func(logicalKey string) errorpagecontrol.ObjectRef {
		return errorpagecontrol.ObjectRef{TenantID: &tenantID, ScopeID: scopeID, LogicalKey: logicalKey}
	}
	stagingRef := ref("error-pages/staging/" + suffix)
	finalRef := ref("error-pages/objects/" + suffix)
	body := []byte("minio error page smoke")
	staged, err := store.PutStaging(t.Context(), stagingRef, body, "text/plain")
	if err != nil {
		t.Fatalf("stage MinIO object: %v", err)
	}
	if _, err := store.Finalize(t.Context(), stagingRef, finalRef, staged); err != nil {
		t.Fatalf("finalize MinIO object: %v", err)
	}
	reader, err := store.Open(t.Context(), finalRef, staged.ImmutableToken)
	if err != nil {
		t.Fatalf("open MinIO object: %v", err)
	}
	opened, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(opened) != string(body) {
		t.Fatalf("read MinIO object: body=%q read=%v close=%v", opened, readErr, closeErr)
	}
	if err := store.Delete(t.Context(), finalRef); err != nil {
		t.Fatalf("delete final MinIO object: %v", err)
	}
	if err := store.Delete(t.Context(), stagingRef); err != nil {
		t.Fatalf("delete staging MinIO object: %v", err)
	}
}

func waitForMinIO(t *testing.T, endpoint, containerName string) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	deadline := time.Now().Add(2 * time.Minute)
	lastStatus := 0
	var lastErr error
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint+"/minio/health/live", nil)
		if err == nil {
			response, requestErr := client.Do(request)
			lastErr = requestErr
			if requestErr == nil {
				lastStatus = response.StatusCode
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	logs, _ := exec.CommandContext(t.Context(), "docker", "logs", "--tail", "100", containerName).CombinedOutput()
	t.Fatalf("isolated MinIO did not become ready: status=%d request=%v logs=%q", lastStatus, lastErr, strings.TrimSpace(string(logs)))
}

func newSmokeS3Client(endpoint string, provider aws.CredentialsProvider, httpClient *http.Client) *s3.Client {
	config := aws.Config{Region: "us-east-1", Credentials: aws.NewCredentialsCache(provider), HTTPClient: httpClient}
	return s3.NewFromConfig(config, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = true
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func cleanupSmokeBucket(t *testing.T, client *s3.Client, bucket string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	objects, err := listSmokeObjectVersions(ctx, client, bucket, "")
	if err != nil {
		t.Errorf("list smoke object versions: %v", err)
		return
	}
	for start := 0; start < len(objects); start += 1000 {
		end := min(start+1000, len(objects))
		output, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects[start:end], Quiet: aws.Bool(true)},
		})
		if err != nil || output == nil || len(output.Errors) != 0 {
			t.Errorf("delete smoke object versions: output=%v error=%v", output, err)
			return
		}
	}
	remaining, err := listSmokeObjectVersions(ctx, client, bucket, "")
	if err != nil || len(remaining) != 0 {
		t.Errorf("smoke object versions remain after cleanup: count=%d error=%v", len(remaining), err)
		return
	}
	t.Log("smoke cleanup ListObjectVersions: versions=0 delete_markers=0")
	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Errorf("delete smoke bucket: %v", err)
	}
}

func assertNoSmokeObjectVersions(t *testing.T, client *s3.Client, bucket, prefix string) {
	t.Helper()
	objects, err := listSmokeObjectVersions(t.Context(), client, bucket, prefix)
	if err != nil || len(objects) != 0 {
		t.Fatalf("ListObjectVersions(%q) = count:%d error:%v, want zero readiness residue", prefix, len(objects), err)
	}
	t.Logf("readiness cleanup ListObjectVersions prefix=%q: versions=0 delete_markers=0", prefix)
}

func listSmokeObjectVersions(ctx context.Context, client *s3.Client, bucket, prefix string) ([]types.ObjectIdentifier, error) {
	paginator := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	objects := make([]types.ObjectIdentifier, 0)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, version := range page.Versions {
			objects = append(objects, types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range page.DeleteMarkers {
			objects = append(objects, types.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
		}
	}
	return objects, nil
}

func TestMinIOSmokeImageIsPinned(t *testing.T) {
	if !strings.HasPrefix(minIOSmokeImage, "minio/minio@sha256:") || len(strings.TrimPrefix(minIOSmokeImage, "minio/minio@sha256:")) != 64 {
		t.Fatalf("MinIO smoke image must use an immutable digest: %q", minIOSmokeImage)
	}
}
