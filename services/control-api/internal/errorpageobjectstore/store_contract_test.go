package errorpageobjectstore

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

var (
	testTenantID = uuid.MustParse("019f9d75-486f-7df1-a972-001122334455")
	testScopeID  = uuid.MustParse("019f9d75-486f-7df1-a972-556677889900")
)

func testObjectRef(logicalKey string) errorpagecontrol.ObjectRef {
	return errorpagecontrol.ObjectRef{TenantID: &testTenantID, ScopeID: testScopeID, LogicalKey: logicalKey}
}

func testPhysicalKey(logicalKey string) string {
	return "control-api/error-pages/tenants/" + testTenantID.String() + "/scopes/" + testScopeID.String() + "/" + logicalKey
}

type fakeS3Object struct {
	body      []byte
	mime      string
	metadata  map[string]string
	checksum  string
	etag      string
	versionID string
}

type fakeS3Version struct {
	object       fakeS3Object
	versionID    string
	deleteMarker bool
}

type fakeS3 struct {
	mu                    sync.Mutex
	objects               map[string]fakeS3Object
	versions              map[string][]fakeS3Version
	version               int
	versioningEnabled     bool
	putFailures           map[string]int
	putCalls              map[string]int
	getBodyOverrides      map[string][]byte
	deleteFailures        map[string]int
	deleteConflicts       map[string]bool
	deleteCommitError     map[string]bool
	requests              []string
	maliciousVersion      string
	redirectLocation      string
	ignoreSourceVersion   bool
	ignoreSourceETag      bool
	ignorePutCondition    bool
	omitFinalChecksums    bool
	requireBoundGet       bool
	ignoreGetVersion      bool
	ignoreGetETag         bool
	tamperReadyGet        bool
	rejectCopy            bool
	copyCalls             int
	listPageSize          int
	seedReadyMarkers      bool
	seedReadyForeign      bool
	cleanupFailure        string
	continuedListCalls    int
	continuedVersions     int
	continuedMarkers      int
	listCalls             int
	malformedContinuation string
	malformedFirstKey     string
	malformedFirstVersion string
	readyForeignKey       string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{
		objects: make(map[string]fakeS3Object), versions: make(map[string][]fakeS3Version), versioningEnabled: true,
		putFailures: make(map[string]int), putCalls: make(map[string]int), getBodyOverrides: make(map[string][]byte),
		deleteFailures: make(map[string]int), deleteConflicts: make(map[string]bool), deleteCommitError: make(map[string]bool),
		listPageSize: 2,
	}
}

func (fake *fakeS3) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.requests = append(fake.requests, request.Method+" "+request.URL.RequestURI())
	if request.Header.Get("Authorization") == "" || strings.Contains(request.URL.RawQuery, "explicit-secret") {
		fake.writeError(response, http.StatusForbidden, "AccessDenied", "unsigned or leaked credential")
		return
	}
	if request.Method == http.MethodGet && request.URL.Query().Has("versioning") {
		if fake.redirectLocation != "" {
			response.Header().Set("Location", fake.redirectLocation)
			response.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if fake.maliciousVersion != "" {
			response.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(response, fake.maliciousVersion)
			return
		}
		status := "Suspended"
		if fake.versioningEnabled {
			status = "Enabled"
		}
		response.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(response, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></VersioningConfiguration>`, status)
		return
	}
	if request.Method == http.MethodGet && request.URL.Query().Has("versions") {
		fake.listVersions(response, request)
		return
	}
	key, ok := fake.requestKey(request.URL)
	if !ok {
		fake.writeError(response, http.StatusNotFound, "NoSuchBucket", "missing bucket")
		return
	}
	switch request.Method {
	case http.MethodPut:
		fake.put(response, request, key)
	case http.MethodHead:
		fake.head(response, request, key)
	case http.MethodGet:
		fake.get(response, request, key)
	case http.MethodDelete:
		fake.delete(response, request, key)
	default:
		fake.writeError(response, http.StatusMethodNotAllowed, "MethodNotAllowed", "unsupported")
	}
}

func (fake *fakeS3) requestKey(requestURL *url.URL) (string, bool) {
	path := strings.TrimPrefix(requestURL.EscapedPath(), "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] != "error-pages" {
		return "", false
	}
	key, err := url.PathUnescape(parts[1])
	return key, err == nil
}

func (fake *fakeS3) put(response http.ResponseWriter, request *http.Request, key string) {
	fake.putCalls[key]++
	if request.Header.Get("X-Amz-Copy-Source") != "" {
		fake.copy(response, request, key)
		return
	}
	if fake.putFailures[key] > 0 {
		fake.putFailures[key]--
		fake.writeError(response, http.StatusInternalServerError, "InternalError", "retryable")
		return
	}
	if request.Header.Get("If-None-Match") != "*" {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "missing condition")
		return
	}
	if _, exists := fake.objects[key]; exists && !fake.ignorePutCondition {
		fake.writeError(response, http.StatusPreconditionFailed, "PreconditionFailed", "already exists")
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "body")
		return
	}
	digest := sha256.Sum256(body)
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	if request.Header.Get("X-Amz-Checksum-Sha256") != checksum {
		fake.writeError(response, http.StatusBadRequest, "BadDigest", "checksum")
		return
	}
	md5Digest := md5.Sum(body)
	if fake.seedReadyMarkers && strings.Contains(key, "/ready/") && len(fake.versions[key]) == 0 {
		fake.version++
		fake.versions[key] = append(fake.versions[key], fakeS3Version{
			versionID: fmt.Sprintf("v-%d", fake.version), deleteMarker: true,
		})
	}
	if fake.seedReadyForeign && fake.readyForeignKey == "" && strings.Contains(key, "/ready/") {
		fake.version++
		separator := strings.LastIndexByte(key, '/')
		fake.readyForeignKey = key[:separator+1] + "foreign"
		foreign := fakeS3Object{body: []byte("foreign"), etag: `"00000000000000000000000000000001"`, versionID: fmt.Sprintf("v-%d", fake.version)}
		fake.objects[fake.readyForeignKey] = foreign
		fake.versions[fake.readyForeignKey] = []fakeS3Version{{object: foreign, versionID: foreign.versionID}}
	}
	fake.version++
	object := fakeS3Object{
		body: append([]byte(nil), body...), mime: request.Header.Get("Content-Type"),
		metadata: map[string]string{
			"cdnca-sha256":         request.Header.Get("X-Amz-Meta-Cdnca-Sha256"),
			"cdnca-size":           request.Header.Get("X-Amz-Meta-Cdnca-Size"),
			"cdnca-mime":           request.Header.Get("X-Amz-Meta-Cdnca-Mime"),
			"cdnca-token":          request.Header.Get("X-Amz-Meta-Cdnca-Token"),
			"cdnca-object-key":     request.Header.Get("X-Amz-Meta-Cdnca-Object-Key"),
			"cdnca-source-id":      request.Header.Get("X-Amz-Meta-Cdnca-Source-Id"),
			"cdnca-source-key":     request.Header.Get("X-Amz-Meta-Cdnca-Source-Key"),
			"cdnca-source-version": request.Header.Get("X-Amz-Meta-Cdnca-Source-Version"),
			"cdnca-source-etag":    request.Header.Get("X-Amz-Meta-Cdnca-Source-Etag"),
		},
		checksum: checksum, etag: `"` + hex.EncodeToString(md5Digest[:]) + `"`,
		versionID: fmt.Sprintf("v-%d", fake.version),
	}
	fake.objects[key] = object
	fake.versions[key] = append(fake.versions[key], fakeS3Version{object: object, versionID: object.versionID})
	fake.writeObjectHeaders(response, object)
	response.WriteHeader(http.StatusOK)
}

func (fake *fakeS3) copy(response http.ResponseWriter, request *http.Request, key string) {
	fake.copyCalls++
	if fake.rejectCopy {
		fake.writeError(response, http.StatusNotImplemented, "NotImplemented", "copy unsupported")
		return
	}
	if request.Header.Get("If-None-Match") != "*" {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "missing destination condition")
		return
	}
	if _, exists := fake.objects[key]; exists {
		fake.writeError(response, http.StatusPreconditionFailed, "PreconditionFailed", "destination exists")
		return
	}
	rawSource, err := url.PathUnescape(request.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "copy source")
		return
	}
	sourceURL, err := url.Parse("/" + strings.TrimPrefix(rawSource, "/"))
	if err != nil {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "copy source")
		return
	}
	sourceKey, ok := fake.requestKey(sourceURL)
	if !ok {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "copy source")
		return
	}
	source, found := fake.objects[sourceKey]
	if !found || !fake.ignoreSourceVersion && sourceURL.Query().Get("versionId") != source.versionID {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "copy source version")
		return
	}
	if !fake.ignoreSourceETag && request.Header.Get("X-Amz-Copy-Source-If-Match") != source.etag {
		fake.writeError(response, http.StatusPreconditionFailed, "PreconditionFailed", "copy source etag")
		return
	}
	if request.Header.Get("X-Amz-Metadata-Directive") != "REPLACE" || request.Header.Get("X-Amz-Checksum-Algorithm") != "SHA256" {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "copy controls")
		return
	}
	fake.version++
	object := fakeS3Object{
		body: append([]byte(nil), source.body...), mime: request.Header.Get("Content-Type"),
		metadata: map[string]string{
			"cdnca-sha256":         request.Header.Get("X-Amz-Meta-Cdnca-Sha256"),
			"cdnca-size":           request.Header.Get("X-Amz-Meta-Cdnca-Size"),
			"cdnca-mime":           request.Header.Get("X-Amz-Meta-Cdnca-Mime"),
			"cdnca-token":          request.Header.Get("X-Amz-Meta-Cdnca-Token"),
			"cdnca-object-key":     request.Header.Get("X-Amz-Meta-Cdnca-Object-Key"),
			"cdnca-source-id":      request.Header.Get("X-Amz-Meta-Cdnca-Source-Id"),
			"cdnca-source-key":     request.Header.Get("X-Amz-Meta-Cdnca-Source-Key"),
			"cdnca-source-version": request.Header.Get("X-Amz-Meta-Cdnca-Source-Version"),
			"cdnca-source-etag":    request.Header.Get("X-Amz-Meta-Cdnca-Source-Etag"),
		},
		checksum: source.checksum, etag: source.etag, versionID: fmt.Sprintf("v-%d", fake.version),
	}
	fake.objects[key] = object
	fake.versions[key] = append(fake.versions[key], fakeS3Version{object: object, versionID: object.versionID})
	fake.writeObjectHeaders(response, object)
	response.Header().Set("Content-Type", "application/xml")
	response.WriteHeader(http.StatusOK)
	fmt.Fprintf(response, `<CopyObjectResult><ETag>%s</ETag><ChecksumSHA256>%s</ChecksumSHA256></CopyObjectResult>`, object.etag, object.checksum)
}

func (fake *fakeS3) head(response http.ResponseWriter, request *http.Request, key string) {
	object, found := fake.objectForRequest(request, key)
	if !found {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "missing")
		return
	}
	fake.writeObjectHeaders(response, object)
	if object.metadata[metadataSourceKey] != "" && fake.omitFinalChecksums {
		response.Header().Del("X-Amz-Checksum-Sha256")
	}
	response.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
	response.Header().Set("Content-Type", object.mime)
	response.WriteHeader(http.StatusOK)
}

func (fake *fakeS3) get(response http.ResponseWriter, request *http.Request, key string) {
	object, found := fake.objects[key]
	if !found {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "missing")
		return
	}
	if versionID := request.URL.Query().Get("versionId"); versionID != "" && versionID != object.versionID && !fake.ignoreGetVersion {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "version")
		return
	}
	if object.metadata[metadataSourceKey] != "" && fake.requireBoundGet &&
		(request.URL.Query().Get("versionId") != object.versionID || request.Header.Get("If-Match") != object.etag) {
		fake.writeError(response, http.StatusPreconditionFailed, "PreconditionFailed", "unbound copied object read")
		return
	}
	if match := request.Header.Get("If-Match"); match != "" && match != object.etag && !fake.ignoreGetETag {
		fake.writeError(response, http.StatusPreconditionFailed, "PreconditionFailed", "etag")
		return
	}
	fake.writeObjectHeaders(response, object)
	if object.metadata[metadataSourceKey] != "" && fake.omitFinalChecksums {
		response.Header().Del("X-Amz-Checksum-Sha256")
	}
	body := object.body
	if override, found := fake.getBodyOverrides[key]; found {
		body = override
	}
	if fake.tamperReadyGet && strings.Contains(key, "/ready/") {
		body = []byte("tampered-readiness-body")
	}
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.Header().Set("Content-Type", object.mime)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

func (fake *fakeS3) objectForRequest(request *http.Request, key string) (fakeS3Object, bool) {
	object, found := fake.objects[key]
	if !found {
		return fakeS3Object{}, false
	}
	if versionID := request.URL.Query().Get("versionId"); versionID != "" && versionID != object.versionID {
		return fakeS3Object{}, false
	}
	return object, true
}

func (fake *fakeS3) delete(response http.ResponseWriter, request *http.Request, key string) {
	if _, found := fake.objects[key]; !found && request.URL.Query().Get("versionId") == "" {
		fake.writeError(response, http.StatusNotFound, "NoSuchKey", "missing")
		return
	}
	if fake.deleteFailures[key] > 0 {
		fake.deleteFailures[key]--
		fake.writeError(response, http.StatusInternalServerError, "InternalError", "delete retryable")
		return
	}
	if fake.deleteConflicts[key] {
		fake.writeError(response, http.StatusConflict, "OperationAborted", "delete conflict")
		return
	}
	versionID := request.URL.Query().Get("versionId")
	if versionID != "" {
		entries := fake.versions[key]
		removed := false
		for index := range entries {
			if entries[index].versionID == versionID {
				if fake.cleanupFailure == "delete-version" && !entries[index].deleteMarker ||
					fake.cleanupFailure == "delete-marker" && entries[index].deleteMarker {
					fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "forced cleanup delete failure")
					return
				}
				entries = append(entries[:index], entries[index+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			fake.writeError(response, http.StatusNotFound, "NoSuchVersion", "missing version")
			return
		}
		fake.versions[key] = entries
		fake.restoreCurrentObject(key)
	} else {
		fake.version++
		markerID := fmt.Sprintf("v-%d", fake.version)
		fake.versions[key] = append(fake.versions[key], fakeS3Version{versionID: markerID, deleteMarker: true})
		delete(fake.objects, key)
	}
	if fake.deleteCommitError[key] {
		delete(fake.deleteCommitError, key)
		fake.writeError(response, http.StatusInternalServerError, "InternalError", "committed without response")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (fake *fakeS3) restoreCurrentObject(key string) {
	delete(fake.objects, key)
	entries := fake.versions[key]
	if len(entries) == 0 {
		delete(fake.versions, key)
		return
	}
	latest := entries[len(entries)-1]
	if !latest.deleteMarker {
		fake.objects[key] = latest.object
	}
}

type fakeListVersionsResult struct {
	XMLName       xml.Name              `xml:"ListVersionsResult"`
	XMLNS         string                `xml:"xmlns,attr"`
	Name          string                `xml:"Name"`
	Prefix        string                `xml:"Prefix"`
	KeyMarker     string                `xml:"KeyMarker"`
	VersionMarker string                `xml:"VersionIdMarker"`
	MaxKeys       int                   `xml:"MaxKeys"`
	IsTruncated   bool                  `xml:"IsTruncated"`
	NextKeyMarker string                `xml:"NextKeyMarker,omitempty"`
	NextVersionID string                `xml:"NextVersionIdMarker,omitempty"`
	Versions      []fakeListVersion     `xml:"Version"`
	DeleteMarkers []fakeListDeleteEntry `xml:"DeleteMarker"`
}

type fakeListVersion struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type fakeListDeleteEntry struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
}

func (fake *fakeS3) listVersions(response http.ResponseWriter, request *http.Request) {
	if strings.Trim(request.URL.Path, "/") != "error-pages" {
		fake.writeError(response, http.StatusNotFound, "NoSuchBucket", "missing bucket")
		return
	}
	fake.listCalls++
	prefix := request.URL.Query().Get("prefix")
	keyMarker := request.URL.Query().Get("key-marker")
	versionMarker := request.URL.Query().Get("version-id-marker")
	if keyMarker != "" {
		fake.continuedListCalls++
		if fake.cleanupFailure == "list-page-2" {
			fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "forced cleanup list failure")
			return
		}
	}
	result := fakeListVersionsResult{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/", Name: "error-pages", Prefix: prefix,
		KeyMarker: keyMarker, VersionMarker: versionMarker, MaxKeys: 1000,
	}
	keys := make([]string, 0, len(fake.versions))
	for key := range fake.versions {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	type listingEntry struct {
		key   string
		entry fakeS3Version
	}
	entries := make([]listingEntry, 0)
	for _, key := range keys {
		versions := fake.versions[key]
		for index := len(versions) - 1; index >= 0; index-- {
			entries = append(entries, listingEntry{key: key, entry: versions[index]})
		}
	}
	start := 0
	if keyMarker != "" {
		start = -1
		for index, item := range entries {
			if item.key == keyMarker && (item.entry.versionID == versionMarker ||
				fake.malformedContinuation == "empty-version" && versionMarker == "") {
				start = index + 1
				break
			}
		}
		if start < 0 {
			fake.writeError(response, http.StatusBadRequest, "InvalidArgument", "invalid continuation marker")
			return
		}
	}
	if fake.cleanupFailure == "final-verify" && start == 0 && len(entries) == 0 && strings.Contains(prefix, "/ready/") {
		fake.writeError(response, http.StatusBadRequest, "InvalidRequest", "forced cleanup verify failure")
		return
	}
	end := len(entries)
	if fake.listPageSize > 0 && start+fake.listPageSize < end {
		end = start + fake.listPageSize
	}
	for index, item := range entries[start:end] {
		entry := item.entry
		key := item.key
		latest := index+start == 0 || entries[index+start-1].key != key
		if entry.deleteMarker {
			result.DeleteMarkers = append(result.DeleteMarkers, fakeListDeleteEntry{
				Key: key, VersionID: entry.versionID, IsLatest: latest, LastModified: "2026-07-26T00:00:00Z",
			})
			continue
		}
		result.Versions = append(result.Versions, fakeListVersion{
			Key: key, VersionID: entry.versionID, IsLatest: latest, LastModified: "2026-07-26T00:00:00Z",
			ETag: entry.object.etag, Size: int64(len(entry.object.body)),
		})
	}
	if end < len(entries) {
		last := entries[end-1]
		result.IsTruncated = true
		result.NextKeyMarker = last.key
		result.NextVersionID = last.entry.versionID
	}
	switch fake.malformedContinuation {
	case "empty-key":
		if keyMarker == "" && result.IsTruncated {
			result.NextKeyMarker = ""
		}
	case "empty-version":
		if keyMarker == "" && result.IsTruncated {
			result.NextVersionID = ""
		}
	case "repeat-current":
		if keyMarker != "" {
			result.IsTruncated = true
			result.NextKeyMarker = keyMarker
			result.NextVersionID = versionMarker
		}
	case "cycle-history":
		if keyMarker == "" && result.IsTruncated {
			fake.malformedFirstKey = result.NextKeyMarker
			fake.malformedFirstVersion = result.NextVersionID
		} else if fake.listCalls == 3 && fake.malformedFirstKey != "" {
			result.IsTruncated = true
			result.NextKeyMarker = fake.malformedFirstKey
			result.NextVersionID = fake.malformedFirstVersion
		}
	}
	if keyMarker != "" {
		fake.continuedVersions += len(result.Versions)
		fake.continuedMarkers += len(result.DeleteMarkers)
	}
	response.Header().Set("Content-Type", "application/xml")
	response.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(response).Encode(result)
}

func (fake *fakeS3) writeObjectHeaders(response http.ResponseWriter, object fakeS3Object) {
	response.Header().Set("ETag", object.etag)
	response.Header().Set("X-Amz-Version-Id", object.versionID)
	response.Header().Set("X-Amz-Checksum-Sha256", object.checksum)
	for key, value := range object.metadata {
		response.Header().Set("X-Amz-Meta-"+key, value)
	}
}

func (fake *fakeS3) writeError(response http.ResponseWriter, status int, code, message string) {
	response.Header().Set("Content-Type", "application/xml")
	response.WriteHeader(status)
	_ = xml.NewEncoder(response).Encode(struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}{Code: code, Message: message})
}

func newTestStore(t *testing.T, fake *fakeS3) (*Store, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	config := validConfig(server.URL)
	store, err := New(t.Context(), config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return store, server
}

func TestNewFailsClosedUnlessVersioningAndProbeGuaranteesPass(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.versioningEnabled = false
	server := httptest.NewServer(fake)
	defer server.Close()
	if store, err := New(t.Context(), validConfig(server.URL)); err == nil || store != nil {
		t.Fatalf("New() = (%v, %v), want nil and error", store, err)
	}

	fake = newFakeS3()
	store, server := newTestStore(t, fake)
	_ = server
	capabilities := store.Capabilities()
	if !capabilities.ImmutableStaging || !capabilities.ConditionalFinalize || !capabilities.TrustedMetadata ||
		!capabilities.ImmutableReads || !capabilities.PreservesStagingAlias {
		t.Fatalf("Capabilities() = %+v, want all verified capabilities", capabilities)
	}
	fake.mu.Lock()
	fake.versioningEnabled = false
	fake.mu.Unlock()
	if err := store.Ready(t.Context()); err == nil {
		t.Fatal("Ready() error = nil after versioning was suspended")
	}
	if capabilities := store.Capabilities(); capabilities != (errorpagecontrol.ObjectStoreCapabilities{}) {
		t.Fatalf("Capabilities() = %+v after failed Ready, want fail-closed zero value", capabilities)
	}
}

func TestPutStatOpenFinalizeDeleteContract(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	body := []byte("immutable error page")
	stagingKey := "error-pages/staging/019f9d75-486f-7df1-a972-112233445566"
	finalKey := "error-pages/objects/019f9d75-486f-7df1-a972-112233445566/" + strings.Repeat("a", 64)

	staged, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), body, "text/plain")
	if err != nil || replayed != staged {
		t.Fatalf("idempotent PutStaging() = (%+v, %v), want %+v", replayed, err, staged)
	}
	if _, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), []byte("different"), "text/plain"); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("different PutStaging() error = %v, want conflict", err)
	}
	stat, err := store.Stat(t.Context(), testObjectRef(stagingKey))
	if err != nil || stat != staged {
		t.Fatalf("Stat() = (%+v, %v), want %+v", stat, err, staged)
	}
	reader, err := store.Open(t.Context(), testObjectRef(stagingKey), staged.ImmutableToken)
	if err != nil {
		t.Fatal(err)
	}
	opened, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(opened, body) {
		t.Fatalf("Open() body = %q, read=%v close=%v", opened, readErr, closeErr)
	}
	if _, err := store.Open(t.Context(), testObjectRef(stagingKey), "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Open(wrong token) error = %v, want conflict", err)
	}

	final, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), staged)
	if err != nil || final != staged {
		t.Fatalf("Finalize() = (%+v, %v), want %+v", final, err, staged)
	}
	replayedFinal, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), staged)
	if err != nil || replayedFinal != staged {
		t.Fatalf("idempotent Finalize() = (%+v, %v), want %+v", replayedFinal, err, staged)
	}
	if after, err := store.Stat(t.Context(), testObjectRef(stagingKey)); err != nil || after != staged {
		t.Fatalf("staging alias not preserved: (%+v, %v)", after, err)
	}

	if err := store.Delete(t.Context(), testObjectRef(finalKey)); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context(), testObjectRef(finalKey)); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("second Delete() error = %v, want not found", err)
	}
}

func TestBrandAssetImageMIMEsRoundTrip(t *testing.T) {
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	for index, mimeType := range []string{"image/png", "image/jpeg", "image/x-icon", "image/vnd.microsoft.icon"} {
		body := []byte(fmt.Sprintf("brand-asset-%d", index))
		key := fmt.Sprintf("brand-assets/staging/image-%d", index)
		info, err := store.PutStaging(t.Context(), testObjectRef(key), body, mimeType)
		if err != nil || info.MIMEType != mimeType {
			t.Fatalf("PutStaging(%s) = (%+v, %v)", mimeType, info, err)
		}
		reader, err := store.Open(t.Context(), testObjectRef(key), info.ImmutableToken)
		if err != nil {
			t.Fatalf("Open(%s) error = %v", mimeType, err)
		}
		opened, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(opened, body) {
			t.Fatalf("Open(%s) body = %q, read=%v close=%v", mimeType, opened, readErr, closeErr)
		}
	}
	if _, err := store.PutStaging(t.Context(), testObjectRef("brand-assets/staging/gif"), []byte("gif"), "image/gif"); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("PutStaging(image/gif) error = %v, want invalid object", err)
	}
}

func TestObjectRefsEnforceCanonicalTenantAndScopeIsolation(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	logicalKey := "error-pages/staging/scoped-object"
	ref := testObjectRef(logicalKey)
	info, err := store.PutStaging(t.Context(), ref, []byte("scoped"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	_, canonicalExists := fake.objects[testPhysicalKey(logicalKey)]
	fake.mu.Unlock()
	if !canonicalExists {
		t.Fatalf("canonical object %q does not exist", testPhysicalKey(logicalKey))
	}
	platformScopeID := uuid.MustParse("019f9d75-486f-7df1-a972-fedcba987654")
	platformRef := errorpagecontrol.ObjectRef{ScopeID: platformScopeID, LogicalKey: "error-pages/staging/platform-object"}
	if _, err := store.PutStaging(t.Context(), platformRef, []byte("platform"), "text/plain"); err != nil {
		t.Fatalf("PutStaging(platform ref) error = %v", err)
	}
	platformKey := "control-api/error-pages/platform/scopes/" + platformScopeID.String() + "/" + platformRef.LogicalKey
	fake.mu.Lock()
	_, platformExists := fake.objects[platformKey]
	fake.mu.Unlock()
	if !platformExists {
		t.Fatalf("canonical platform object %q does not exist", platformKey)
	}

	otherTenantID := uuid.MustParse("019f9d75-486f-7df1-a972-aabbccddeeff")
	otherTenant := errorpagecontrol.ObjectRef{TenantID: &otherTenantID, ScopeID: ref.ScopeID, LogicalKey: logicalKey}
	if _, err := store.Open(t.Context(), otherTenant, info.ImmutableToken); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("Open(cross-tenant ref) error = %v, want not found", err)
	}
	if err := store.Delete(t.Context(), otherTenant); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("Delete(cross-tenant ref) error = %v, want not found", err)
	}
	if _, err := store.Stat(t.Context(), ref); err != nil {
		t.Fatalf("cross-tenant access changed owner object: %v", err)
	}
	if _, err := store.Finalize(t.Context(), ref,
		errorpagecontrol.ObjectRef{TenantID: &otherTenantID, ScopeID: ref.ScopeID, LogicalKey: "error-pages/objects/cross-tenant"}, info); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("Finalize(cross-tenant refs) error = %v, want invalid object", err)
	}
	otherScope := errorpagecontrol.ObjectRef{TenantID: ref.TenantID, ScopeID: uuid.New(), LogicalKey: "error-pages/objects/cross-scope"}
	if _, err := store.Finalize(t.Context(), ref, otherScope, info); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("Finalize(cross-scope refs) error = %v, want invalid object", err)
	}

	nilTenantID := uuid.Nil
	invalidRefs := []errorpagecontrol.ObjectRef{
		{TenantID: ref.TenantID, LogicalKey: logicalKey},
		{TenantID: &nilTenantID, ScopeID: ref.ScopeID, LogicalKey: logicalKey},
		{TenantID: ref.TenantID, ScopeID: ref.ScopeID},
		{TenantID: ref.TenantID, ScopeID: ref.ScopeID, LogicalKey: "../escape"},
		{TenantID: ref.TenantID, ScopeID: ref.ScopeID, LogicalKey: "/absolute"},
	}
	for index, invalid := range invalidRefs {
		if _, err := store.Stat(t.Context(), invalid); err == nil {
			t.Fatalf("invalid ref %d was accepted", index)
		}
	}
}

func TestConcurrentPutAndFinalizeAreLinearizable(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	stagingKey := "error-pages/staging/019f9d75-486f-7df1-a972-223344556677"
	finalKey := "error-pages/objects/019f9d75-486f-7df1-a972-223344556677/" + strings.Repeat("b", 64)
	body := []byte("same body")

	putResults := make(chan error, 16)
	var staged errorpagecontrol.ObjectInfo
	var stagedMu sync.Mutex
	for range 16 {
		go func() {
			info, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), body, "text/plain")
			if err == nil {
				stagedMu.Lock()
				if staged.ImmutableToken == "" {
					staged = info
				} else if staged != info {
					err = fmt.Errorf("non-linearizable info: %+v != %+v", info, staged)
				}
				stagedMu.Unlock()
			}
			putResults <- err
		}()
	}
	for range 16 {
		if err := <-putResults; err != nil {
			t.Fatal(err)
		}
	}

	finalResults := make(chan error, 16)
	for range 16 {
		go func() {
			info, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), staged)
			if err == nil && info != staged {
				err = fmt.Errorf("final info: %+v != %+v", info, staged)
			}
			finalResults <- err
		}()
	}
	for range 16 {
		if err := <-finalResults; err != nil {
			t.Fatal(err)
		}
	}
}

func TestConcurrentDivergentPutAndFinalizeHaveSingleContentWinner(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	putKey := "error-pages/staging/019f9d75-486f-7df1-a972-778899001122"
	putResults := make(chan struct {
		info errorpagecontrol.ObjectInfo
		err  error
	}, 16)
	for index := range 16 {
		body := []byte("content-a")
		if index%2 == 1 {
			body = []byte("content-b")
		}
		go func() {
			info, err := store.PutStaging(t.Context(), testObjectRef(putKey), body, "text/plain")
			putResults <- struct {
				info errorpagecontrol.ObjectInfo
				err  error
			}{info, err}
		}()
	}
	winnerDigest := ""
	conflicts := 0
	for range 16 {
		result := <-putResults
		switch {
		case result.err == nil:
			if winnerDigest == "" {
				winnerDigest = result.info.SHA256
			} else if result.info.SHA256 != winnerDigest {
				t.Fatalf("two divergent PutStaging winners: %s and %s", winnerDigest, result.info.SHA256)
			}
		case errors.Is(result.err, errorpagecontrol.ErrConflict):
			conflicts++
		default:
			t.Fatalf("PutStaging() unexpected error = %v", result.err)
		}
	}
	if winnerDigest == "" || conflicts == 0 {
		t.Fatalf("winner digest = %q conflicts = %d", winnerDigest, conflicts)
	}

	stagingA := "error-pages/staging/019f9d75-486f-7df1-a972-889900112233"
	stagingB := "error-pages/staging/019f9d75-486f-7df1-a972-990011223344"
	infoA, err := store.PutStaging(t.Context(), testObjectRef(stagingA), []byte("final-a"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := store.PutStaging(t.Context(), testObjectRef(stagingB), []byte("final-b"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	finalKey := "error-pages/objects/019f9d75-486f-7df1-a972-889900112233/" + strings.Repeat("c", 64)
	finalResults := make(chan error, 2)
	go func() {
		_, err := store.Finalize(t.Context(), testObjectRef(stagingA), testObjectRef(finalKey), infoA)
		finalResults <- err
	}()
	go func() {
		_, err := store.Finalize(t.Context(), testObjectRef(stagingB), testObjectRef(finalKey), infoB)
		finalResults <- err
	}()
	successes, finalizeConflicts := 0, 0
	for range 2 {
		switch err := <-finalResults; {
		case err == nil:
			successes++
		case errors.Is(err, errorpagecontrol.ErrConflict):
			finalizeConflicts++
		default:
			t.Fatalf("Finalize() unexpected error = %v", err)
		}
	}
	if successes != 1 || finalizeConflicts != 1 {
		t.Fatalf("Finalize outcomes: successes=%d conflicts=%d", successes, finalizeConflicts)
	}
}

func TestFinalizeRejectsDifferentSourceWithIdenticalContent(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	body := []byte("identical")
	stagingA := "error-pages/staging/019f9d75-486f-7df1-a972-001122334455"
	stagingB := "error-pages/staging/019f9d75-486f-7df1-a972-112233445566"
	finalKey := "error-pages/objects/019f9d75-486f-7df1-a972-001122334455/" + strings.Repeat("d", 64)
	infoA, err := store.PutStaging(t.Context(), testObjectRef(stagingA), body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := store.PutStaging(t.Context(), testObjectRef(stagingB), body, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingA), testObjectRef(finalKey), infoA); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	sourceObject := fake.objects[testPhysicalKey(stagingA)]
	finalObject := fake.objects[testPhysicalKey(finalKey)]
	fake.mu.Unlock()
	if finalObject.metadata[metadataSourceID] != sourceObject.metadata[metadataSourceID] ||
		finalObject.metadata[metadataSourceKey] != testPhysicalKey(stagingA) ||
		finalObject.metadata[metadataSourceVersion] != sourceObject.versionID ||
		finalObject.metadata[metadataSourceETag] != sourceObject.etag {
		t.Fatalf("final source metadata = %#v, source = %#v", finalObject.metadata, sourceObject)
	}
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingB), testObjectRef(finalKey), infoB); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Finalize(different source, identical content) error = %v, want conflict", err)
	}
}

func TestFinalizeRejectsTamperedPersistedSourceIdentity(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	stagingKey := "error-pages/staging/tampered-source"
	finalKey := "error-pages/objects/tampered-source/" + strings.Repeat("e", 64)
	info, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), []byte("tamper"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), info); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	object := fake.objects[testPhysicalKey(finalKey)]
	object.metadata = cloneMetadata(object.metadata)
	object.metadata[metadataSourceVersion] = "wrong-version"
	fake.objects[testPhysicalKey(finalKey)] = object
	fake.mu.Unlock()
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), info); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Finalize(tampered source identity) error = %v, want conflict", err)
	}
}

func TestReadyAndFinalizeVerifyChecksumOmittingObjectsByContent(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.omitFinalChecksums = true
	fake.requireBoundGet = true
	store, _ := newTestStore(t, fake)
	stagingKey := "error-pages/staging/minio-checksum-compatibility"
	finalKey := "error-pages/objects/minio-checksum-compatibility/" + strings.Repeat("f", 64)
	body := []byte("checksum verified locally")
	info, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), body, "text/plain")
	if err != nil {
		t.Fatalf("PutStaging() error = %v", err)
	}
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), info); err != nil {
		t.Fatalf("Finalize(checksum-omitting copy) error = %v", err)
	}
	if err := store.Ready(t.Context()); err != nil {
		t.Fatalf("Ready(checksum-omitting copies) error = %v", err)
	}
}

func TestChecksumOmittingObjectRejectsBodyMismatch(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.omitFinalChecksums = true
	fake.requireBoundGet = true
	store, _ := newTestStore(t, fake)
	stagingKey := "error-pages/staging/minio-checksum-corrupt"
	finalKey := "error-pages/objects/minio-checksum-corrupt/" + strings.Repeat("a", 64)
	info, err := store.PutStaging(t.Context(), testObjectRef(stagingKey), []byte("trusted"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finalize(t.Context(), testObjectRef(stagingKey), testObjectRef(finalKey), info); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.getBodyOverrides[testPhysicalKey(finalKey)] = []byte("corrupt")
	fake.mu.Unlock()
	if _, err := store.Stat(t.Context(), testObjectRef(finalKey)); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Stat(corrupt checksum-omitting copy) error = %v, want conflict", err)
	}
}

func TestReadyRejectsBackendThatIgnoresPutDestinationCondition(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.ignorePutCondition = true
	server := httptest.NewServer(fake)
	defer server.Close()
	if store, err := New(t.Context(), validConfig(server.URL)); err == nil || store != nil {
		t.Fatalf("New() = (%v, %v), want nil and error", store, err)
	}
}

func TestReadyRevokesCapabilitiesAndCleansProbeObjectsOnConditionalFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeS3)
	}{
		{name: "destination condition", mutate: func(fake *fakeS3) { fake.ignorePutCondition = true }},
		{name: "get source version", mutate: func(fake *fakeS3) { fake.ignoreGetVersion = true }},
		{name: "get source etag", mutate: func(fake *fakeS3) { fake.ignoreGetETag = true }},
		{name: "get body checksum", mutate: func(fake *fakeS3) { fake.tamperReadyGet = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeS3()
			store, _ := newTestStore(t, fake)
			fake.mu.Lock()
			test.mutate(fake)
			fake.mu.Unlock()
			if err := store.Ready(t.Context()); err == nil {
				t.Fatal("Ready() error = nil")
			}
			if capabilities := store.Capabilities(); capabilities != (errorpagecontrol.ObjectStoreCapabilities{}) {
				t.Fatalf("Capabilities() = %+v, want zero value", capabilities)
			}
			fake.mu.Lock()
			leaked := ""
			for key := range fake.objects {
				if strings.Contains(key, "/ready/") {
					leaked = key
					break
				}
			}
			fake.mu.Unlock()
			if leaked != "" {
				t.Fatalf("readiness object leaked: %s", leaked)
			}
		})
	}
}

func TestReadyDoesNotRequireCopyObjectSemantics(t *testing.T) {
	fake := newFakeS3()
	fake.rejectCopy = true
	server := httptest.NewServer(fake)
	defer server.Close()
	store, err := New(t.Context(), validConfig(server.URL))
	if err != nil || store == nil {
		t.Fatalf("New(copy-unsupported provider) = (%v, %v), want ready store", store, err)
	}
	fake.mu.Lock()
	copyCalls := fake.copyCalls
	fake.mu.Unlock()
	if copyCalls != 0 {
		t.Fatalf("readiness CopyObject calls = %d, want 0", copyCalls)
	}
}

func TestReadyCleanupRemovesOnlyProbeVersionsAndDeleteMarkers(t *testing.T) {
	t.Run("paginated versions and delete markers preserve foreign", func(t *testing.T) {
		fake := newFakeS3()
		fake.listPageSize = 1
		fake.seedReadyMarkers = true
		fake.seedReadyForeign = true
		server := httptest.NewServer(fake)
		defer server.Close()
		config := validConfig(server.URL)
		store := &Store{
			client: s3.NewFromConfig(aws.Config{
				Region: config.Region, Credentials: aws.NewCredentialsCache(config.Credentials), HTTPClient: server.Client(),
			}, func(options *s3.Options) {
				options.BaseEndpoint = aws.String(server.URL)
				options.UsePathStyle = true
			}),
			bucket: config.Bucket, prefix: config.Prefix, maxSize: config.MaxObjectSize, cleanupTimeout: config.RequestTimeout,
		}
		if err := store.Ready(t.Context()); err != nil {
			t.Fatalf("Ready() error = %v", err)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		foreignKey := fake.readyForeignKey
		if got := fake.versions[foreignKey]; foreignKey == "" || len(got) != 1 || got[0].deleteMarker {
			t.Fatalf("foreign version under readiness prefix changed: key=%q versions=%#v", foreignKey, got)
		}
		for key, versions := range fake.versions {
			if strings.Contains(key, "/ready/") && key != foreignKey && len(versions) != 0 {
				t.Fatalf("readiness versions or delete markers leaked for %q: %#v", key, versions)
			}
		}
		if fake.continuedListCalls < 2 || fake.continuedVersions == 0 || fake.continuedMarkers == 0 || fake.continuedListCalls > 32 {
			t.Fatalf("pagination evidence = calls:%d versions:%d markers:%d", fake.continuedListCalls, fake.continuedVersions, fake.continuedMarkers)
		}
	})

	for _, failure := range []string{"list-page-2", "delete-version", "delete-marker", "final-verify"} {
		t.Run(failure+" failure revokes prior capabilities", func(t *testing.T) {
			fake := newFakeS3()
			store, _ := newTestStore(t, fake)
			if capabilities := store.Capabilities(); !capabilities.ImmutableStaging {
				t.Fatalf("Capabilities() before failed recheck = %+v, want enabled", capabilities)
			}
			fake.mu.Lock()
			fake.listPageSize = 1
			fake.seedReadyMarkers = true
			fake.cleanupFailure = failure
			fake.mu.Unlock()
			err := store.Ready(t.Context())
			if !errors.Is(err, errorpagecontrol.ErrUnavailable) {
				t.Fatalf("Ready() error = %v, want typed unavailable", err)
			}
			if capabilities := store.Capabilities(); capabilities != (errorpagecontrol.ObjectStoreCapabilities{}) {
				t.Fatalf("Capabilities() = %+v after cleanup failure, want zero value", capabilities)
			}
			message := err.Error()
			if strings.Contains(message, "/ready/") || strings.Contains(message, "v-") || strings.Contains(message, "forced cleanup") {
				t.Fatalf("Ready() leaked cleanup provider details: %q", message)
			}
		})
	}
}

func TestReadyRejectsMalformedListObjectVersionsContinuation(t *testing.T) {
	for _, test := range []struct {
		name string
		mode string
	}{
		{name: "empty next key marker", mode: "empty-key"},
		{name: "empty next version id marker", mode: "empty-version"},
		{name: "repeated current pair", mode: "repeat-current"},
		{name: "cycle to historical pair", mode: "cycle-history"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeS3()
			store, _ := newTestStore(t, fake)
			fake.mu.Lock()
			fake.listPageSize = 1
			fake.malformedContinuation = test.mode
			fake.listCalls = 0
			fake.malformedFirstKey = ""
			fake.malformedFirstVersion = ""
			fake.mu.Unlock()

			err := store.Ready(t.Context())
			if !errors.Is(err, errorpagecontrol.ErrUnavailable) {
				t.Fatalf("Ready() error = %v, want typed unavailable", err)
			}
			if capabilities := store.Capabilities(); capabilities != (errorpagecontrol.ObjectStoreCapabilities{}) {
				t.Fatalf("Capabilities() = %+v after malformed continuation, want zero value", capabilities)
			}
			fake.mu.Lock()
			listCalls := fake.listCalls
			fake.mu.Unlock()
			if listCalls == 0 || listCalls > 8 {
				t.Fatalf("ListObjectVersions calls = %d, want 1..8", listCalls)
			}
			message := err.Error()
			for _, leaked := range []string{
				"NextKeyMarker", "NextVersionIdMarker", "key-marker", "version-id-marker",
				"/ready/", "v-", "http://", "https://", "provider",
			} {
				if strings.Contains(message, leaked) {
					t.Fatalf("Ready() leaked continuation/provider detail %q: %q", leaked, message)
				}
			}
		})
	}
}

type readinessGetErrorS3 struct {
	s3API
	err          error
	rejectedOnly bool
}

func (client readinessGetErrorS3) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(input.Key)
	versionID := aws.ToString(input.VersionId)
	etag := aws.ToString(input.IfMatch)
	rejected := !strings.HasPrefix(versionID, "v-") || etag == `"00000000000000000000000000000000"`
	if strings.Contains(key, "/ready/") && (!client.rejectedOnly || rejected) {
		return nil, client.err
	}
	return client.s3API.GetObject(ctx, input, options...)
}

type canceledReadS3 struct {
	s3API
	versioning    *s3.GetBucketVersioningOutput
	versioningErr error
	head          *s3.HeadObjectOutput
	get           *s3.GetObjectOutput
	getErr        error
}

func (client canceledReadS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return client.versioning, client.versioningErr
}

func (client canceledReadS3) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return client.head, nil
}

func (client canceledReadS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return client.get, client.getErr
}

type canceledReadCloser struct {
	read bool
}

func (reader *canceledReadCloser) Read(target []byte) (int, error) {
	if reader.read {
		return 0, context.Canceled
	}
	reader.read = true
	return copy(target, "partial"), context.Canceled
}

func (*canceledReadCloser) Close() error { return nil }

type deadlineReadCloser struct{}

func (*deadlineReadCloser) Read([]byte) (int, error) { return 0, context.DeadlineExceeded }
func (*deadlineReadCloser) Close() error             { return nil }

func TestReadyRejectsNilVersioningOutputWithoutPanic(t *testing.T) {
	store := &Store{client: canceledReadS3{}, bucket: "error-pages", prefix: "control-api/error-pages", maxSize: 1024}
	var readyErr error
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		readyErr = store.Ready(t.Context())
	}()
	if panicked || !errors.Is(readyErr, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("Ready(nil versioning output) = panic:%t error:%v, want typed unavailable", panicked, readyErr)
	}
}

func TestReadyPropagatesVersioningContextErrors(t *testing.T) {
	for _, contextErr := range []error{context.Canceled, context.DeadlineExceeded} {
		store := &Store{
			client: canceledReadS3{versioningErr: contextErr}, bucket: "error-pages",
			prefix: "control-api/error-pages", maxSize: 1024,
		}
		if err := store.Ready(t.Context()); !errors.Is(err, contextErr) {
			t.Fatalf("Ready(%v) error = %v, want context error", contextErr, err)
		}
	}
	for _, test := range []struct {
		name         string
		contextErr   error
		rejectedOnly bool
	}{
		{name: "formal get canceled", contextErr: context.Canceled},
		{name: "formal get deadline", contextErr: context.DeadlineExceeded},
		{name: "rejected get canceled", contextErr: context.Canceled, rejectedOnly: true},
		{name: "rejected get deadline", contextErr: context.DeadlineExceeded, rejectedOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeS3()
			store, _ := newTestStore(t, fake)
			store.client = readinessGetErrorS3{s3API: store.client, err: test.contextErr, rejectedOnly: test.rejectedOnly}
			if err := store.Ready(t.Context()); !errors.Is(err, test.contextErr) {
				t.Fatalf("Ready() error = %v, want %v", err, test.contextErr)
			}
			if capabilities := store.Capabilities(); capabilities != (errorpagecontrol.ObjectStoreCapabilities{}) {
				t.Fatalf("Capabilities() = %+v after context failure, want zero value", capabilities)
			}
		})
	}
}

func TestStatRejectsNilHeadOutput(t *testing.T) {
	t.Parallel()
	store := &Store{client: canceledReadS3{}, bucket: "error-pages", prefix: "control-api/error-pages", maxSize: 1024}
	store.ready.Store(true)
	if _, err := store.Stat(t.Context(), testObjectRef("error-pages/staging/nil-head")); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Stat(nil HEAD output) error = %v, want conflict", err)
	}
}

func TestOpenPrioritizesContextCancellationOverIntegrityFailure(t *testing.T) {
	t.Parallel()
	body := []byte("complete-body")
	digest := sha256.Sum256(body)
	info := errorpagecontrol.ObjectInfo{
		Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), MIMEType: "text/plain",
		ImmutableToken: "sha256:" + hex.EncodeToString(digest[:]),
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	ref := testObjectRef("error-pages/staging/cancel")
	fullKey := testPhysicalKey(ref.LogicalKey)
	metadata := objectMetadata(info, fullKey, objectSource{id: strings.Repeat("1", 64)})
	head := &s3.HeadObjectOutput{
		ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-cancel"),
	}
	get := &s3.GetObjectOutput{
		Body: &canceledReadCloser{}, ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-cancel"),
	}
	store := &Store{client: canceledReadS3{head: head, get: get}, bucket: "error-pages", prefix: "control-api/error-pages", maxSize: 1 << 20}
	store.ready.Store(true)
	if _, err := store.Open(t.Context(), ref, info.ImmutableToken); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context.Canceled", err)
	}
}

func TestOpenRejectsNilGetOutputAndBodyWithoutPanic(t *testing.T) {
	body := []byte("complete-body")
	digest := sha256.Sum256(body)
	info := errorpagecontrol.ObjectInfo{
		Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), MIMEType: "text/plain",
		ImmutableToken: "sha256:" + hex.EncodeToString(digest[:]),
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	ref := testObjectRef("error-pages/staging/nil-get")
	fullKey := testPhysicalKey(ref.LogicalKey)
	metadata := objectMetadata(info, fullKey, objectSource{id: strings.Repeat("2", 64)})
	head := &s3.HeadObjectOutput{
		ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-nil"),
	}
	for _, test := range []struct {
		name string
		get  *s3.GetObjectOutput
	}{
		{name: "nil output"},
		{name: "nil body", get: &s3.GetObjectOutput{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &Store{client: canceledReadS3{head: head, get: test.get}, bucket: "error-pages", prefix: "control-api/error-pages", maxSize: 1 << 20}
			store.ready.Store(true)
			var openErr error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				_, openErr = store.Open(t.Context(), ref, info.ImmutableToken)
			}()
			if panicked || !errors.Is(openErr, errorpagecontrol.ErrConflict) {
				t.Fatalf("Open(%s) = panic:%t error:%v, want typed conflict", test.name, panicked, openErr)
			}
		})
	}
}

func TestOpenPropagatesCanceledAndDeadlineContexts(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	store := &Store{}
	if _, err := store.Open(canceled, testObjectRef("error-pages/staging/canceled-before-ready"), "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(canceled before ready) error = %v, want context.Canceled", err)
	}

	body := []byte("complete-body")
	digest := sha256.Sum256(body)
	info := errorpagecontrol.ObjectInfo{
		Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), MIMEType: "text/plain",
		ImmutableToken: "sha256:" + hex.EncodeToString(digest[:]),
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	ref := testObjectRef("error-pages/staging/deadline")
	fullKey := testPhysicalKey(ref.LogicalKey)
	metadata := objectMetadata(info, fullKey, objectSource{id: strings.Repeat("3", 64)})
	head := &s3.HeadObjectOutput{
		ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-deadline"),
	}
	get := &s3.GetObjectOutput{
		Body: &deadlineReadCloser{}, ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-deadline"),
	}
	store = &Store{client: canceledReadS3{head: head, get: get}, bucket: "error-pages", prefix: "control-api/error-pages", maxSize: 1 << 20}
	store.ready.Store(true)
	if _, err := store.Open(t.Context(), ref, info.ImmutableToken); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Open(deadline body) error = %v, want context.DeadlineExceeded", err)
	}
}

func TestOpenPropagatesGetObjectContextErrors(t *testing.T) {
	body := []byte("complete-body")
	digest := sha256.Sum256(body)
	info := errorpagecontrol.ObjectInfo{
		Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), MIMEType: "text/plain",
		ImmutableToken: "sha256:" + hex.EncodeToString(digest[:]),
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	ref := testObjectRef("error-pages/staging/get-context")
	fullKey := testPhysicalKey(ref.LogicalKey)
	metadata := objectMetadata(info, fullKey, objectSource{id: strings.Repeat("4", 64)})
	head := &s3.HeadObjectOutput{
		ContentLength: aws.Int64(info.Size), ContentType: aws.String(info.MIMEType), Metadata: metadata,
		ChecksumSHA256: aws.String(checksum), ETag: aws.String(`"0123456789abcdef0123456789abcdef"`), VersionId: aws.String("v-context"),
	}
	for _, contextErr := range []error{context.Canceled, context.DeadlineExceeded} {
		store := &Store{
			client: canceledReadS3{head: head, getErr: contextErr}, bucket: "error-pages",
			prefix: "control-api/error-pages", maxSize: 1 << 20,
		}
		store.ready.Store(true)
		if _, err := store.Open(t.Context(), ref, info.ImmutableToken); !errors.Is(err, contextErr) {
			t.Fatalf("Open(GetObject %v) error = %v, want context error", contextErr, err)
		}
	}
}

func TestRetryCancellationAndErrorRedaction(t *testing.T) {
	t.Parallel()
	const secret = "server-must-not-escape"
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	key := "error-pages/staging/019f9d75-486f-7df1-a972-334455667788"
	fullKey := testPhysicalKey(key)
	fake.mu.Lock()
	fake.putFailures[fullKey] = 1
	fake.mu.Unlock()
	if _, err := store.PutStaging(t.Context(), testObjectRef(key), []byte("retry"), "text/plain"); err != nil {
		t.Fatalf("retrying PutStaging() error = %v", err)
	}
	fake.mu.Lock()
	putCalls := fake.putCalls[fullKey]
	fake.mu.Unlock()
	if putCalls != 2 {
		t.Fatalf("put calls = %d, want 2", putCalls)
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.PutStaging(cancelled, testObjectRef(key+"-cancel"), []byte("cancel"), "text/plain"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled PutStaging() error = %v, want context.Canceled", err)
	}

	malicious := newFakeS3()
	malicious.maliciousVersion = `<VersioningConfiguration><Status>` + secret + `</Status></VersioningConfiguration>`
	server := httptest.NewServer(malicious)
	defer server.Close()
	_, err := New(t.Context(), validConfig(server.URL))
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "explicit-secret") {
		t.Fatalf("New() returned unsafe error: %v", err)
	}
}

func TestReadyDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	fake := newFakeS3()
	fake.redirectLocation = target.URL + "/credential-capture"
	server := httptest.NewServer(fake)
	defer server.Close()
	if _, err := New(t.Context(), validConfig(server.URL)); err == nil {
		t.Fatal("New() error = nil, want redirect rejection")
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}
}

func TestTransportUsesTLS12DedicatedCAAndNoProxy(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	server := httptest.NewUnstartedServer(fake)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	config := validConfig(server.URL)
	config.CACertificatePEM = certificatePEM
	if _, err := New(t.Context(), config); err != nil {
		t.Fatalf("New(custom CA) error = %v", err)
	}
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	client := newHTTPClient(validated)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		transport.TLSClientConfig.RootCAs == validated.roots {
		t.Fatalf("unsafe transport: %#v", transport)
	}
}

func TestExplicitProviderPreventsEnvironmentSharedConfigAndMetadataFallback(t *testing.T) {
	const secret = "ambient-credential-secret"
	metadataRequests := atomic.Int64{}
	metadata := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		metadataRequests.Add(1)
	}))
	defer metadata.Close()
	credentialsFile := t.TempDir() + "/credentials"
	if err := os.WriteFile(credentialsFile, []byte("[default]\naws_access_key_id="+secret+"\naws_secret_access_key="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", secret)
	t.Setenv("AWS_SECRET_ACCESS_KEY", secret)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsFile)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", metadata.URL)
	fake := newFakeS3()
	server := httptest.NewServer(fake)
	defer server.Close()
	config := validConfig(server.URL)
	config.Credentials = credentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("provider failure " + secret)
	})
	_, err := New(t.Context(), config)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("New() returned unsafe credential error: %v", err)
	}
	if metadataRequests.Load() != 0 {
		t.Fatalf("metadata requests = %d, want 0", metadataRequests.Load())
	}
	fake.mu.Lock()
	requests := len(fake.requests)
	fake.mu.Unlock()
	if requests != 0 {
		t.Fatalf("signed S3 requests = %d, want 0 with rejected explicit credentials", requests)
	}
}

func TestTypedUnavailableAndNotFoundMapping(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	missingKey := "error-pages/staging/019f9d75-486f-7df1-a972-556677889900"
	if _, err := store.Stat(t.Context(), testObjectRef(missingKey)); !errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("Stat(missing) error = %v, want not found", err)
	}
	fullKey := testPhysicalKey(missingKey)
	fake.mu.Lock()
	fake.putFailures[fullKey] = 10
	fake.mu.Unlock()
	if _, err := store.PutStaging(t.Context(), testObjectRef(missingKey), []byte("unavailable"), "text/plain"); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("PutStaging(500) error = %v, want unavailable", err)
	}

	missingBucket := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		newFakeS3().writeError(response, http.StatusNotFound, "NoSuchBucket", "sensitive backend detail")
	}))
	defer missingBucket.Close()
	_, err := New(t.Context(), validConfig(missingBucket.URL))
	if !errors.Is(err, errorpagecontrol.ErrUnavailable) || errors.Is(err, errorpagecontrol.ErrObjectNotFound) {
		t.Fatalf("New(missing bucket) error = %v, want unavailable only", err)
	}
}

func TestDeleteHandlesCommitRetryWindowAndTypedFailures(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	put := func(key string) {
		t.Helper()
		if _, err := store.PutStaging(t.Context(), testObjectRef(key), []byte("delete"), "text/plain"); err != nil {
			t.Fatal(err)
		}
	}

	committedKey := "error-pages/staging/019f9d75-486f-7df1-a972-aabbccddeeff"
	put(committedKey)
	fake.mu.Lock()
	fake.deleteCommitError[testPhysicalKey(committedKey)] = true
	fake.mu.Unlock()
	if err := store.Delete(t.Context(), testObjectRef(committedKey)); err != nil {
		t.Fatalf("Delete(committed before 500) error = %v", err)
	}

	conflictKey := "error-pages/staging/019f9d75-486f-7df1-a972-bbccddeeff00"
	put(conflictKey)
	fake.mu.Lock()
	fake.deleteConflicts[testPhysicalKey(conflictKey)] = true
	fake.mu.Unlock()
	if err := store.Delete(t.Context(), testObjectRef(conflictKey)); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Delete(conflict) error = %v, want conflict", err)
	}

	unavailableKey := "error-pages/staging/019f9d75-486f-7df1-a972-ccddeeff0011"
	put(unavailableKey)
	fake.mu.Lock()
	fake.deleteFailures[testPhysicalKey(unavailableKey)] = 10
	fake.mu.Unlock()
	if err := store.Delete(t.Context(), testObjectRef(unavailableKey)); !errors.Is(err, errorpagecontrol.ErrUnavailable) {
		t.Fatalf("Delete(unavailable) error = %v, want unavailable", err)
	}
}

func TestStatRejectsUntrustedMetadataAndMultipartETag(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	key := "error-pages/staging/019f9d75-486f-7df1-a972-445566778899"
	if _, err := store.PutStaging(t.Context(), testObjectRef(key), []byte("trusted"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	fullKey := testPhysicalKey(key)
	mutations := []func(*fakeS3Object){
		func(object *fakeS3Object) { object.metadata["cdnca-sha256"] = strings.Repeat("0", 64) },
		func(object *fakeS3Object) { object.metadata[metadataObjectKey] = "other/tenant/object" },
		func(object *fakeS3Object) { object.metadata[metadataSourceID] = strings.Repeat("0", 63) },
		func(object *fakeS3Object) { object.metadata[metadataSourceKey] = "unexpected/source" },
		func(object *fakeS3Object) {
			object.checksum = base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
		},
		func(object *fakeS3Object) { object.etag = `"0123456789abcdef0123456789abcdef-2"` },
		func(object *fakeS3Object) { object.versionID = "" },
	}
	for index, mutate := range mutations {
		fake.mu.Lock()
		original := fake.objects[fullKey]
		changed := original
		changed.metadata = cloneMetadata(original.metadata)
		mutate(&changed)
		fake.objects[fullKey] = changed
		fake.mu.Unlock()
		if _, err := store.Stat(t.Context(), testObjectRef(key)); !errors.Is(err, errorpagecontrol.ErrConflict) {
			t.Fatalf("mutation %d Stat() error = %v, want conflict", index, err)
		}
		fake.mu.Lock()
		fake.objects[fullKey] = original
		fake.mu.Unlock()
	}
	const headerSecret = "malicious-header-secret"
	fake.mu.Lock()
	object := fake.objects[fullKey]
	object.etag = `"` + headerSecret + `"`
	fake.objects[fullKey] = object
	fake.mu.Unlock()
	if _, err := store.Stat(t.Context(), testObjectRef(key)); err == nil || strings.Contains(err.Error(), headerSecret) {
		t.Fatalf("Stat(malicious header) unsafe error = %v", err)
	}
}

func TestOpenRejectsBodyThatDoesNotMatchBoundChecksum(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store, _ := newTestStore(t, fake)
	key := "error-pages/staging/019f9d75-486f-7df1-a972-667788990011"
	info, err := store.PutStaging(t.Context(), testObjectRef(key), []byte("trusted"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.getBodyOverrides[testPhysicalKey(key)] = []byte("corrupt")
	fake.mu.Unlock()
	if _, err := store.Open(t.Context(), testObjectRef(key), info.ImmutableToken); !errors.Is(err, errorpagecontrol.ErrConflict) {
		t.Fatalf("Open(corrupt body) error = %v, want conflict", err)
	}
}

func cloneMetadata(metadata map[string]string) map[string]string {
	clone := make(map[string]string, len(metadata))
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		clone[key] = metadata[key]
	}
	return clone
}
