package jobhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNumberedPageScopeFiltersBoundariesAndLegacyCompatibility(t *testing.T) {
	tenantA, tenantB, scopeA := uuid.New(), uuid.New(), uuid.New()
	reader := &fixtureReader{scopeTenants: map[uuid.UUID]uuid.UUID{scopeA: tenantA}}
	for index := range 7 {
		tenantID, state := tenantA, StateQueued
		if index == 5 {
			tenantID = tenantB
		}
		if index == 6 {
			state = StateFailed
		}
		job := fixtureJob(uuid.New(), tenantID, state, fixtureNow.Add(-time.Duration(index)*time.Minute))
		job.Kind = "cache.operation"
		reader.jobs = append(reader.jobs, job)
	}
	service := fixtureService(reader)
	request := fixtureListRequest(AudienceTenant)
	request.Page, request.Limit, request.States, request.Kind = 2, 2, []State{StateQueued}, "cache.operation"
	page, err := service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || page.Page.Total == nil || *page.Page.Total != 5 || *page.Page.TotalPages != 3 ||
		page.Page.Number != 2 || page.Page.Limit != 2 || page.Page.NextCursor != "" || len(page.Data) != 2 ||
		page.Data[0].TaskID != reader.jobs[2].TaskID || page.Data[1].TaskID != reader.jobs[3].TaskID ||
		page.TaskMetadata == nil || len(*page.TaskMetadata) != len(page.Data) {
		t.Fatalf("numbered page=%+v err=%v", page, err)
	}
	request.Page = 4
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || len(page.Data) != 0 || page.Page.Number != 4 || *page.Page.Total != 5 || *page.Page.TotalPages != 3 {
		t.Fatalf("out-of-range page=%+v err=%v", page, err)
	}
	request.Page, request.TaskID = 1, &reader.jobs[1].TaskID
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || *page.Page.Total != 1 || len(page.Data) != 1 || page.Data[0].TaskID != *request.TaskID {
		t.Fatalf("exact task page=%+v err=%v", page, err)
	}
	request.Resource = "not-a-resource"
	page, err = service.List(t.Context(), tenantPrincipal(scopeA), request)
	if err != nil || *page.Page.Total != 0 || *page.Page.TotalPages != 0 || page.Data == nil {
		t.Fatalf("empty page=%+v err=%v", page, err)
	}
	request.TenantID = &tenantB
	if _, err := service.List(t.Context(), tenantPrincipal(scopeA), request); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant scope override err=%v", err)
	}
	platformRequest := fixtureListRequest(AudiencePlatform)
	platformRequest.Page, platformRequest.TenantID = 1, &tenantB
	page, err = service.List(t.Context(), platformPrincipal(uuid.New()), platformRequest)
	if err != nil || *page.Page.Total != 1 || len(page.Data) != 1 || page.Data[0].TenantID != tenantB {
		t.Fatalf("platform tenant filter=%+v err=%v", page, err)
	}
	legacy, err := service.List(t.Context(), tenantPrincipal(scopeA), fixtureListRequest(AudienceTenant))
	encoded, _ := json.Marshal(legacy)
	if err != nil || legacy.Page.NextCursor == "" || strings.Contains(string(encoded), "task_metadata") ||
		strings.Contains(string(encoded), "total_pages") || legacy.Page.Total != nil {
		t.Fatalf("legacy response changed=%s err=%v", encoded, err)
	}
}

func TestHandlerRejectsInvalidNumberedPaginationBeforeReader(t *testing.T) {
	reader := &fixtureReader{}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		return platformPrincipal(uuid.New()), nil
	}, HandlerConfig{})
	for _, query := range []string{
		"page=", "page=0", "page=-1", "page=01", "page=1.5", "page=+1", "page=1000001", "page=9999999999999999999999",
		"page=1&page=2", "page=1&cursor=", "page=1&cursor=invalid", "page=1&limit=0", "page=1&limit=101",
	} {
		t.Run(query, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs")+"&"+query, nil))
			if response.Code != 400 || reader.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
			}
		})
	}
}

type numberedReaderResult struct {
	Reader
	jobs  []Job
	total int64
	err   error
}

func (reader numberedReaderResult) ListNumberedPage(context.Context, ReadScope, ListQuery) ([]Job, int64, error) {
	return reader.jobs, reader.total, reader.err
}

func TestNumberedPageRejectsInconsistentStorageAndUnavailableReaders(t *testing.T) {
	job := fixtureJob(uuid.New(), uuid.New(), StateQueued, fixtureNow)
	request := fixtureListRequest(AudiencePlatform)
	request.Page = 1
	for _, test := range []struct {
		name   string
		reader Reader
		want   error
	}{
		{"negative count", numberedReaderResult{Reader: &fixtureReader{}, total: -1}, ErrInvalidStoreResponse},
		{"missing row", numberedReaderResult{Reader: &fixtureReader{}, total: 1}, ErrInvalidStoreResponse},
		{"extra row", numberedReaderResult{Reader: &fixtureReader{}, jobs: []Job{job}, total: 0}, ErrInvalidStoreResponse},
		{"storage unavailable", numberedReaderResult{Reader: &fixtureReader{}, err: errors.New("private SQL")}, ErrStoreUnavailable},
		{"no numbered reader", struct{ Reader }{Reader: &fixtureReader{}}, ErrStoreUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(test.reader, fixtureServiceConfig())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.List(t.Context(), platformPrincipal(uuid.New()), request); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
	request.TaskID = &job.TaskID
	other := job
	other.TaskID = uuid.New()
	service, _ := NewService(numberedReaderResult{Reader: &fixtureReader{}, jobs: []Job{other}, total: 1}, fixtureServiceConfig())
	if _, err := service.List(t.Context(), platformPrincipal(uuid.New()), request); !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("incorrect task filter error=%v", err)
	}
}

func TestKindCatalogAuthorizationEmptyDataAndCopyIsolation(t *testing.T) {
	service := fixtureService(&fixtureReader{})
	principal := platformPrincipal(uuid.New())
	catalog, err := service.Kinds(t.Context(), principal, AudiencePlatform)
	if err != nil || len(catalog.Data) != 10 {
		t.Fatalf("catalog=%+v err=%v", catalog, err)
	}
	for _, kind := range catalog.Data {
		if kind.Integration != "integrated" || kind.RuntimeStatus != "unknown" || !strings.HasPrefix(kind.NameKey, "jobs.kindNames.") {
			t.Fatalf("invalid kind=%+v", kind)
		}
	}
	catalog.Data[0].Kind = "changed"
	fresh, _ := service.Kinds(t.Context(), principal, AudiencePlatform)
	if fresh.Data[0].Kind == "changed" {
		t.Fatal("catalog mutation changed subsequent responses")
	}
	denied := principal
	denied.Permissions = nil
	if _, err := service.Kinds(t.Context(), denied, AudiencePlatform); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("denied err=%v", err)
	}
	if _, err := service.Kinds(t.Context(), tenantPrincipal(uuid.New()), AudiencePlatform); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("wrong audience err=%v", err)
	}
	if _, err := service.Kinds(t.Context(), tenantPrincipal(uuid.New()), AudienceTenant); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Kinds(ctx, principal, AudiencePlatform); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled err=%v", err)
	}
}

func TestTaskMetadataDoesNotChangeJobJSONRevisionOrInventDependency(t *testing.T) {
	job := fixtureJob(uuid.New(), uuid.New(), StateQueued, fixtureNow)
	job.Kind = "dns.cname.allocation"
	before, _ := json.Marshal(job)
	revision := revisionForJob(job)
	metadata := derivedTaskMetadata(job)
	metadata.Dependencies = TaskDependencies{State: "observed", Items: []TaskDependency{
		{TaskID: uuid.New(), Relation: "completion", Status: StateRunning},
	}}
	job.taskMetadata = &metadata
	after, _ := json.Marshal(job)
	if string(before) != string(after) || revision != revisionForJob(job) {
		t.Fatal("presentation metadata changed immutable job JSON or command revision")
	}
	if result, err := metadataForJobs([]Job{job}); err != nil || result[0].Dependencies.State != "observed" {
		t.Fatalf("metadata=%+v err=%v", result, err)
	}
	for _, mutate := range []func(*TaskMetadata){
		func(value *TaskMetadata) { value.TaskID = uuid.New() },
		func(value *TaskMetadata) { value.Name.Resource = "wrong" },
		func(value *TaskMetadata) { value.Priority.Policy = "priority_20" },
		func(value *TaskMetadata) { value.Dependencies.State = "unknown" },
		func(value *TaskMetadata) { value.Dependencies.Items = []TaskDependency{} },
		func(value *TaskMetadata) { value.Dependencies.Items[0].TaskID = job.TaskID },
	} {
		copy := metadata
		copy.Dependencies.Items = append([]TaskDependency{}, metadata.Dependencies.Items...)
		mutate(&copy)
		job.taskMetadata = &copy
		if _, err := metadataForJobs([]Job{job}); !errors.Is(err, ErrInvalidStoreResponse) {
			t.Fatalf("invalid metadata accepted=%+v err=%v", copy, err)
		}
	}
	unknown := derivedTaskMetadata(Job{Kind: "not.registered"})
	if unknown.Name.NameKey != "jobs.kindNames.unknown" || unknown.Priority.Policy != "unknown" ||
		unknown.Dependencies.State != "unknown" || unknown.Dependencies.Items == nil || len(unknown.Dependencies.Items) != 0 {
		t.Fatalf("unknown metadata invented facts=%+v", unknown)
	}
	if derivedTaskMetadata(Job{Kind: "dns.cname.allocation"}).Dependencies.State != "unknown" {
		t.Fatal("CNAME allocation without a recorded relation must remain unknown")
	}
}

func TestTaskMetadataReportsNoDependencyOnlyForKindsWithoutRelation(t *testing.T) {
	for _, kind := range integratedKinds {
		metadata := derivedTaskMetadata(Job{Kind: kind.Kind})
		want := "none"
		if kind.Kind == "dns.cname.allocation" {
			want = "unknown"
		}
		if metadata.Dependencies.State != want || len(metadata.Dependencies.Items) != 0 {
			t.Fatalf("kind %s dependencies=%+v want state %s", kind.Kind, metadata.Dependencies, want)
		}
	}
	job := fixtureJob(uuid.New(), uuid.New(), StateQueued, fixtureNow)
	job.Kind = "dns.cname.allocation"
	forged := derivedTaskMetadata(job)
	forged.Dependencies.State = "none"
	job.taskMetadata = &forged
	if _, err := metadataForJobs([]Job{job}); !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("CNAME allocation must not be reported as dependency-free: %v", err)
	}
	job.Kind = "cache.operation"
	forged = derivedTaskMetadata(job)
	forged.Dependencies = TaskDependencies{State: "none", Items: []TaskDependency{{TaskID: uuid.New(), Relation: "completion", Status: StateQueued}}}
	job.taskMetadata = &forged
	if _, err := metadataForJobs([]Job{job}); !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("none dependency state must not carry items: %v", err)
	}
}
