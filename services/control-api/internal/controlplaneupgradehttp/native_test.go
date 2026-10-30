package controlplaneupgradehttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestNativePublicationUsesPackageDigestAndExactReplaySurvivesDrain(t *testing.T) {
	handler, repository, request, status := nativeFixture(t)
	receipt, err := handler.Publish(t.Context(), request)
	if err != nil || receipt.CurrentDigest != status.CurrentArtifactSHA256 || receipt.CurrentDigest == status.RunnerExeSHA256 || repository.writes != 1 {
		t.Fatalf("publication=%+v writes=%d err=%v", receipt, repository.writes, err)
	}
	status.Ready, status.Busy, status.Phase = false, true, "draining"
	status.CurrentVersion = "1.5.0"
	handler.readStatus = func(string, string, time.Time) (controlplaneupgrade.NativeStandaloneStatus, error) {
		return *status, nil
	}
	for _, gate := range []http.Handler{handler.Handler(), handler.Gate(http.NotFoundHandler())} {
		retry := httptest.NewRequest(http.MethodPost, nativePlanPath, bytes.NewReader(request.Bundle))
		retry.Header.Set("Content-Type", "application/json")
		retry.Header.Set("If-Match", `"0"`)
		retry.Header.Set("Idempotency-Key", request.IdempotencyKey)
		response := httptest.NewRecorder()
		gate.ServeHTTP(response, retry)
		if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || repository.writes != 1 {
			t.Fatalf("lost-response replay status=%d writes=%d body=%s", response.Code, repository.writes, response.Body.String())
		}
	}
	for name, change := range map[string]func(*controlplaneupgrade.PublishRequest){
		"payload": func(value *controlplaneupgrade.PublishRequest) {
			value.Bundle = append(append([]byte{}, value.Bundle...), '\n')
		},
		"key":      func(value *controlplaneupgrade.PublishRequest) { value.IdempotencyKey = "another-key" },
		"revision": func(value *controlplaneupgrade.PublishRequest) { value.ExpectedRevision++ },
		"actor":    func(value *controlplaneupgrade.PublishRequest) { value.ActorUserID = uuid.New() },
		"scope":    func(value *controlplaneupgrade.PublishRequest) { value.ActorScopeID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			change(&candidate)
			if _, err := handler.Publish(t.Context(), candidate); err == nil || repository.writes != 1 {
				t.Fatalf("nonexact replay err=%v writes=%d", err, repository.writes)
			}
		})
	}
}

func TestNativeNewPlansRequireVerifiedReadyAndNeverUseBinaryDigest(t *testing.T) {
	for name, change := range map[string]func(*controlplaneupgrade.NativeStandaloneStatus){
		"busy":               func(value *controlplaneupgrade.NativeStandaloneStatus) { value.Busy = true },
		"not ready":          func(value *controlplaneupgrade.NativeStandaloneStatus) { value.Ready = false },
		"wrong version":      func(value *controlplaneupgrade.NativeStandaloneStatus) { value.CurrentVersion = "1.3.0" },
		"wrong layout":       func(value *controlplaneupgrade.NativeStandaloneStatus) { value.ArtifactFormat = "raw-binary" },
		"wrong installation": func(value *controlplaneupgrade.NativeStandaloneStatus) { value.InstallationID = uuid.NewString() },
		"wrong protocol":     func(value *controlplaneupgrade.NativeStandaloneStatus) { value.ProtocolVersion++ },
		"binary digest": func(value *controlplaneupgrade.NativeStandaloneStatus) {
			value.CurrentArtifactSHA256 = value.RunnerExeSHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			handler, repository, request, status := nativeFixture(t)
			change(status)
			if _, err := handler.Publish(t.Context(), request); err == nil || repository.writes != 0 {
				t.Fatalf("unsafe plan accepted err=%v writes=%d", err, repository.writes)
			}
		})
	}
	handler, repository, request, _ := nativeFixture(t)
	handler.readStatus = func(string, string, time.Time) (controlplaneupgrade.NativeStandaloneStatus, error) {
		return controlplaneupgrade.NativeStandaloneStatus{}, errors.New("stale file or pid mismatch")
	}
	if _, err := handler.Publish(t.Context(), request); err == nil || repository.writes != 0 {
		t.Fatal("untrusted state accepted")
	}
	if state := handler.MaintenanceRuntimeStatus(t.Context()); state.Ready || state.Reason != "control_upgrade_runner_unconfirmed" {
		t.Fatalf("state=%+v", state)
	}
}

func TestNativeStatusProjectsOnlyMatchingPublicationAndExecution(t *testing.T) {
	handler, repository, request, _ := nativeFixture(t)
	publication, err := handler.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	state := controlplaneupgrade.State{Schema: controlplaneupgrade.StateSchema, PlanID: publication.PlanID,
		BundleSHA256: publication.BundleSHA256, Sequence: publication.ReleaseSequence, Phase: controlplaneupgrade.PhaseCompleted,
		Receipt: &controlplaneupgrade.Receipt{ID: "execution-1", PlanID: publication.PlanID, BundleSHA256: publication.BundleSHA256,
			Sequence: publication.ReleaseSequence, Target: controlplaneupgrade.TargetNativeStandalone,
			CurrentVersion: publication.CurrentVersion, TargetVersion: publication.TargetVersion,
			Result: controlplaneupgrade.ResultApplied, CompletedAt: 1_800_000_020}}
	handler.readState = func(string) (controlplaneupgrade.State, error) { return state, nil }
	journal := controlplaneupgrade.History{Schema: controlplaneupgrade.HistorySchema, PlanID: publication.PlanID,
		Sequence: publication.ReleaseSequence, Entries: []controlplaneupgrade.HistoryEntry{
			{Phase: controlplaneupgrade.PhaseVerified, At: 1_800_000_001}, {Phase: controlplaneupgrade.PhaseCompleted, At: 1_800_000_020}}}
	historyFile := ""
	handler.readHistory = func(filename string) (controlplaneupgrade.History, error) {
		historyFile = filename
		return journal, nil
	}
	repository.document.Data = map[string][]byte{"private-token": []byte("must-not-leak")}
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	var body NativePlanStatus
	decodeBody(t, response, &body)
	if response.Code != 200 || body.PublicationRevision != 1 || body.Execution.State != "completed" ||
		body.Execution.Receipt == nil || body.Execution.Receipt.ID != "execution-1" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(body.Execution.History) != 2 || body.Execution.History[1].Phase != controlplaneupgrade.PhaseCompleted ||
		historyFile != handler.config.StatusFile+".history.json" {
		t.Fatalf("history=%+v file=%q", body.Execution.History, historyFile)
	}
	// A journal of another plan is never shown as this execution's log.
	journal.PlanID = uuid.NewString()
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	body = NativePlanStatus{}
	decodeBody(t, response, &body)
	if body.Execution.State != "completed" || body.Execution.History != nil || strings.Contains(response.Body.String(), `"history"`) {
		t.Fatalf("foreign history projected=%s", response.Body.String())
	}
	journal.PlanID = publication.PlanID
	for _, private := range []string{"runner_pid", "start_id", "runner_exe_sha256", "/run/", "must-not-leak", "signature", "download_url"} {
		if strings.Contains(response.Body.String(), private) {
			t.Fatalf("private field leaked: %s", private)
		}
	}
	state.PlanID = uuid.NewString()
	if result := nativeExecution(state, publication); result.State != "unavailable" || result.Receipt != nil {
		t.Fatalf("unmatched receipt accepted=%+v", result)
	}
	state.PlanID, state.Sequence = publication.PlanID, publication.ReleaseSequence+1
	if result := nativeExecution(state, publication); result.State != "unavailable" {
		t.Fatalf("unmatched sequence accepted=%+v", result)
	}
	handler.readState = func(string) (controlplaneupgrade.State, error) {
		return controlplaneupgrade.State{}, controlplaneupgrade.ErrCorruptState
	}
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	decodeBody(t, response, &body)
	if body.Execution.State != "unavailable" || body.Execution.Receipt != nil {
		t.Fatalf("unknown state invented progress=%+v", body.Execution)
	}
}

func TestNativeHTTPAuthorizationQueriesAndFailClosedMaintenance(t *testing.T) {
	handler, repository, _, _ := nativeFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, httptest.NewRequest(method, nativePlanPath+"?unknown=1", bytes.NewBufferString("{}")))
		if response.Code != 400 || repository.writes != 0 {
			t.Fatalf("query accepted status=%d", response.Code)
		}
	}
	handler.core.authenticate = func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	if response.Code != 401 {
		t.Fatalf("unauthenticated status=%d", response.Code)
	}
	handler.core.authenticate = func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
			ScopeKind: "tenant", Permissions: []string{"control.upgrades.manage"}}}, nil
	}
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath, nil))
	if response.Code != 403 {
		t.Fatalf("tenant status=%d", response.Code)
	}
	gate := handler.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		gate.ServeHTTP(response, httptest.NewRequest(method, "/v1/sites", nil))
		want := 503
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			want = 204
		}
		if response.Code != want {
			t.Fatalf("missing trusted maintenance %s status=%d", method, response.Code)
		}
	}
}

type nativeMemoryRepository struct {
	mu       sync.Mutex
	document controlplaneupgrade.SecretDocument
	writes   int
}

func (repository *nativeMemoryRepository) Read(context.Context) (controlplaneupgrade.SecretDocument, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.document, nil
}

func (repository *nativeMemoryRepository) CompareAndSwap(_ context.Context, expected string, document controlplaneupgrade.SecretDocument) (controlplaneupgrade.SecretDocument, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if expected != repository.document.ResourceVersion {
		return controlplaneupgrade.SecretDocument{}, controlplaneupgrade.ErrSecretConflict
	}
	repository.writes++
	document.ResourceVersion = strconv.Itoa(repository.writes)
	repository.document = document
	return document, nil
}

type nativeTestSigner struct{ private ed25519.PrivateKey }

func (nativeTestSigner) KeyID() string { return "native-test-release" }
func (signer nativeTestSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, message), nil
}

func nativeFixture(t *testing.T) (*NativeHandler, *nativeMemoryRepository, controlplaneupgrade.PublishRequest, *controlplaneupgrade.NativeStandaloneStatus) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := nativeTestSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.KeyID(), PublicKey: signer.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	installationID, userID, scopeID := uuid.NewString(), uuid.New(), uuid.New()
	repository := &nativeMemoryRepository{document: controlplaneupgrade.SecretDocument{ResourceVersion: "0"}}
	handler, err := NewNative(NativeDependencies{InstallationID: installationID, CurrentVersion: "1.4.0", ProtocolVersion: 2,
		Repository: repository, Trust: trust, StatusFile: "/run/cdnca-upgrade/status.json", StateFile: "/run/cdnca-upgrade/status.json.state.json",
		MaintenanceFile: "/run/cdnca-upgrade/maintenance.json", Now: func() time.Time { return now },
		AuthenticateSession: func(*http.Request) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
				UserID: userID, ScopeID: scopeID, ScopeKind: "platform", Permissions: []string{"control.upgrades.manage"}}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	status := &controlplaneupgrade.NativeStandaloneStatus{Ready: true, Reason: "ready", InstallationID: installationID,
		ProtocolVersion: 2, ArtifactFormat: controlplaneupgrade.NativeManifestSchema, CurrentVersion: "1.4.0",
		CurrentArtifactSHA256: strings.Repeat("52", 32), RunnerExeSHA256: strings.Repeat("53", 32), Phase: "idle"}
	handler.readStatus = func(string, string, time.Time) (controlplaneupgrade.NativeStandaloneStatus, error) {
		return *status, nil
	}
	handler.readState = func(string) (controlplaneupgrade.State, error) {
		return controlplaneupgrade.State{}, controlplaneupgrade.ErrStateNotFound
	}
	artifact := func(version string, fill byte, sequence uint64) entitlement.UpgradePlanArtifact {
		manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
			Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
			ArtifactID: uuid.NewString(), Component: "control-api", Version: version, ProtocolMin: 1, ProtocolMax: 3,
			ArtifactSizeBytes: 4096, ReleaseSequence: sequence, DigestAlgorithm: "sha256",
			SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)), DownloadURL: "https://releases.example.invalid/" + version}
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest, signer)
		if err != nil {
			t.Fatal(err)
		}
		return entitlement.UpgradePlanArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
	}
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: uuid.NewString(), PlanID: uuid.NewString(), InitialPlanRevision: 1, ParentGrantID: uuid.NewString(),
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		ParentGrantIssuedAt: now.Add(-time.Minute).Unix(), ParentGrantExpiresAt: now.Add(48 * time.Hour).Unix(),
		CustomerID: uuid.NewString(), InstallationID: installationID, LicenseID: uuid.NewString(), Channel: "stable", ChannelRevision: 7,
		Component: "control-api", CurrentVersion: "1.4.0", Version: "1.5.0", ProtocolVersion: 2,
		Forward: artifact("1.5.0", 0x51, 42), Rollback: artifact("1.4.0", 0x52, 41),
		IssuedAt: now.Unix(), CommandIssuanceNotAfter: now.Add(24 * time.Hour).Unix()}
	signed, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("encode signed bundle: %v", err)
	}
	return handler, repository, controlplaneupgrade.PublishRequest{Bundle: encoded, ExpectedRevision: 0,
		IdempotencyKey: "native-upgrade-1", RequestID: "native-test", ActorUserID: userID, ActorScopeID: scopeID}, status
}

func TestNativeRunLogProjectsOnlyTheCurrentExecution(t *testing.T) {
	handler, _, request, _ := nativeFixture(t)
	get := func() (int, NativeRunLogStatus, string) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativeRunLogPath, nil))
		var body NativeRunLogStatus
		if response.Code == http.StatusOK {
			decodeBody(t, response, &body)
		}
		return response.Code, body, response.Body.String()
	}
	// No publication yet: nothing to show, never a 404 or a fabricated log.
	if code, body, _ := get(); code != 200 || body.State != "unavailable" || body.RunLog != nil {
		t.Fatalf("before publication: %d %+v", code, body)
	}
	publication, err := handler.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	phase := controlplaneupgrade.PhaseExpanded
	handler.readState = func(string) (controlplaneupgrade.State, error) {
		return controlplaneupgrade.State{Schema: controlplaneupgrade.StateSchema, PlanID: publication.PlanID,
			BundleSHA256: publication.BundleSHA256, Sequence: publication.ReleaseSequence, Phase: phase}, nil
	}
	log := controlplaneupgrade.RunLog{Schema: controlplaneupgrade.RunLogSchema, PlanID: publication.PlanID,
		Sequence: publication.ReleaseSequence, StartedAt: 1_800_000_000, Attempts: 1,
		Entries: []controlplaneupgrade.RunLogEntry{{At: 1_800_000_000, Level: "info", Event: "run_started", Version: publication.TargetVersion}},
		Programs: []controlplaneupgrade.RunLogProgram{{Unit: "cdnca-control-api.service", CapturedAt: 1_800_000_001,
			Trigger: "run_completed", Lines: []string{"ready"}}}}
	file := ""
	handler.readRunLog = func(filename string) (controlplaneupgrade.RunLog, error) {
		file = filename
		return log, nil
	}
	code, body, raw := get()
	if code != 200 || body.State != "available" || body.RunLog == nil || body.RunLog.Entries[0].Event != "run_started" ||
		file != handler.config.StatusFile+".runlog.json" || body.Schema != "cdnca.native-control-upgrade-runlog/v1" {
		t.Fatalf("current log: %d %s file=%q", code, raw, file)
	}
	log.Sequence++
	if _, body, _ := get(); body.State != "unavailable" || body.RunLog != nil {
		t.Fatalf("log of another sequence projected: %+v", body)
	}
	log.Sequence = publication.ReleaseSequence
	handler.readRunLog = func(string) (controlplaneupgrade.RunLog, error) {
		return controlplaneupgrade.RunLog{}, controlplaneupgrade.ErrCorruptState
	}
	if _, body, _ := get(); body.State != "unavailable" {
		t.Fatalf("corrupt log projected: %+v", body)
	}
	handler.readState = func(string) (controlplaneupgrade.State, error) {
		return controlplaneupgrade.State{}, controlplaneupgrade.ErrStateNotFound
	}
	if _, body, _ := get(); body.State != "unavailable" {
		t.Fatalf("log without execution projected: %+v", body)
	}
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativeRunLogPath+"?lines=1000", nil))
	if response.Code != 400 {
		t.Fatalf("query accepted: %d", response.Code)
	}
	handler.core.authenticate = func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
			ScopeKind: "tenant", Permissions: []string{"control.upgrades.manage"}}}, nil
	}
	if code, _, _ := get(); code != 403 {
		t.Fatalf("tenant read run log: %d", code)
	}
}
