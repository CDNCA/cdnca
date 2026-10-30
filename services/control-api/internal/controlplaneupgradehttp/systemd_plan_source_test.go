package controlplaneupgradehttp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

func TestOPS06SystemdPlanSourceAuthenticatesAndReturnsExactETagReplay(t *testing.T) {
	installationID := uuid.NewString()
	bundle := []byte(`{"signed":"plan"}`)
	digest := sha256.Sum256(bundle)
	repository := &systemdPlanRepository{document: controlplaneupgrade.SecretDocument{ResourceVersion: "9", Bundle: bundle,
		Publication: &controlplaneupgrade.PublicationReceipt{PlanID: uuid.NewString(), PublicationRevision: 7,
			InstallationID: installationID, Component: "control-api", BundleSHA256: fmt.Sprintf("%x", digest)}}}
	handler, err := NewSystemdPlanSourceHandler(repository, installationID,
		controlplaneupgrade.SystemdControlUpgradeOperation, []byte("internal-token-32-bytes-long-value"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, SystemdPlanSourcePath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || repository.reads != 0 {
		t.Fatalf("unauthorized status=%d reads=%d", response.Code, repository.reads)
	}
	request = httptest.NewRequest(http.MethodGet, SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	wantETag := `"7:` + fmt.Sprintf("%x", digest) + `"`
	if response.Code != http.StatusOK || response.Body.String() != string(bundle) || response.Header().Get("ETag") != wantETag ||
		response.Header().Get(SystemdPlanInstallationHeader) != installationID ||
		response.Header().Get(SystemdPlanOperationHeader) != controlplaneupgrade.SystemdControlUpgradeOperation ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("plan response status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
	request.Header.Set("If-None-Match", wantETag)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 || response.Header().Get("ETag") != wantETag {
		t.Fatalf("replay status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestOPS06SystemdPlanSourceFailsClosedOnInvalidBindingAndRequest(t *testing.T) {
	installationID := uuid.NewString()
	bundle := []byte(`{"signed":"plan"}`)
	digest := sha256.Sum256(bundle)
	repository := &systemdPlanRepository{document: controlplaneupgrade.SecretDocument{ResourceVersion: "1", Bundle: bundle,
		Publication: &controlplaneupgrade.PublicationReceipt{PlanID: uuid.NewString(), PublicationRevision: 1,
			InstallationID: uuid.NewString(), Component: "control-api", BundleSHA256: fmt.Sprintf("%x", digest)}}}
	handler, err := NewSystemdPlanSourceHandler(repository, installationID,
		controlplaneupgrade.SystemdControlUpgradeOperation, []byte("internal-token-32-bytes-long-value"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{SystemdPlanSourcePath + "?target=other", SystemdPlanSourcePath + "/other"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("target %q status=%d", target, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, SystemdPlanSourcePath, strings.NewReader("secret"))
	request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, SystemdPlanSourcePath, nil)
	request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), string(bundle)) {
		t.Fatalf("cross-binding status=%d body=%q", response.Code, response.Body.String())
	}
}

type systemdPlanRepository struct {
	document controlplaneupgrade.SecretDocument
	reads    int
}

func (repository *systemdPlanRepository) Read(context.Context) (controlplaneupgrade.SecretDocument, error) {
	repository.reads++
	return repository.document, nil
}

func (repository *systemdPlanRepository) CompareAndSwap(context.Context, string,
	controlplaneupgrade.SecretDocument) (controlplaneupgrade.SecretDocument, error) {
	return controlplaneupgrade.SecretDocument{}, controlplaneupgrade.ErrSecretConflict
}
