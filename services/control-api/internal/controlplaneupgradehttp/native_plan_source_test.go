package controlplaneupgradehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

func TestNativePlanSourceDistinguishesEmptyPublicationFromUnavailableRepository(t *testing.T) {
	installationID := uuid.NewString()
	for _, test := range []struct {
		name       string
		document   controlplaneupgrade.SecretDocument
		err        error
		authorized bool
		want       int
	}{
		{name: "empty", document: controlplaneupgrade.SecretDocument{ResourceVersion: "0"}, authorized: true, want: 204},
		{name: "empty unauthenticated", document: controlplaneupgrade.SecretDocument{ResourceVersion: "0"}, want: 401},
		{name: "database unavailable", err: controlplaneupgrade.ErrSecretUnavailable, authorized: true, want: 503},
		{name: "orphan bundle", document: controlplaneupgrade.SecretDocument{Bundle: []byte(`{}`)}, authorized: true, want: 503},
		{name: "orphan publication", document: controlplaneupgrade.SecretDocument{Publication: &controlplaneupgrade.PublicationReceipt{}}, authorized: true, want: 503},
		{name: "orphan control", document: controlplaneupgrade.SecretDocument{Control: &controlplaneupgrade.ControlState{}}, authorized: true, want: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &nativePlanReadRepository{document: test.document, err: test.err}
			handler, err := NewSystemdPlanSourceHandler(repository, installationID,
				controlplaneupgrade.SystemdControlUpgradeOperation, []byte("internal-token-32-bytes-long-value"), 1024)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, SystemdPlanSourcePath, nil)
			if test.authorized {
				request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d", response.Code, test.want)
			}
			if test.want == 204 && (response.Body.Len() != 0 || response.Header().Get("ETag") != "" ||
				response.Header().Get(SystemdPlanInstallationHeader) != installationID ||
				response.Header().Get(SystemdPlanOperationHeader) != controlplaneupgrade.SystemdControlUpgradeOperation ||
				response.Header().Get("Cache-Control") != "no-store") {
				t.Fatalf("empty publication headers=%v body=%q", response.Header(), response.Body.String())
			}
		})
	}
}

type nativePlanReadRepository struct {
	document controlplaneupgrade.SecretDocument
	err      error
}

func (repository *nativePlanReadRepository) Read(context.Context) (controlplaneupgrade.SecretDocument, error) {
	return repository.document, repository.err
}
func (*nativePlanReadRepository) CompareAndSwap(context.Context, string, controlplaneupgrade.SecretDocument) (controlplaneupgrade.SecretDocument, error) {
	return controlplaneupgrade.SecretDocument{}, controlplaneupgrade.ErrSecretConflict
}
