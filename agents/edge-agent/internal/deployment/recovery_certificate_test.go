package deployment

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
)

type certificateRecoveryInterruptRuntime struct {
	*fakeRuntime
	interrupt bool
}

func (runtime *certificateRecoveryInterruptRuntime) Healthy(ctx context.Context, version string) error {
	if runtime.interrupt {
		panic("health interruption")
	}
	return runtime.fakeRuntime.Healthy(ctx, version)
}

func TestRecoverProtectsBothCertificateGenerationsUntilHealthy(t *testing.T) {
	for _, failure := range []string{"runtime", "initial-set", "resolve", "resolve-and-restore", "final-set"} {
		t.Run(failure, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "deployment")
			runtime := &certificateRecoveryInterruptRuntime{fakeRuntime: &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}}
			certificates := newTestCertificateVersionStore(t)
			manager := newCertificateDeploymentManager(t, root, runtime, certificates)
			baseline := certificateDeploymentCommand(t, "baseline", 1, testConfigV1, "", testCertificateV1)
			if result, err := manager.Process(t.Context(), baseline); err != nil || result.State != StateHealthy {
				t.Fatalf("baseline=%+v %v", result, err)
			}
			candidate := certificateDeploymentCommand(t, "candidate", 1, testConfigV2, testConfigV1, testCertificateV2)
			runtime.interrupt = true
			func() {
				defer func() {
					if got := recover(); got != "health interruption" {
						t.Fatalf("interruption=%v", got)
					}
				}()
				_, _ = manager.Process(t.Context(), candidate)
			}()
			runtime.interrupt = false
			manager = newCertificateDeploymentManager(t, root, runtime, certificates)
			injected := errors.New("injected certificate recovery failure")
			certificates.setFailures = map[int]error{}
			switch failure {
			case "runtime":
				runtime.healthFailures[testConfigV1] = injected
			case "initial-set":
				certificates.setFailures[len(certificates.setCalls)+1] = injected
			case "resolve", "resolve-and-restore":
				certificates.resolveErr = injected
				if failure == "resolve-and-restore" {
					certificates.setFailures[len(certificates.setCalls)+2] = injected
				}
			case "final-set":
				certificates.setFailures[len(certificates.setCalls)+2] = injected
			}
			if err := manager.Recover(t.Context()); err == nil {
				t.Fatal("failed recovery accepted")
			}
			refs := certificates.references
			for _, version := range []string{testCertificateV1, testCertificateV2} {
				if !containsTestString(refs.Current, version) && !containsTestString(refs.Previous, version) {
					t.Fatalf("recovery lost generation protection: version=%s refs=%+v", version, refs)
				}
			}
			stored, err := manager.store.loadJournal(candidate.DeploymentID)
			if err != nil || stored.Attempts[0].Phase != phaseHealth {
				t.Fatalf("failed recovery consumed journal: %+v %v", stored, err)
			}
			delete(runtime.healthFailures, testConfigV1)
			certificates.resolveErr = nil
			certificates.setFailures = nil
			if err := manager.Recover(t.Context()); err != nil {
				t.Fatal(err)
			}
			want := certstore.CertificateVersionReferences{Current: []string{testCertificateV1}}
			if !reflect.DeepEqual(certificates.references, want) {
				t.Fatalf("successful recovery refs=%+v want=%+v", certificates.references, want)
			}
		})
	}
}
