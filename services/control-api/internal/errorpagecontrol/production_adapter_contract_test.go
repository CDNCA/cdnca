package errorpagecontrol

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestProductionAdapterContractFailsClosedWithoutExternalDependencies(t *testing.T) {
	valid := runtimeFactoryDependencies(t, "production-adapter-contract")
	tests := map[string]func(*RuntimeDependencies){
		"content store":  func(dependencies *RuntimeDependencies) { dependencies.ContentStore = nil },
		"scanner":        func(dependencies *RuntimeDependencies) { dependencies.Scanner = nil },
		"limit provider": func(dependencies *RuntimeDependencies) { dependencies.Limits = nil },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			remove(&dependencies)
			runtime, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", runtime, err)
			}
		})
	}
}

func TestProductionAdapterContractRequiresAllObjectStoreGuarantees(t *testing.T) {
	complete := ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
	tests := map[string]func(*ObjectStoreCapabilities){
		"immutable staging":       func(value *ObjectStoreCapabilities) { value.ImmutableStaging = false },
		"conditional finalize":    func(value *ObjectStoreCapabilities) { value.ConditionalFinalize = false },
		"trusted metadata":        func(value *ObjectStoreCapabilities) { value.TrustedMetadata = false },
		"immutable reads":         func(value *ObjectStoreCapabilities) { value.ImmutableReads = false },
		"preserved staging alias": func(value *ObjectStoreCapabilities) { value.PreservesStagingAlias = false },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			capabilities := complete
			remove(&capabilities)
			dependencies := runtimeFactoryDependencies(t, "production-object-contract")
			dependencies.ContentStore = capabilityContentStore{
				ContentStore: dependencies.ContentStore,
				capabilities: capabilities,
			}
			runtime, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", runtime, err)
			}
		})
	}
}

func TestProductionAdapterContractRejectsCredentialBearingScannerIdentity(t *testing.T) {
	const credential = "scanner-production-secret"
	dependencies := runtimeFactoryDependencies(t, "production-scanner-contract")
	dependencies.Scanner = &testScanner{name: "clamd://scanner:" + credential + "@scan.internal:3310"}
	runtime, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
	if runtime != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", runtime, err)
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatalf("constructor error leaked scanner credential: %v", err)
	}
}

func TestProductionAdapterContractMapsLimitSourceFailureToUnavailable(t *testing.T) {
	const credential = "postgres://limit-user:limit-secret@database.internal/control"
	service := &Service{limits: failingProductionLimits{err: errors.New(credential)}}
	_, err := service.entitlementLimits(t.Context(), nil, EntitlementCheck{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("entitlementLimits() error = %v, want ErrUnavailable", err)
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatalf("limit provider error leaked credential: %v", err)
	}
}

type capabilityContentStore struct {
	ContentStore
	capabilities ObjectStoreCapabilities
}

func (store capabilityContentStore) Capabilities() ObjectStoreCapabilities {
	return store.capabilities
}

type failingProductionLimits struct {
	err error
}

func (provider failingProductionLimits) Limits(context.Context, pgx.Tx, EntitlementCheck) (EntitlementLimits, error) {
	return EntitlementLimits{}, provider.err
}
