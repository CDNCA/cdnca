package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
)

func TestNodePortTransitionDisabledReadinessCallback(t *testing.T) {
	runtime, err := openNodePortTransitionProductionRuntime(false, config.Config{}, nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime=%v err=%v", runtime, err)
	}
	httpConfig := httpapi.Config{NodePortTransitionReady: runtime.Ready}
	if err := httpConfig.NodePortTransitionReady(); err == nil {
		t.Fatal("disabled runtime must reject writes without dereferencing a nil receiver")
	}
	if err := (&nodePortTransitionProductionRuntime{}).Ready(); err == nil {
		t.Fatal("incomplete runtime dependencies must not report ready")
	}
}
