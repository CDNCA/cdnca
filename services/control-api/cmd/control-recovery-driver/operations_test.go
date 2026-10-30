package main

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMalformedOperationReceiptIsUncertain(t *testing.T) {
	directory := t.TempDir()
	store, err := newOperationStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(store.directory, safeStateName("capture-backup-postgresql")+".receipt.json")
	if err := os.WriteFile(receiptPath, []byte(`{"schema":"cdnca.control-recovery-driver.receipt/v1"`), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	_, code := store.execute("capture", "backup-postgresql", map[string]string{"backup_id": "backup"}, false, func() (any, string) {
		mutated = true
		return nil, ""
	})
	if code != uncertainCode || mutated {
		t.Fatalf("execute() = (%q, mutated=%v), want (%q, false)", code, mutated, uncertainCode)
	}
}

func TestGetScaleAcceptsKubernetesMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"kind":"Scale","apiVersion":"autoscaling/v1","metadata":{"name":"control-api","resourceVersion":"7"},"spec":{"replicas":3},"status":{"replicas":2,"selector":"app=control-api"}}`)
	}))
	defer server.Close()
	spec, observed, err := getScale(context.Background(), server.Client(), server.URL, "cdnca", "control-api")
	if err != nil || spec != 3 || observed != 2 {
		t.Fatalf("getScale() = (%d, %d, %v)", spec, observed, err)
	}
}

func TestFreezeRecordPrecedesFirstScaleMutation(t *testing.T) {
	stateDirectory := t.TempDir()
	backupID := "backup-ops12"
	freezeID := "freeze-" + safeStateName(backupID)[:32]
	recordPath := filepath.Join(stateDirectory, "freeze-"+safeStateName(freezeID)+".json")
	var replicas atomic.Int32
	replicas.Store(3)
	var mutationBeforeRecord atomic.Bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet:
			current := replicas.Load()
			_, _ = io.WriteString(writer, `{"kind":"Scale","apiVersion":"autoscaling/v1","metadata":{"name":"control-api"},"spec":{"replicas":`+integerText(current)+`},"status":{"replicas":`+integerText(current)+`}}`)
		case http.MethodPatch:
			if _, err := os.Stat(recordPath); err != nil {
				mutationBeforeRecord.Store(true)
			}
			body, _ := io.ReadAll(request.Body)
			if strings.Contains(string(body), `"replicas":0`) {
				replicas.Store(0)
			} else {
				replicas.Store(3)
			}
			_, _ = io.WriteString(writer, `{}`)
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	certificate := server.Certificate()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o400); err != nil {
		t.Fatal(err)
	}
	namespacePath := writeTrustedTestFile(t, "namespace", "cdnca")
	tokenPath := writeTrustedTestFile(t, "token", "test-token")
	runtime, err := newDriverRuntime(driverPlan{
		StateDirectory: stateDirectory,
		Kubernetes: kubernetesPlan{
			APIServer: server.URL, NamespaceFile: namespacePath, TokenFile: tokenPath, CAFile: certPath,
			SettleTimeoutSeconds: 2, Workloads: []workloadPlan{{Name: "control-api"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, code := runtime.freeze(ctx, backupID); code != "" {
		t.Fatalf("freeze() code = %q", code)
	}
	if mutationBeforeRecord.Load() {
		t.Fatal("scale mutation happened before the durable freeze record existed")
	}
}

func writeTrustedTestFile(t *testing.T, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(value), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func integerText(value int32) string {
	return strconv.FormatInt(int64(value), 10)
}
