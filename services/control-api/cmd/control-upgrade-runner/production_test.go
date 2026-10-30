//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

func TestProductionPlanReadIsBoundedAndRejectsHardlinks(t *testing.T) {
	root := t.TempDir()
	oversized := filepath.Join(root, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTROL_UPGRADE_PLAN_FILE", oversized)
	if _, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_FILE", 1<<20); err == nil {
		t.Fatal("oversized plan was accepted")
	}

	plan := filepath.Join(root, "bundle.json")
	alias := filepath.Join(root, "bundle-alias.json")
	if err := os.WriteFile(plan, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(plan, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTROL_UPGRADE_PLAN_FILE", plan)
	if _, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_FILE", 1<<20); err == nil {
		t.Fatal("hard-linked plan was accepted")
	}
}

func TestProductionRunnerLockIsExclusive(t *testing.T) {
	root := t.TempDir()
	first, err := acquireRunnerLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRunnerLock(root); err == nil {
		_ = first.Close()
		t.Fatal("second runner lock was accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireRunnerLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, "runner.lock"))
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("runner lock mode = (%v, %v)", info, err)
	}
}

func TestOPS06ProductionHTTPRuntimeRequiresMTLSAndSeedsRestartLKG(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(root, "credentials")
	lkgDirectory := filepath.Join(root, "lkg")
	for _, directory := range []string{credentials, lkgDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	caFile, certificateFile, keyFile := writeOPS06ClientPKI(t, credentials)
	tokenFile := filepath.Join(credentials, "token")
	if err := os.WriteFile(tokenFile, []byte("internal-token-32-bytes-long-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	installationID := uuid.NewString()
	lkgPath := filepath.Join(lkgDirectory, "plan.bundle")
	store, err := NewHTTPLKGStore(lkgPath, installationID, controlplaneupgrade.SystemdControlUpgradeOperation, 1024)
	if err != nil {
		t.Fatal(err)
	}
	plan := ops06HTTPPlan([]byte(`{"signed":"restart"}`), 9)
	if err := store.Save(plan); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", tokenFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_URL", "https://control.example/v1/internal/control-upgrade/plan")
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE", caFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE", certificateFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE", keyFile)
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT", "2s")
	t.Setenv("CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES", "1024")
	t.Setenv("CONTROL_UPGRADE_PLAN_LKG_FILE", lkgPath)
	source, reopened, initial, err := openHTTPPlanRuntime(installationID)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := source.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != 0x0304 || transport.TLSClientConfig.MaxVersion != 0x0304 ||
		len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("HTTP mTLS transport = %#v", transport)
	}
	if reopened == nil || initial == nil || !sameHTTPPlan(*initial, plan) || source.cached == nil ||
		!sameHTTPPlan(*source.cached, plan) {
		t.Fatalf("restart seed store=%v initial=%#v cache=%#v", reopened, initial, source.cached)
	}
}

func TestOPS06RunPlanLoopPersistsFreshAndUsesExactDegradedLKG(t *testing.T) {
	fresh := ops06HTTPPlan([]byte(`{"signed":"fresh-plan-secret"}`), 2)
	lkg := ops06HTTPPlan([]byte(`{"signed":"lkg-plan-secret"}`), 1)
	verifier := func(bundle []byte) error {
		if bytes.Contains(bundle, []byte("invalid")) {
			return controlplaneupgrade.ErrInvalidPlan
		}
		return nil
	}

	t.Run("fresh 200 persists before run", func(t *testing.T) {
		events := []string{}
		source := &ops06PlanSource{plans: []HTTPPlan{fresh}, events: &events}
		store := &ops06LKGWriter{events: &events}
		runner := &ops06PlanRunner{events: &events}
		orderedVerifier := func(bundle []byte) error {
			events = append(events, "verify")
			return verifier(bundle)
		}
		if err := runPlanLoop(t.Context(), source, store, nil, runner, orderedVerifier, time.Millisecond, true,
			slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(events, []string{"fetch", "verify", "save", "run"}) || len(store.saved) != 1 ||
			!sameHTTPPlan(store.saved[0], fresh) || string(runner.bundles[0]) != string(fresh.Bundle) {
			t.Fatalf("events=%v saved=%#v bundles=%q", events, store.saved, runner.bundles)
		}
	})

	t.Run("304 restart exact replay", func(t *testing.T) {
		replayed := cloneHTTPPlan(lkg)
		replayed.Replayed = true
		store := &ops06LKGWriter{}
		runner := &ops06PlanRunner{}
		if err := runPlanLoop(t.Context(), &ops06PlanSource{plans: []HTTPPlan{replayed}}, store, &lkg,
			runner, verifier, time.Millisecond, true, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
			t.Fatal(err)
		}
		if len(store.saved) != 0 || len(runner.bundles) != 1 || string(runner.bundles[0]) != string(lkg.Bundle) {
			t.Fatalf("304 saved=%d bundles=%q", len(store.saved), runner.bundles)
		}
	})

	t.Run("bad response preserves LKG and logs no secret", func(t *testing.T) {
		invalid := ops06HTTPPlan([]byte(`{"signed":"invalid-response-plan-secret"}`), 3)
		var logs bytes.Buffer
		store := &ops06LKGWriter{}
		runner := &ops06PlanRunner{}
		if err := runPlanLoop(t.Context(), &ops06PlanSource{plans: []HTTPPlan{invalid}}, store, &lkg,
			runner, verifier, time.Millisecond, true, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
			t.Fatal(err)
		}
		if len(store.saved) != 0 || len(runner.bundles) != 1 || string(runner.bundles[0]) != string(lkg.Bundle) ||
			!strings.Contains(logs.String(), "degraded") || strings.Contains(logs.String(), "plan-secret") ||
			strings.Contains(logs.String(), "internal-token") {
			t.Fatalf("fallback saved=%d bundles=%q logs=%q", len(store.saved), runner.bundles, logs.String())
		}
	})

	t.Run("durability failure preserves LKG", func(t *testing.T) {
		var logs bytes.Buffer
		store := &ops06LKGWriter{err: ErrHTTPLKGUnavailable}
		runner := &ops06PlanRunner{}
		if err := runPlanLoop(t.Context(), &ops06PlanSource{plans: []HTTPPlan{fresh}}, store, &lkg,
			runner, verifier, time.Millisecond, true, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
			t.Fatal(err)
		}
		if len(runner.bundles) != 1 || string(runner.bundles[0]) != string(lkg.Bundle) ||
			!strings.Contains(logs.String(), "degraded") || strings.Contains(logs.String(), "plan-secret") {
			t.Fatalf("durability fallback bundles=%q logs=%q", runner.bundles, logs.String())
		}
	})

	t.Run("unavailable source without LKG fails closed", func(t *testing.T) {
		runner := &ops06PlanRunner{}
		err := runPlanLoop(t.Context(), &ops06PlanSource{errors: []error{ErrHTTPPlanSourceUnavailable}},
			&ops06LKGWriter{}, nil, runner, verifier, time.Millisecond, true,
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		if !errors.Is(err, ErrNoVerifiedPlan) || len(runner.bundles) != 0 {
			t.Fatalf("fail-closed error=%v bundles=%d", err, len(runner.bundles))
		}
	})
}

type ops06PlanSource struct {
	plans  []HTTPPlan
	errors []error
	index  int
	events *[]string
}

func (source *ops06PlanSource) Fetch(context.Context) (HTTPPlan, error) {
	if source.events != nil {
		*source.events = append(*source.events, "fetch")
	}
	index := source.index
	source.index++
	if index < len(source.errors) && source.errors[index] != nil {
		return HTTPPlan{}, source.errors[index]
	}
	if index >= len(source.plans) {
		return HTTPPlan{}, ErrHTTPPlanSourceUnavailable
	}
	return cloneHTTPPlan(source.plans[index]), nil
}

type ops06LKGWriter struct {
	saved  []HTTPPlan
	err    error
	events *[]string
}

func (store *ops06LKGWriter) Save(plan HTTPPlan) error {
	if store.events != nil {
		*store.events = append(*store.events, "save")
	}
	if store.err != nil {
		return store.err
	}
	store.saved = append(store.saved, cloneHTTPPlan(plan))
	return nil
}

type ops06PlanRunner struct {
	bundles [][]byte
	err     error
	events  *[]string
}

func (runner *ops06PlanRunner) Run(_ context.Context, bundle []byte) (controlplaneupgrade.Receipt, error) {
	if runner.events != nil {
		*runner.events = append(*runner.events, "run")
	}
	runner.bundles = append(runner.bundles, append([]byte(nil), bundle...))
	return controlplaneupgrade.Receipt{}, runner.err
}

func writeOPS06ClientPKI(t *testing.T, root string) (string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OPS06 CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OPS06 runner"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, clientPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, block *pem.Block, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return write("ca.pem", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}, 0o600),
		write("client.pem", &pem.Block{Type: "CERTIFICATE", Bytes: clientDER}, 0o600),
		write("client-key.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}, 0o600)
}
