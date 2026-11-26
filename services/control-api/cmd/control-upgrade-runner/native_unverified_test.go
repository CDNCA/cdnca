package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

// Issue 43: an unverified current release is logged once with a stable reason
// at start, and a signature-verified plan is refused with its bindings logged
// once per distinct rejection, without the bundle or signature.
func TestNativeUnverifiedCurrentReleaseIsLoggedAndRefusesPlans(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	installationID := uuid.NewString()
	signer := nativeVerifierSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.KeyID(), PublicKey: signer.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlplaneupgrade.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	probeErr := errors.Join(controlplaneupgrade.ErrTargetMismatch, errors.New("file_digest_differs bin/control-api"))
	status := controlplaneupgrade.NativeStandaloneStatus{Reason: controlplaneupgrade.NativeReasonCurrentReleaseUnverified, Phase: "idle",
		InstallationID: installationID, ProtocolVersion: 2, ArtifactFormat: controlplaneupgrade.NativeManifestSignedSchema}
	runner := nativeVerifierRunner{probe: func(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error) { return status, probeErr }}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	logNativeStartup(t.Context(), runner, logger)
	if line := logs.String(); !strings.Contains(line, "refusing plans") || !strings.Contains(line, controlplaneupgrade.NativeReasonCurrentReleaseUnverified) ||
		!strings.Contains(line, "bin/control-api") {
		t.Fatalf("startup diagnostic: %q", line)
	}
	logs.Reset()

	plan := nativeSignedPlan(t, signer, installationID, "1.0.35", "1.0.36", 42, now)
	verify := newNativePlanVerifier(t.Context(), trust, installationID, 2, store, runner, func() time.Time { return now }, logger)
	for range 3 {
		if err := verify(plan); !errors.Is(err, controlplaneupgrade.ErrTargetMismatch) {
			t.Fatalf("plan accepted on an unverified release: %v", err)
		}
	}
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(plan)
	if err != nil {
		t.Fatal(err)
	}
	line := logs.String()
	if strings.Count(line, "control upgrade plan rejected") != 1 || !strings.Contains(line, signed.Bundle.PlanID) ||
		!strings.Contains(line, "plan_current_version=1.0.35") || !strings.Contains(line, "plan_target_version=1.0.36") ||
		!strings.Contains(line, "reason="+controlplaneupgrade.NativeReasonCurrentReleaseUnverified) ||
		strings.Contains(line, signed.Signature) {
		t.Fatalf("rejection audit: %q", line)
	}
}

// With no published plan and no LKG the native loop waits and never runs
// anything, whatever the current release state; only cancellation ends it.
func TestNativeLoopWithoutPendingPlanStaysIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	fetches := 0
	source := nativePlanFetcherFunc(func(context.Context) (HTTPPlan, error) {
		if fetches++; fetches == 5 {
			cancel()
		}
		return HTTPPlan{}, ErrHTTPPlanNotPublished
	})
	runner := &ops06PlanRunner{}
	verify := func([]byte) error { t.Fatal("nothing to verify"); return nil }
	err := runPlanLoop(ctx, source, &ops06LKGWriter{}, nil, runner, verify, time.Millisecond, false,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if !errors.Is(err, context.Canceled) || fetches < 5 || len(runner.bundles) != 0 {
		t.Fatalf("idle loop err=%v fetches=%d runs=%d", err, fetches, len(runner.bundles))
	}
}
