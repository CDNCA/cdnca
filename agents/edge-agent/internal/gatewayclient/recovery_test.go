package gatewayclient

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type scriptedRecoverer struct {
	due      atomic.Bool
	attempts atomic.Int32
	recover  func(attempt int32) (bool, string, error)
}

func (recoverer *scriptedRecoverer) RecoveryDue() bool { return recoverer.due.Load() }

func (recoverer *scriptedRecoverer) Recover(context.Context) (bool, string, error) {
	attempt := recoverer.attempts.Add(1)
	recovered, sha, err := recoverer.recover(attempt)
	if recovered {
		recoverer.due.Store(false)
	}
	return recovered, sha, err
}

// GW-02: with an expired certificate Run recovers it before dialing; it never
// dials mTLS with the expired certificate, and once recovered it dials.
func TestRunRecoversExpiredCertificateBeforeDialing(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	config.InitialBackoff, config.MaximumBackoff = time.Millisecond, 5*time.Millisecond
	dialer := &failingDialer{}
	recoverer := &scriptedRecoverer{}
	recoverer.due.Store(true)
	recoverer.recover = func(int32) (bool, string, error) {
		if dialer.calls.Load() != 0 {
			t.Error("dialed with an expired certificate")
		}
		return true, "aa00000000000000000000000000000000000000000000000000000000000000", nil
	}
	var renewed atomic.Value
	client, err := New(config, dialer, noOpManager{}, testTrust(t), WithCertificateRecoverer(recoverer),
		WithCertificateRenewer(noRenewal{}, func(sha string) { renewed.Store(sha) }))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for dialer.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v", err)
	}
	if recoverer.attempts.Load() != 1 || dialer.calls.Load() == 0 {
		t.Fatalf("recovery attempts=%d dials=%d", recoverer.attempts.Load(), dialer.calls.Load())
	}
	if renewed.Load() != "aa00000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("certificate change callback = %v", renewed.Load())
	}
}

// A refused or unavailable recovery never stops Run (the node keeps serving).
func TestRunKeepsRetryingRefusedRecovery(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	dialer := &failingDialer{}
	recoverer := &scriptedRecoverer{recover: func(int32) (bool, string, error) { return false, "", errors.New("refused") }}
	recoverer.due.Store(true)
	client, err := New(config, dialer, noOpManager{}, testTrust(t), WithCertificateRecoverer(recoverer))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := client.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() = %v, want the context deadline", err)
	}
	if recoverer.attempts.Load() != 1 || dialer.calls.Load() != 0 {
		t.Fatalf("recovery attempts=%d dials=%d", recoverer.attempts.Load(), dialer.calls.Load())
	}
}

type noRenewal struct{}

func (noRenewal) Renew(context.Context, agentv1.AgentGatewayServiceClient) (bool, string, error) {
	return false, "", nil
}
