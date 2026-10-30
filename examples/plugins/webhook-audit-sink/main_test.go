package main

import (
	"io"
	"log"
	"os"
	"testing"
	"time"
)

func TestReceiverSecretsFromEnvironmentUsesStrictExpiry(t *testing.T) {
	tests := []struct {
		name         string
		previous     string
		validUntil   string
		wantError    bool
		wantPrevious bool
	}{
		{name: "not yet expired", previous: testPreviousKey, validUntil: "2026-07-23T08:31:00Z", wantPrevious: true},
		{name: "fractional UTC", previous: testPreviousKey, validUntil: "2026-07-23T08:31:00.25Z", wantPrevious: true},
		{name: "expiry boundary", previous: testPreviousKey, validUntil: "2026-07-23T08:30:00Z"},
		{name: "expired", previous: testPreviousKey, validUntil: "2026-07-23T08:29:59Z"},
		{name: "missing expiry", previous: testPreviousKey, wantError: true},
		{name: "expiry without previous", validUntil: "2026-07-23T08:31:00Z", wantError: true},
		{name: "non-canonical UTC", previous: testPreviousKey, validUntil: "2026-07-23T08:31:00+00:00", wantError: true},
		{name: "invalid expiry", previous: testPreviousKey, validUntil: "not-a-time", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CDNCA_WEBHOOK_SECRET_CURRENT", testCurrentKey)
			t.Setenv("CDNCA_WEBHOOK_SECRET_PREVIOUS", test.previous)
			t.Setenv("CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL", test.validUntil)
			secrets, err := receiverSecretsFromEnvironment(testNow)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError=%v", err, test.wantError)
			}
			if err == nil {
				defer secrets.clear()
				if (len(secrets.previous) != 0) != test.wantPrevious {
					t.Fatalf("previous bytes = %d, wantPrevious=%v", len(secrets.previous), test.wantPrevious)
				}
			}
			for _, name := range []string{
				"CDNCA_WEBHOOK_SECRET_CURRENT",
				"CDNCA_WEBHOOK_SECRET_PREVIOUS",
				"CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL",
			} {
				if _, exists := os.LookupEnv(name); exists {
					t.Fatalf("%s remained in the process environment", name)
				}
			}
		})
	}
}

func TestNewReceiverClearsAlreadyExpiredPreviousSecret(t *testing.T) {
	recorder := failingRecorder{}
	receiver, err := newReceiver(
		[]byte(testCurrentKey), []byte(testPreviousKey), testNow,
		testTenantID, recorder, func() time.Time { return testNow }, time.Minute, log.New(io.Discard, "", 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(receiver.previousSecret) != 0 || !receiver.previousValidUntil.IsZero() {
		t.Fatal("expired previous secret remained configured")
	}
	receiver.Close()
	if len(receiver.currentSecret) != 0 || len(receiver.previousSecret) != 0 {
		t.Fatal("receiver close retained secret bytes")
	}
}

func TestReceiverCopiesSecretsBeforeSourceClear(t *testing.T) {
	secrets := receiverSecrets{current: []byte(testCurrentKey), previous: []byte(testPreviousKey), previousValidUntil: testNow.Add(time.Minute)}
	currentSource := secrets.current
	previousSource := secrets.previous
	receiver, err := newReceiver(
		secrets.current, secrets.previous, secrets.previousValidUntil,
		testTenantID, failingRecorder{}, func() time.Time { return testNow }, time.Minute, log.New(io.Discard, "", 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	secrets.clear()
	for _, value := range append(currentSource, previousSource...) {
		if value != 0 {
			t.Fatal("source secret bytes were not cleared")
		}
	}
	if string(receiver.currentSecret) != testCurrentKey || string(receiver.previousSecret) != testPreviousKey {
		t.Fatal("receiver did not retain isolated secret copies")
	}
}
