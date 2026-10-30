package apikeycredential

import (
	"bytes"
	"testing"
	"time"
)

func TestVerifierConfigured(t *testing.T) {
	var nilVerifier *Verifier
	if nilVerifier.Configured() {
		t.Fatal("nil Verifier reported configured")
	}
	if new(Verifier).Configured() {
		t.Fatal("zero Verifier reported configured")
	}
	verifier, err := NewVerifier(bytes.Repeat([]byte{'p'}, 32), time.Now)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if !verifier.Configured() {
		t.Fatal("NewVerifier() result reported unconfigured")
	}
}
