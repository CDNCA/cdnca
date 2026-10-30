package apikeycredential

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestPepperKeyringVersionBindingAndRotation(t *testing.T) {
	active := bytes.Repeat([]byte{0x22}, 32)
	previous := bytes.Repeat([]byte{0x11}, 32)
	keyring, err := NewPepperKeyring(PepperKeyringConfig{
		ActiveVersion: "pepper-v2", Active: active,
		PreviousVersion: "pepper-v1", Previous: previous,
	})
	if err != nil {
		t.Fatalf("NewPepperKeyring() error = %v", err)
	}
	if !keyring.Configured() || keyring.ActiveVersion() != "pepper-v2" {
		t.Fatalf("configured keyring active version = %q", keyring.ActiveVersion())
	}

	version, activeDigest, ok := keyring.SignActive("test-domain\x00", []byte("payload"))
	if !ok || version != "pepper-v2" {
		t.Fatalf("active signature = (%q, %v)", version, ok)
	}
	previousDigest, ok := keyring.Sign("pepper-v1", "test-domain\x00", []byte("payload"))
	if !ok || bytes.Equal(activeDigest[:], previousDigest[:]) {
		t.Fatal("active and previous peppers did not remain version-bound")
	}
	if _, ok := keyring.Sign("pepper-unknown", "test-domain\x00", []byte("payload")); ok {
		t.Fatal("unknown pepper version was accepted")
	}
	for _, rendered := range []string{fmt.Sprint(keyring), fmt.Sprintf("%#v", keyring)} {
		if strings.Contains(rendered, string(active)) || strings.Contains(rendered, string(previous)) {
			t.Fatalf("keyring formatting exposed secret material: %q", rendered)
		}
	}
}

func TestPepperKeyringRejectsAmbiguousConfiguration(t *testing.T) {
	valid := bytes.Repeat([]byte{0x33}, 32)
	tests := []PepperKeyringConfig{
		{},
		{ActiveVersion: "pepper-v1", Active: valid[:31]},
		{ActiveVersion: " pepper-v1", Active: valid},
		{ActiveVersion: "pepper-v1", Active: valid, PreviousVersion: "pepper-v0"},
		{ActiveVersion: "pepper-v1", Active: valid, Previous: valid},
		{ActiveVersion: "pepper-v1", Active: valid, PreviousVersion: "pepper-v1", Previous: valid},
		{ActiveVersion: "pepper-v1", Active: valid, PreviousVersion: "pepper-v0", Previous: valid},
	}
	for index, config := range tests {
		if _, err := NewPepperKeyring(config); err == nil {
			t.Fatalf("invalid config %d was accepted", index)
		}
	}
}
