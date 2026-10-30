package node

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testRegistrationKeys(t *testing.T) registrationKeys {
	t.Helper()
	keys, err := newRegistrationKeys(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatalf("newRegistrationKeys() error = %v", err)
	}
	return keys
}

func TestRegistrationKeysRejectShortSecret(t *testing.T) {
	if _, err := newRegistrationKeys(bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Fatal("newRegistrationKeys() accepted a short secret")
	}
}

func TestRegistrationCredentialRoundTrip(t *testing.T) {
	keys := testRegistrationKeys(t)
	scopeID, keyID := uuid.New(), uuid.New()
	credential := keys.credential(scopeID, keyID)
	if !strings.HasPrefix(credential, registrationCredentialPrefix) || len(credential) > 128 {
		t.Fatalf("credential = %q", credential)
	}
	if !registrationCredentialPattern.MatchString(credential) {
		t.Fatalf("credential %q does not match the shared install-node.sh pattern", credential)
	}
	if keys.credential(scopeID, keyID) != credential {
		t.Fatal("credential is not deterministic for the same key ID")
	}
	if keys.credential(scopeID, uuid.New()) == credential || keys.credential(uuid.New(), keyID) == credential {
		t.Fatal("credential does not bind scope and key ID")
	}
	parsed, err := keys.verifyCredential(scopeID, credential)
	if err != nil || parsed != keyID {
		t.Fatalf("verifyCredential() = %v, %v", parsed, err)
	}
	other, _ := newRegistrationKeys(bytes.Repeat([]byte{0x42}, 32))
	if _, err := other.verifyCredential(scopeID, credential); !errors.Is(err, ErrInvalidRegistrationCredential) {
		t.Fatalf("verifyCredential() with another secret error = %v", err)
	}
	// The tampered last character must differ from the original: a 32-byte
	// MAC's last base64url character is one of 16 values (A, E, I, ...), so a
	// fixed "A" left the credential unchanged in 1 of 16 runs.
	tampered := byte('A')
	if credential[len(credential)-1] == tampered {
		tampered = 'E'
	}
	for _, invalid := range []string{"", "nrk1.", credential + "x", strings.Replace(credential, "nrk1.", "nrk2.", 1),
		credential[:len(credential)-1] + string(tampered), "nrk1.not-a-uuid.abc"} {
		if _, err := keys.verifyCredential(scopeID, invalid); !errors.Is(err, ErrInvalidRegistrationCredential) {
			t.Fatalf("verifyCredential(%q) error = %v", invalid, err)
		}
	}
}

func TestRegisteredNodeIDsAreDeterministicAndMarked(t *testing.T) {
	keys := testRegistrationKeys(t)
	scopeID := uuid.New()
	fingerprint := bytes.Repeat([]byte{7}, 32)
	first := keys.registeredNodeID(scopeID, fingerprint, 0)
	if first != keys.registeredNodeID(scopeID, fingerprint, 0) {
		t.Fatal("registered node ID is not deterministic")
	}
	if first == keys.registeredNodeID(scopeID, fingerprint, 1) ||
		first == keys.registeredNodeID(uuid.New(), fingerprint, 0) ||
		first == keys.registeredNodeID(scopeID, bytes.Repeat([]byte{8}, 32), 0) {
		t.Fatal("registered node ID does not bind scope, fingerprint and generation")
	}
	if !IsSelfRegisteredNodeID(first) || first.Variant() != uuid.RFC4122 {
		t.Fatalf("registered node ID %s is not a version 8 RFC 9562 UUID", first)
	}
	reserved, _ := newID()
	if IsSelfRegisteredNodeID(reserved) {
		t.Fatal("console-reserved node IDs must not look self-registered")
	}
}

func TestNormalizeRegistrationRequest(t *testing.T) {
	valid := RegisterRequest{
		Credential: "nrk1.x", MachineFingerprint: strings.Repeat("ab", 32), Hostname: "  edge-01 ",
		OSName: "Ubuntu 24.04.1 LTS", KernelVersion: "6.8.0-45-generic", Architecture: "x86_64",
		SourceIP: "203.0.113.9", RequestID: "request-1",
	}
	normalized, err := normalizeRegisterRequest(valid)
	if err != nil {
		t.Fatalf("normalizeRegisterRequest() error = %v", err)
	}
	if normalized.hostname != "edge-01" || normalized.ipv4 != "203.0.113.9" || normalized.ipv6 != "" ||
		normalized.description != "Ubuntu 24.04.1 LTS · 6.8.0-45-generic · x86_64" || len(normalized.fingerprint) != 32 {
		t.Fatalf("normalized = %+v", normalized)
	}
	loopback := valid
	loopback.SourceIP = "127.0.0.1"
	if normalized, err := normalizeRegisterRequest(loopback); err != nil || normalized.ipv4 != "" {
		t.Fatalf("loopback source = %+v, %v", normalized, err)
	}
	v6 := valid
	v6.SourceIP = "2001:db8::9"
	if normalized, err := normalizeRegisterRequest(v6); err != nil || normalized.ipv6 != "2001:db8::9" || normalized.ipv4 != "" {
		t.Fatalf("IPv6 source = %+v, %v", normalized, err)
	}
	// The installer's reported public IP fills in when the request came over
	// a private network or loopback; a public source address wins.
	for _, c := range []struct{ source, reported, want string }{
		{"10.0.0.5", "8.8.8.8", "8.8.8.8"},
		{"127.0.0.1", "1.1.1.1", "1.1.1.1"},
		{"8.8.4.4", "1.1.1.1", "8.8.4.4"},
		{"10.0.0.5", "not-an-ip", "10.0.0.5"},
		{"10.0.0.5", "192.168.1.9", "10.0.0.5"},
		{"127.0.0.1", "", ""},
	} {
		r := valid
		r.SourceIP, r.PublicIP = c.source, c.reported
		if normalized, err := normalizeRegisterRequest(r); err != nil || normalized.ipv4 != c.want {
			t.Errorf("source %s reported %s: %+v %v, want %s", c.source, c.reported, normalized, err, c.want)
		}
	}
	empty := valid
	empty.Hostname = ""
	if normalized, err := normalizeRegisterRequest(empty); err != nil || normalized.hostname != "node" {
		t.Fatalf("empty hostname = %+v, %v", normalized, err)
	}
	for name, mutate := range map[string]func(*RegisterRequest){
		"short fingerprint":     func(r *RegisterRequest) { r.MachineFingerprint = "ab" },
		"uppercase fingerprint": func(r *RegisterRequest) { r.MachineFingerprint = strings.Repeat("AB", 32) },
		"control hostname":      func(r *RegisterRequest) { r.Hostname = "edge\n01" },
		"long hostname":         func(r *RegisterRequest) { r.Hostname = strings.Repeat("a", 129) },
		"long os":               func(r *RegisterRequest) { r.OSName = strings.Repeat("a", 129) },
		"missing request":       func(r *RegisterRequest) { r.RequestID = "" },
		"empty credential":      func(r *RegisterRequest) { r.Credential = "" },
	} {
		request := valid
		mutate(&request)
		if _, err := normalizeRegisterRequest(request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
}

func TestPendingNodeInitializationNeedsLiveIdentity(t *testing.T) {
	if err := validateStateChange(StatePending, StateActive, false); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("pending -> active without identity error = %v", err)
	}
	if err := validateStateChange(StatePending, StateActive, true); err != nil {
		t.Fatalf("pending -> active with identity error = %v", err)
	}
	for _, target := range []string{StateDraining, StateDisabled} {
		if err := validateStateChange(StatePending, target, true); !errors.Is(err, ErrStateTransition) {
			t.Fatalf("pending -> %s error = %v", target, err)
		}
	}
	if err := validateStateChange(StatePending, StateRetired, false); err != nil {
		t.Fatalf("pending -> retired error = %v", err)
	}
}

// "retired" as a target means delete, which works for every node, including a
// legacy retired row; nothing else may leave a retired row.
func TestDeleteTargetAcceptsEveryState(t *testing.T) {
	for _, current := range []string{StatePending, StateActive, StateDraining, StateDisabled, StateRetired} {
		if err := validateStateChange(current, StateRetired, false); err != nil {
			t.Fatalf("%s -> delete error = %v", current, err)
		}
	}
	for _, target := range []string{StateActive, StateDisabled, ""} {
		if err := validateStateChange(StateRetired, target, true); !errors.Is(err, ErrRetired) {
			t.Fatalf("retired -> %q error = %v", target, err)
		}
	}
}
