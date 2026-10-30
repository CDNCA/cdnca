package grant

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func signRaw(private ed25519.PrivateKey, payload []byte) Signed {
	return Signed{KeyID: "k1", Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, signedMessage(payload)))}
}

func signedFields(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	raw, _ := json.Marshal(validGrant())
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	mutate(fields)
	payload, _ := json.Marshal(fields)
	return payload
}

// 1.0.35 does not accept v1 grants (ADR 0012 §10), and a field this leaf does
// not know may be a limit it cannot enforce, so v2 is strict at every level.
func TestVerifyRejectsV1AndUnknownFields(t *testing.T) {
	public, private := testKey(t)
	keyring := Keyring{"k1": public}
	cases := map[string]func(map[string]any){
		"v1 schema":        func(f map[string]any) { f["schema"] = "cdnca.market.supply-grant/v1" },
		"top level":        func(f map[string]any) { f["future_hint"] = 1 },
		"allocation":       func(f map[string]any) { f["allocation"].(map[string]any)["domains"] = 5 },
		"limit item":       func(f map[string]any) { f["limits"].([]any)[0].(map[string]any)["burst"] = 1 },
		"tags":             func(f map[string]any) { f["tags"].(map[string]any)["anycast"] = true },
		"load thresholds":  func(f map[string]any) { f["load_thresholds"].(map[string]any)["disk_percent"] = 1 },
		"compliance":       func(f map[string]any) { f["compliance"].(map[string]any)["require_x"] = true },
		"unknown metric":   func(f map[string]any) { f["limits"].([]any)[0].(map[string]any)["metric"] = "iops" },
		"limits not array": func(f map[string]any) { f["limits"] = map[string]any{} },
	}
	for name, mutate := range cases {
		if _, err := keyring.Verify(signRaw(private, signedFields(t, mutate))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// A v2 grant without limits is a valid unlimited grant.
	got, err := keyring.Verify(signRaw(private, signedFields(t, func(f map[string]any) { delete(f, "limits") })))
	if err != nil || len(got.Limits) != 0 {
		t.Fatalf("unlimited grant: %+v, %v", got.Limits, err)
	}
}

// Limits always encode as an array so the signed bytes of "unlimited" are
// stable ("limits":[] rather than null).
func TestUnlimitedGrantEncodesEmptyArray(t *testing.T) {
	_, private := testKey(t)
	g := validGrant()
	g.Limits = nil
	signed, err := Sign(g, "k1", private)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(signed.Payload)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || string(fields["limits"]) != "[]" {
		t.Fatalf("limits = %s, %v", fields["limits"], err)
	}
}
