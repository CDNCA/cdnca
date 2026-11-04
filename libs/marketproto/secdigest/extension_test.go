package secdigest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// A window with observe-only decisions: v1 summary of the enforced ones,
// log lines of both, and the logged count in the extension.
func withLogged() (Digest, Extension) {
	d := valid()
	d.Logs = append(d.Logs, Log{AtMS: start*1000 + 9, ClientIP: "203.0.113.8", Host: "www.example.test", Path: "/",
		Action: "log", Detector: "xss", RuleID: "941100"})
	return d, Extension{Logged: 7}
}

func TestExtendedRoundTrip(t *testing.T) {
	public, private := key(t)
	d, e := withLogged()
	signed, err := SignExtended(d, e, private)
	if err != nil {
		t.Fatal(err)
	}
	got, ext, err := VerifyExtended(public, signed)
	if err != nil || !reflect.DeepEqual(got, d) || ext != e {
		t.Fatalf("round trip %+v %+v %v", got, ext, err)
	}
}

// A subscriber built before the extension decodes Signed with only payload
// and signature (encoding/json, unknown keys ignored) and Verify accepts
// the same window, log lines with action "log" included.
func TestOldSubscriberAcceptsExtended(t *testing.T) {
	public, private := key(t)
	d, e := withLogged()
	signed, err := SignExtended(d, e, private)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(signed)
	var old struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify(public, Signed{Payload: old.Payload, Signature: old.Signature})
	if err != nil || !reflect.DeepEqual(got, d) {
		t.Fatalf("old subscriber: %+v %v", got, err)
	}
}

// A leaf built before the extension sends what Sign gives; a zero extension
// gives exactly that, and the new subscriber reads a zero Logged.
func TestOldLeafAndZeroExtension(t *testing.T) {
	public, private := key(t)
	d := valid()
	plain, err := Sign(d, private)
	if err != nil {
		t.Fatal(err)
	}
	zero, err := SignExtended(d, Extension{}, private)
	if err != nil || zero != plain {
		t.Fatalf("zero extension changed the wire: %+v %v", zero, err)
	}
	body, _ := json.Marshal(plain)
	if string(body) != `{"payload":"`+plain.Payload+`","signature":"`+plain.Signature+`"}` {
		t.Fatalf("v1 wire changed: %s", body)
	}
	got, ext, err := VerifyExtended(public, plain)
	if err != nil || !reflect.DeepEqual(got, d) || ext != (Extension{}) {
		t.Fatalf("old leaf: %+v %+v %v", got, ext, err)
	}
}

func TestExtensionRejected(t *testing.T) {
	public, private := key(t)
	_, otherPrivate := key(t)
	d, e := withLogged()
	signed, err := SignExtended(d, e, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignExtended(d, Extension{Logged: -1}, private); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative logged signed: %v", err)
	}
	// Moved onto another digest of the same leaf.
	other := valid()
	other.LeafSiteID = uuid.New()
	moved, err := Sign(other, private)
	if err != nil {
		t.Fatal(err)
	}
	moved.Extension, moved.ExtensionSignature = signed.Extension, signed.ExtensionSignature
	forged := signed
	raw, _ := json.Marshal(Extension{Logged: 1})
	forged.Extension = base64.StdEncoding.EncodeToString(raw)
	stripped := signed
	stripped.ExtensionSignature = ""
	otherSigned := signed // same payload bytes, extension signed by another key
	if s, err := SignExtended(d, e, otherPrivate); err != nil || s.Payload != signed.Payload {
		t.Fatalf("other key: %v", err)
	} else {
		otherSigned.ExtensionSignature = s.ExtensionSignature
	}
	negative := signed
	raw, _ = json.Marshal(Extension{Logged: -3})
	negative.Extension = base64.StdEncoding.EncodeToString(raw)
	negative.ExtensionSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, extensionMessage(negative.Payload, negative.Extension)))
	long := signed
	long.Extension = base64.StdEncoding.EncodeToString(make([]byte, maxExtension))
	long.ExtensionSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, extensionMessage(long.Payload, long.Extension)))
	for name, s := range map[string]Signed{"moved": moved, "forged": forged, "stripped": stripped,
		"other key": otherSigned, "negative": negative, "long": long} {
		if _, _, err := VerifyExtended(public, s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A later leaf may add extension fields; this subscriber keeps what it knows.
func TestExtensionUnknownFieldAccepted(t *testing.T) {
	public, private := key(t)
	d := valid()
	s, err := Sign(d, private)
	if err != nil {
		t.Fatal(err)
	}
	s.Extension = base64.StdEncoding.EncodeToString([]byte(`{"logged":4,"later":1}`))
	s.ExtensionSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, extensionMessage(s.Payload, s.Extension)))
	if _, ext, err := VerifyExtended(public, s); err != nil || ext.Logged != 4 {
		t.Fatalf("%+v %v", ext, err)
	}
}

// The extension stays small: the largest count is far under its bound, so
// a full digest plus extension stays within MaxPayload + a few hundred bytes.
func TestExtensionBounded(t *testing.T) {
	_, private := key(t)
	d := valid()
	fill(&d)
	s, err := SignExtended(d, Extension{Logged: math.MaxInt64}, private)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Extension) > maxExtension/4 || len(s.ExtensionSignature) != 88 {
		t.Fatalf("extension %d bytes, signature %d", len(s.Extension), len(s.ExtensionSignature))
	}
}
