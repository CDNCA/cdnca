package rulepack

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Only the sqli fixture's rule bodies use the detect operator; nothing
// derived from a sealed copy except the plaintext itself may contain it.
const plaintextMarker = `"operator":"detect"`

type installation struct {
	id        string
	private   []byte
	public    []byte
	keyID     string
	sealed    []byte
	sha256    string
	wrapped   string
	watermark [WatermarkSize]byte
}

func newKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// deliver does what the license service does for one installation:
// watermark, seal under the version CEK, wrap the CEK to the installation.
func deliver(t *testing.T, canonical, cek, watermarkKey []byte, id string) installation {
	t.Helper()
	private, public := newKey(t)
	pack, err := Compile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	tag := WatermarkTag(watermarkKey, id, pack.Pack.PackID, pack.Pack.Version)
	marked, err := Watermark(canonical, tag)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(marked, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := installation{id: id, private: private, public: public, keyID: X25519KeyID(public), sealed: sealed,
		sha256: digestOf(sealed), watermark: tag}
	result.wrapped, err = WrapKey(public, cek, installationContext(result, pack.Pack))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func installationContext(target installation, pack Pack) WrapContext {
	return WrapContext{Purpose: WrapPurposeInstallation, RecipientKeyID: target.keyID, PackID: pack.PackID,
		Version: pack.Version, SealedSHA256: target.sha256}
}

func sqliCanonical(t *testing.T) []byte {
	return compileFile(t, "system-sqli.json").Canonical
}

func TestSealOpenRoundTrip(t *testing.T) {
	canonical := sqliCanonical(t)
	cek, watermarkKey := randomBytes(t, CEKSize), randomBytes(t, 32)
	a := deliver(t, canonical, cek, watermarkKey, "11111111-1111-4111-8111-111111111111")

	manifest, err := OpenManifest(a.sealed, a.sha256)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Sealed || len(manifest.Pack.Rules) != 0 || manifest.SHA256 != a.sha256 ||
		manifest.Pack.PackID != "system/sqli-basic" || manifest.ExportName("r010") == "" {
		t.Fatalf("manifest = %+v", manifest)
	}
	if !bytes.Contains(canonical, []byte(plaintextMarker)) || bytes.Contains(a.sealed, []byte(plaintextMarker)) {
		t.Fatal("sealed document carries plaintext rule content (or the marker is not in the plaintext)")
	}

	key, err := UnwrapKey(a.private, a.wrapped, installationContext(a, manifest.Pack))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(a.sealed, a.sha256, key)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Sealed || len(opened.Pack.Rules) != 2 || opened.SHA256 != a.sha256 {
		t.Fatalf("opened = %+v", opened)
	}
	// Deterministic: the same installation copy seals and wraps identically.
	again := deliverWithKey(t, canonical, cek, watermarkKey, a)
	if !bytes.Equal(again.sealed, a.sealed) || again.wrapped != a.wrapped {
		t.Fatal("sealing or wrapping is not deterministic")
	}
}

func deliverWithKey(t *testing.T, canonical, cek, watermarkKey []byte, target installation) installation {
	t.Helper()
	pack, _ := Compile(canonical)
	marked, err := Watermark(canonical, WatermarkTag(watermarkKey, target.id, pack.Pack.PackID, pack.Pack.Version))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(marked, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	target.sealed, target.sha256 = sealed, digestOf(sealed)
	target.wrapped, err = WrapKey(target.public, cek, installationContext(target, pack.Pack))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// ADR 0007 §6.2 "包文件在安装之间复制使用": A's copy (sealed bytes and its
// wrapped key) does not open at installation B.
func TestCopyToAnotherInstallationDoesNotDecrypt(t *testing.T) {
	canonical := sqliCanonical(t)
	cek, watermarkKey := randomBytes(t, CEKSize), randomBytes(t, 32)
	a := deliver(t, canonical, cek, watermarkKey, "11111111-1111-4111-8111-111111111111")
	b := deliver(t, canonical, cek, watermarkKey, "22222222-2222-4222-8222-222222222222")
	if a.sha256 == b.sha256 {
		t.Fatal("installations received the same bytes (no per-installation watermark)")
	}
	pack, _ := Compile(canonical)

	// B's key, A's wrapped CEK (bound to A's key id).
	if _, err := UnwrapKey(b.private, a.wrapped, installationContext(a, pack.Pack)); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("B unwrapped A's key: %v", err)
	}
	// B claims A's wrapped key is for itself.
	forged := installationContext(a, pack.Pack)
	forged.RecipientKeyID = b.keyID
	if _, err := UnwrapKey(b.private, a.wrapped, forged); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("A's wrapped key opened under B's key id: %v", err)
	}
	// A's sealed object with B's (valid) wrapped key: the binding names B's
	// object, so the key does not open for A's object.
	if _, err := UnwrapKey(b.private, b.wrapped, installationContext(installation{keyID: b.keyID, sha256: a.sha256}, pack.Pack)); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("B's wrapped key opened for A's object: %v", err)
	}
	// A node key wrap is not an installation key wrap.
	nodeContext := installationContext(a, pack.Pack)
	nodeContext.Purpose = WrapPurposeNode
	if _, err := UnwrapKey(a.private, a.wrapped, nodeContext); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("installation wrap opened as a node wrap: %v", err)
	}
	// Without the CEK the sealed bytes do not open.
	if _, err := Open(a.sealed, a.sha256, randomBytes(t, CEKSize)); !errors.Is(err, ErrSealRejected) {
		t.Fatalf("opened with another key: %v", err)
	}
}

func TestTamperedSealedPackIsRejected(t *testing.T) {
	canonical := sqliCanonical(t)
	cek, watermarkKey := randomBytes(t, CEKSize), randomBytes(t, 32)
	a := deliver(t, canonical, cek, watermarkKey, "11111111-1111-4111-8111-111111111111")
	var sealed Sealed
	if err := json.Unmarshal(a.sealed, &sealed); err != nil {
		t.Fatal(err)
	}
	reseal := func(change func(*Sealed)) ([]byte, string) {
		copied := sealed
		change(&copied)
		encoded, _ := json.Marshal(copied)
		return encoded, digestOf(encoded)
	}
	ciphertext, _ := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	ciphertext[len(ciphertext)/2] ^= 1
	cases := map[string]func(*Sealed){
		"ciphertext bit": func(s *Sealed) { s.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext) },
		"manifest name":  func(s *Sealed) { s.Manifest.Name = "改过的名字" },
		"manifest cost":  func(s *Sealed) { s.Manifest.Cost.Units = 1 },
		"nonce":          func(s *Sealed) { s.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 12)) },
	}
	for name, change := range cases {
		document, digest := reseal(change)
		if _, err := Open(document, digest, cek); !errors.Is(err, ErrSealRejected) {
			t.Errorf("%s: tampered document opened: %v", name, err)
		}
	}
	// The digest the catalog signed no longer matches.
	document, _ := reseal(cases["ciphertext bit"])
	if _, err := OpenManifest(document, a.sha256); !errors.Is(err, ErrSealRejected) {
		t.Errorf("tampered bytes passed the signed digest: %v", err)
	}
	// A tampered wrapped key does not open.
	wire, _ := base64.RawURLEncoding.DecodeString(a.wrapped)
	wire[len(wire)-1] ^= 1
	pack, _ := Compile(canonical)
	if _, err := UnwrapKey(a.private, base64.RawURLEncoding.EncodeToString(wire), installationContext(a, pack.Pack)); !errors.Is(err, ErrKeyRejected) {
		t.Errorf("tampered wrapped key opened: %v", err)
	}
	// A non-canonical spelling of the same document is refused.
	spaced := append([]byte(" "), a.sealed...)
	if _, err := OpenManifest(spaced, digestOf(spaced)); !errors.Is(err, ErrSealRejected) {
		t.Errorf("non-canonical sealed document accepted: %v", err)
	}
}

func TestWatermarkTracesTheInstallation(t *testing.T) {
	canonical := sqliCanonical(t)
	cek, watermarkKey := randomBytes(t, CEKSize), randomBytes(t, 32)
	ids := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333"}
	b := deliver(t, canonical, cek, watermarkKey, ids[1])
	opened, err := Open(b.sealed, b.sha256, cek)
	if err != nil {
		t.Fatal(err)
	}
	// The leaked plaintext as a node holds it.
	plaintext, _ := json.Marshal(opened.Pack)
	tag, err := ExtractWatermark(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if got := MatchWatermark(watermarkKey, tag, opened.Pack.PackID, opened.Pack.Version, ids); got != ids[1] {
		t.Fatalf("watermark traced to %q, want %q", got, ids[1])
	}
	// A single rule name is enough, and so is the manifest the control plane holds.
	if tag, err := ExtractWatermark([]byte(opened.Pack.Rules[0].Name)); err != nil || tag != b.watermark {
		t.Fatalf("rule name watermark = %x, %v", tag, err)
	}
	manifest, _ := OpenManifest(b.sealed, b.sha256)
	if tag, err := ExtractWatermark([]byte(manifest.Pack.Description)); err != nil || tag != b.watermark {
		t.Fatalf("manifest watermark = %x, %v", tag, err)
	}
	// Invisible: the visible text is unchanged; execution is unchanged.
	original, _ := Compile(canonical)
	for index, rule := range opened.Pack.Rules {
		if strings.Map(stripMark, rule.Name) != original.Pack.Rules[index].Name {
			t.Fatalf("rule %s visible name changed: %q", rule.ID, rule.Name)
		}
		left, _ := json.Marshal(rule.WAF)
		right, _ := json.Marshal(original.Pack.Rules[index].WAF)
		if !bytes.Equal(left, right) {
			t.Fatalf("watermark changed rule %s body", rule.ID)
		}
	}
	// No watermark in an unmarked pack; re-marking replaces the tag.
	if _, err := ExtractWatermark(canonical); !errors.Is(err, ErrNoWatermark) {
		t.Fatalf("unmarked pack: %v", err)
	}
	other := WatermarkTag(watermarkKey, ids[2], original.Pack.PackID, original.Pack.Version)
	remarked, err := Watermark(opened.Canonical[:0:0], other)
	if err == nil {
		t.Fatal("watermarking empty content succeeded")
	}
	marked, _ := Watermark(canonical, b.watermark)
	remarked, err = Watermark(marked, other)
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := ExtractWatermark(remarked); err != nil || tag != other {
		t.Fatalf("re-marked tag = %x, %v", tag, err)
	}
	// Long names are shortened, never over the field limit.
	long := strings.Repeat("长", 128)
	if got := withMark(long, encodeWatermark(other), maxNameRunes); len([]rune(got)) != maxNameRunes {
		t.Fatalf("marked name has %d runes", len([]rune(got)))
	}
}

func stripMark(r rune) rune {
	if watermarkSymbol(r) >= 0 {
		return -1
	}
	return r
}

// The control plane resolves a sealed mount from its manifest alone; the
// node, holding the CEK, reproduces the same resolved_sha256 and runs the
// sealed rules too. The control plane's resolution exposes no sealed rule.
func TestSealedMountsResolveIdenticallyOnControlAndNode(t *testing.T) {
	canonical := sqliCanonical(t)
	cek, watermarkKey := randomBytes(t, CEKSize), randomBytes(t, 32)
	a := deliver(t, canonical, cek, watermarkKey, "11111111-1111-4111-8111-111111111111")
	manifest, err := OpenManifest(a.sealed, a.sha256)
	if err != nil {
		t.Fatal(err)
	}
	cc := compileFile(t, "system-cc.json")
	user := compileFile(t, "user-allow.json")
	requests := []MountRequest{
		{Pack: manifest, Priority: 500, Params: Params{"action": json.RawMessage(`"log"`)}, RuleStates: map[string]bool{"r020": false}},
		{Pack: cc, Priority: 200, Params: Params{"requests": json.RawMessage(`300`)}},
		{Pack: user, Priority: 500},
	}
	resolution := Resolve(requests, Target{})
	if resolution.Security == nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	encoded, _ := json.Marshal(resolution)
	if bytes.Contains(encoded, []byte(plaintextMarker)) {
		t.Fatal("control plane resolution exposes sealed rule content")
	}
	for _, rule := range resolution.Rules {
		if rule.PackID == "system/sqli-basic" {
			t.Fatalf("sealed rule listed: %+v", rule)
		}
	}
	if resolution.Cost.Rules < manifest.Cost.Rules {
		t.Fatalf("sealed pack cost not counted: %+v", resolution.Cost)
	}

	opened, err := Open(a.sealed, a.sha256, cek)
	if err != nil {
		t.Fatal(err)
	}
	packs := map[string]*CompiledPack{a.sha256: opened, cc.SHA256: cc, user.SHA256: user}
	rules, err := Verify(*resolution.Security, packs)
	if err != nil {
		t.Fatal(err)
	}
	sealedRules := 0
	for _, rule := range rules {
		if rule.PackID == "system/sqli-basic" {
			sealedRules++
			if rule.RuleID == "r020" {
				t.Fatal("rule switched off by the site still runs")
			}
		}
	}
	if sealedRules != 1 {
		t.Fatalf("node runs %d sealed rules, want 1 (r010)", sealedRules)
	}
	// A node that only has the manifest cannot run the document.
	packs[a.sha256] = manifest
	if _, err := Verify(*resolution.Security, packs); err == nil {
		t.Fatal("node verified sealed mounts without opening the pack")
	}
	// Invalid params on a sealed mount are refused at the control plane too.
	bad := append([]MountRequest{}, requests...)
	bad[0].Params = Params{"action": json.RawMessage(`"drop"`)}
	if Resolve(bad, Target{}).Security != nil {
		t.Fatal("invalid sealed mount params accepted")
	}
}

func TestNodeRewrapOpensOnlyOnThatNode(t *testing.T) {
	canonical := sqliCanonical(t)
	cek := randomBytes(t, CEKSize)
	a := deliver(t, canonical, cek, randomBytes(t, 32), "11111111-1111-4111-8111-111111111111")
	pack, _ := Compile(canonical)
	installationKey, err := UnwrapKey(a.private, a.wrapped, installationContext(a, pack.Pack))
	if err != nil {
		t.Fatal(err)
	}
	node1Private, node1Public := newKey(t)
	node2Private, node2Public := newKey(t)
	contextFor := func(public []byte) WrapContext {
		return WrapContext{Purpose: WrapPurposeNode, RecipientKeyID: X25519KeyID(public), PackID: pack.Pack.PackID,
			Version: pack.Pack.Version, SealedSHA256: a.sha256}
	}
	wrapped, err := WrapKey(node1Public, installationKey, contextFor(node1Public))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnwrapKey(node1Private, wrapped, contextFor(node1Public)); err != nil || !bytes.Equal(got, cek) {
		t.Fatalf("node 1 unwrap: %v", err)
	}
	if _, err := UnwrapKey(node2Private, wrapped, contextFor(node2Public)); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("node 2 opened node 1's key: %v", err)
	}
	if _, err := WrapKey(node1Public, installationKey, contextFor(node2Public)); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("wrapped to a key that is not the named recipient: %v", err)
	}
}
