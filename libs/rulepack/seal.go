package rulepack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Content protection of encrypted packs (ADR 0007 §6, PA-14): "防复制、防随手
// 看、可追溯，不防节点 root".
//
// A sealed pack (cdnca.rule-pack-sealed/v1) is a public manifest — the pack
// without its rules, plus what the control plane needs to list, enable and
// mount it — and the canonical pack bytes encrypted with AES-256-GCM under
// the pack version's content key (CEK). The AAD binds the manifest, so
// neither half can be swapped. The control plane only ever reads the
// manifest; the node decrypts in memory (Open) and requires the plaintext to
// reproduce the manifest exactly.
//
// The bytes the catalog names (sha256) are the sealed document: the license
// service seals each installation's watermarked copy, so copies differ per
// installation and the CEK is delivered wrapped per installation (wrap.go).
const (
	SealedSchema   = "cdnca.rule-pack-sealed/v1"
	ManifestSchema = "cdnca.rule-pack-manifest/v1"
	CEKSize        = 32
	// MaxSealedBytes bounds a sealed document: a MaxPackBytes plaintext in
	// base64 plus the manifest.
	MaxSealedBytes = 2 << 20

	sealAADDomain   = "cdnca-rule-pack-seal-aad/v1\x00"
	sealNonceDomain = "cdnca-rule-pack-seal-nonce/v1\x00"
)

var (
	// ErrSealRejected: a sealed document is malformed, its ciphertext does
	// not authenticate (tampered, or another CEK) or its plaintext does not
	// reproduce the manifest.
	ErrSealRejected = errors.New("sealed rule pack rejected")
)

// Manifest is the public part of a sealed pack. Field order is the
// canonical order (json.Marshal of the struct, sorted map keys).
type Manifest struct {
	Schema           string               `json:"schema"`
	PackID           string               `json:"pack_id"`
	Version          string               `json:"version"`
	Layer            Layer                `json:"layer"`
	Engine           Engine               `json:"engine"`
	EngineMinVersion uint32               `json:"engine_min_version"`
	Name             string               `json:"name"`
	Description      string               `json:"description"`
	LicenseSPDX      string               `json:"license_spdx,omitempty"`
	ParamsSchema     map[string]ParamSpec `json:"params_schema"`
	Exports          []string             `json:"exports"`
	// ExportNames are the display names of the exported rules (page only).
	ExportNames           map[string]string `json:"export_names"`
	Defaults              Params            `json:"defaults"`
	RequiredEngineVersion uint32            `json:"required_engine_version"`
	Requires              []string          `json:"requires"`
	Cost                  Cost              `json:"cost"`
	RuleCount             int               `json:"rule_count"`
	// PlaintextSHA256 is the digest of the canonical pack bytes.
	PlaintextSHA256 string `json:"plaintext_sha256"`
	// CRSRuleIDs (modsecurity, required there) is the CRS rule numbers the
	// pack's rule sets evaluate, computed by the sealer from the plaintext
	// (Seal, PackCRSRuleIDs), never taken from the seller. It is bound to the
	// ciphertext (AAD) and the license service signs the sealed document's
	// digest in its catalog, so the control plane can check a site's CRS
	// profile by it without the rules; the node checks it once it opens the
	// pack (CheckCRSRuleIDs).
	CRSRuleIDs []int `json:"crs_rule_ids,omitempty"`
}

// Sealed is the sealed document.
type Sealed struct {
	Schema     string   `json:"schema"`
	Manifest   Manifest `json:"manifest"`
	Nonce      string   `json:"nonce"`
	Ciphertext string   `json:"ciphertext"`
}

// ManifestOf returns the manifest of a compiled (plaintext) pack.
func ManifestOf(compiled *CompiledPack) Manifest {
	pack := compiled.Pack
	names := make(map[string]string, len(pack.Exports))
	for _, id := range pack.Exports {
		if rule, ok := findRule(pack, id); ok {
			names[id] = rule.Name
		}
	}
	requires := append([]string{}, compiled.Requires...)
	return Manifest{Schema: ManifestSchema, PackID: pack.PackID, Version: pack.Version, Layer: pack.Layer,
		Engine: pack.Engine, EngineMinVersion: pack.EngineMinVersion, Name: pack.Name, Description: pack.Description,
		LicenseSPDX: pack.LicenseSPDX, ParamsSchema: pack.ParamsSchema, Exports: append([]string{}, pack.Exports...),
		ExportNames: names, Defaults: pack.Defaults, RequiredEngineVersion: compiled.RequiredEngineVersion,
		Requires: requires, Cost: compiled.Cost, RuleCount: len(pack.Rules), PlaintextSHA256: compiled.SHA256,
		CRSRuleIDs: append([]int(nil), compiled.CRSRuleIDs...)}
}

// Seal encrypts a canonical pack under cek. The nonce is derived from the
// CEK and the plaintext digest, so sealing the same bytes twice gives the
// same document (the catalog digest of an installation's copy is stable)
// and two different plaintexts never share a nonce under one CEK.
//
// A modsecurity pack's manifest carries the CRS rule numbers its rule sets
// evaluate in crs (the CRS rule text the license service publishes),
// computed here from the plaintext (PackCRSRuleIDs): crs is required for
// one, ignored otherwise.
func Seal(canonical, cek []byte, crs *edgeconfig.CRSManifest) ([]byte, error) {
	compiled, err := Compile(canonical)
	if err != nil {
		return nil, err
	}
	var ids []int
	if compiled.Pack.Engine == EngineModSecurity && !IsCRSTuningPack(compiled.Pack.PackID) {
		if ids, err = ComputeCRSRuleIDs(crs, compiled.Pack); err != nil {
			return nil, err
		}
	}
	return SealWithCRSRuleIDs(canonical, cek, ids)
}

// SealWithCRSRuleIDs is Seal with the manifest's CRS rule list given (nil
// for other engines). Only the sealer that computed ids from the same
// plaintext (Seal) or a test forging a wrong list calls it.
func SealWithCRSRuleIDs(canonical, cek []byte, ids []int) ([]byte, error) {
	if len(cek) != CEKSize {
		return nil, fmt.Errorf("%w: content key must be %d bytes", ErrSealRejected, CEKSize)
	}
	compiled, err := Compile(canonical)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(compiled.Canonical, canonical) {
		return nil, fmt.Errorf("%w: not in canonical form", ErrInvalidPack)
	}
	if len(ids) != 0 {
		if err := validCRSRuleIDs(compiled.Pack.Engine, ids); err != nil {
			return nil, fmt.Errorf("%w: crs_rule_ids: %v", ErrInvalidPack, err)
		}
	}
	compiled.CRSRuleIDs = ids
	manifest := ManifestOf(compiled)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	aead, err := newPackAEAD(cek)
	if err != nil {
		return nil, err
	}
	nonce := deriveNonce(cek, compiled.SHA256, aead.NonceSize())
	ciphertext := aead.Seal(nil, nonce, canonical, sealAAD(manifestBytes))
	document, err := json.Marshal(Sealed{Schema: SealedSchema, Manifest: manifest,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)})
	if err != nil || len(document) > MaxSealedBytes {
		return nil, fmt.Errorf("%w: sealed document is too large", ErrInvalidPack)
	}
	return document, nil
}

// OpenManifest checks a sealed document's form and digest without any key
// and returns its manifest as a compiled pack with no rules (Sealed set).
// This is all the control plane reads of an encrypted pack.
func OpenManifest(document []byte, wantSHA256 string) (*CompiledPack, error) {
	sealed, err := decodeSealed(document, wantSHA256)
	if err != nil {
		return nil, err
	}
	return manifestPack(sealed.Manifest, document, wantSHA256), nil
}

// Open decrypts a sealed document with cek in memory, recompiles the
// plaintext and requires it to reproduce the manifest. The result runs the
// pack's rules; SHA256 / Canonical are those of the sealed document (what
// mounts and the object store name), not of the plaintext.
func Open(document []byte, wantSHA256 string, cek []byte) (*CompiledPack, error) {
	sealed, err := decodeSealed(document, wantSHA256)
	if err != nil {
		return nil, err
	}
	if len(cek) != CEKSize {
		return nil, fmt.Errorf("%w: content key must be %d bytes", ErrSealRejected, CEKSize)
	}
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(sealed.Nonce)
	ciphertext, cipherErr := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	aead, err := newPackAEAD(cek)
	if err != nil || nonceErr != nil || cipherErr != nil || len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: nonce or ciphertext is invalid", ErrSealRejected)
	}
	manifestBytes, _ := json.Marshal(sealed.Manifest)
	plaintext, err := aead.Open(nil, nonce, ciphertext, sealAAD(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext does not authenticate", ErrSealRejected)
	}
	defer clear(plaintext)
	compiled, err := Load(plaintext, sealed.Manifest.PlaintextSHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: plaintext: %v", ErrSealRejected, err)
	}
	// The CRS rule list is the sealer's (the node has no say in it here):
	// CheckCRSRuleIDs checks the opened rules evaluate exactly it.
	compiled.CRSRuleIDs = append([]int(nil), sealed.Manifest.CRSRuleIDs...)
	reproduced, _ := json.Marshal(ManifestOf(compiled))
	if !bytes.Equal(reproduced, manifestBytes) {
		return nil, fmt.Errorf("%w: plaintext does not match the manifest", ErrSealRejected)
	}
	compiled.Sealed = true
	compiled.ExportNames = sealed.Manifest.ExportNames
	compiled.Canonical = append([]byte(nil), document...)
	compiled.SHA256 = wantSHA256
	return compiled, nil
}

// IsSealed reports whether document is a sealed pack (its schema field);
// it does not validate it.
func IsSealed(document []byte) bool {
	var probe struct {
		Schema string `json:"schema"`
	}
	return json.Unmarshal(document, &probe) == nil && probe.Schema == SealedSchema
}

func decodeSealed(document []byte, wantSHA256 string) (Sealed, error) {
	sum := sha256.Sum256(document)
	if len(document) == 0 || len(document) > MaxSealedBytes || hex.EncodeToString(sum[:]) != wantSHA256 {
		return Sealed{}, fmt.Errorf("%w: digest mismatch", ErrSealRejected)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var sealed Sealed
	if err := decoder.Decode(&sealed); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Sealed{}, fmt.Errorf("%w: document is not a sealed pack", ErrSealRejected)
	}
	canonical, err := json.Marshal(sealed)
	if err != nil || !bytes.Equal(canonical, document) || sealed.Schema != SealedSchema {
		return Sealed{}, fmt.Errorf("%w: document is not canonical", ErrSealRejected)
	}
	if err := validateManifest(sealed.Manifest); err != nil {
		return Sealed{}, err
	}
	return sealed, nil
}

// validateManifest checks the manifest on its own (no rules to check it
// against; Open checks it against the plaintext).
func validateManifest(manifest Manifest) error {
	invalid := func(reason string) error { return fmt.Errorf("%w: manifest %s", ErrSealRejected, reason) }
	if manifest.Schema != ManifestSchema {
		return invalid("schema")
	}
	if layer, ok := packIDLayer(manifest.PackID); !ok || layer != manifest.Layer {
		return invalid("pack_id / layer")
	}
	maximum, known := EngineMaxVersion[manifest.Engine]
	if !known || manifest.RequiredEngineVersion < 1 || manifest.EngineMinVersion < manifest.RequiredEngineVersion ||
		manifest.EngineMinVersion > maximum {
		return invalid("engine")
	}
	maxRules, maxExported := packBudget.Rules, maxExports
	if IsCRSTuningPack(manifest.PackID) {
		maxRules, maxExported = maxCRSTuningEntries, maxCRSTuningEntries
	}
	if !validText(manifest.Name, 1, 128) || !validText(manifest.Description, 0, 1000) || !sha256Hex(manifest.PlaintextSHA256) ||
		manifest.RuleCount < 1 || manifest.RuleCount > maxRules || manifest.Cost.within(packBudget) != nil {
		return invalid("name, description, digest, rule count or cost")
	}
	if !sort.StringsAreSorted(manifest.Exports) || len(manifest.Exports) > maxExported ||
		len(manifest.ExportNames) > len(manifest.Exports) || len(manifest.ParamsSchema) > maxParams {
		return invalid("exports or params")
	}
	for _, id := range manifest.Exports {
		if !ruleIDPattern.MatchString(id) && !crsRuleIDPattern.MatchString(id) {
			return invalid("export id")
		}
	}
	for id, name := range manifest.ExportNames {
		if sort.SearchStrings(manifest.Exports, id) == len(manifest.Exports) || !validText(name, 1, 128) {
			return invalid("export name")
		}
	}
	for name := range manifest.ParamsSchema {
		if !paramNamePattern.MatchString(name) || name == ParamExclusions {
			return invalid("param name")
		}
	}
	// A modsecurity manifest without the list (sealed before the license
	// service computed it) stays readable but cannot be mounted
	// (SiteCRSExclusions refuses it).
	if len(manifest.CRSRuleIDs) != 0 && validCRSRuleIDs(manifest.Engine, manifest.CRSRuleIDs) != nil {
		return invalid("crs_rule_ids")
	}
	pack := manifestAsPack(manifest)
	if _, err := normalizeParams(pack, manifest.Defaults, true); err != nil {
		return invalid("defaults")
	}
	return nil
}

func manifestAsPack(manifest Manifest) Pack {
	return Pack{Schema: Schema, PackID: manifest.PackID, Version: manifest.Version, Layer: manifest.Layer,
		Engine: manifest.Engine, EngineMinVersion: manifest.EngineMinVersion, Name: manifest.Name,
		Description: manifest.Description, LicenseSPDX: manifest.LicenseSPDX, ParamsSchema: manifest.ParamsSchema,
		Exports: manifest.Exports, Rules: nil, Defaults: manifest.Defaults}
}

func manifestPack(manifest Manifest, document []byte, digest string) *CompiledPack {
	return &CompiledPack{Pack: manifestAsPack(manifest), Canonical: append([]byte(nil), document...), SHA256: digest,
		RequiredEngineVersion: manifest.RequiredEngineVersion, Requires: append([]string{}, manifest.Requires...),
		Cost: manifest.Cost, Sealed: true, ExportNames: manifest.ExportNames,
		CRSRuleIDs: append([]int(nil), manifest.CRSRuleIDs...)}
}

func newPackAEAD(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("%w: content key", ErrSealRejected)
	}
	return cipher.NewGCM(block)
}

func deriveNonce(cek []byte, plaintextSHA256 string, size int) []byte {
	mac := hmac.New(sha256.New, cek)
	mac.Write([]byte(sealNonceDomain))
	mac.Write([]byte(plaintextSHA256))
	return mac.Sum(nil)[:size]
}

func sealAAD(manifest []byte) []byte {
	return append([]byte(sealAADDomain), manifest...)
}

func sha256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == hexLower(value)
}

func hexLower(value string) string {
	decoded, _ := hex.DecodeString(value)
	return hex.EncodeToString(decoded)
}
