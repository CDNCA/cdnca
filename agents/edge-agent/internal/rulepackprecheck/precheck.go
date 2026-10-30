// Package rulepackprecheck is the node side of rule pack mounts (ADR 0009
// §8.4): before a site's security.mounts is applied the agent recompiles it
// from the pack objects with the same compiler the control plane used
// (libs/rulepack) and refuses the document unless it reproduces the order
// and resolved_sha256. Delivery (artifact set, site objects) is not wired
// yet; this is the precheck those installers call.
package rulepackprecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/rulepack"
)

// Objects returns the bytes of a content-addressed object (pack artifact)
// by its sha256, or an error when the node does not have it.
type Objects func(sha256 string) ([]byte, error)

var ErrRejected = errors.New("rule pack mounts rejected")

// Loader compiles an object's bytes: rulepack.Load for plain packs; the
// rule pack vault (rulepackvault.Vault.Load) also opens sealed ones (PA-14).
type Loader func(content []byte, sha256 string) (*rulepack.CompiledPack, error)

// Check decodes a security document, loads every mounted pack by digest and
// verifies the document. It returns the node rules in execution order. A
// sealed pack is refused (CheckWith opens it with the vault).
func Check(document []byte, objects Objects) ([]rulepack.NodeRule, error) {
	return CheckWith(document, objects, rulepack.Load)
}

func decodeSecurity(document []byte) (rulepack.Security, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var security rulepack.Security
	if err := decoder.Decode(&security); err != nil {
		return rulepack.Security{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return security, nil
}

// CheckWith is Check with the pack loader.
func CheckWith(document []byte, objects Objects, load Loader) (rules []rulepack.NodeRule, err error) {
	rules, _, _, err = checkWithPacks(document, objects, load)
	return rules, err
}

// checkWithPacks is CheckWith that also returns the decoded document and the
// loaded packs by digest.
func checkWithPacks(document []byte, objects Objects, load Loader) ([]rulepack.NodeRule, rulepack.Security,
	map[string]*rulepack.CompiledPack, error) {
	security, err := decodeSecurity(document)
	if err != nil {
		return nil, rulepack.Security{}, nil, err
	}
	packs := make(map[string]*rulepack.CompiledPack, len(security.Mounts))
	for _, mount := range security.Mounts {
		if _, loaded := packs[mount.SHA256]; loaded {
			continue
		}
		content, err := objects(mount.SHA256)
		if err != nil {
			return nil, rulepack.Security{}, nil, fmt.Errorf("%w: pack %s object %s: %v", ErrRejected, mount.PackID, mount.SHA256, err)
		}
		pack, err := load(content, mount.SHA256)
		if err != nil {
			return nil, rulepack.Security{}, nil, fmt.Errorf("%w: pack %s: %v", ErrRejected, mount.PackID, err)
		}
		packs[mount.SHA256] = pack
	}
	rules, err := rulepack.Verify(security, packs)
	if err != nil {
		return nil, rulepack.Security{}, nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return rules, security, packs, nil
}
