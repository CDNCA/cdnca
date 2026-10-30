package goldenrelease

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// crsProfilePacks are copies of libs/rulepack/testdata/crs-profiles (the
// packs license migration 087 seeds; TestEmbeddedCRSProfilePacksMatchRulepack
// keeps them equal), embedded so the renderers run without the source tree.
//
//go:embed crsprofiles/*.json
var crsProfilePacks embed.FS

// CRSProfiles are the embedded system CRS profile packs, by digest (the
// dynamic routing renderer and the agent check give the node these packs).
func CRSProfiles() (map[string]edgeconfig.CRSProfile, error) {
	entries, err := crsProfilePacks.ReadDir("crsprofiles")
	if err != nil {
		return nil, err
	}
	result := map[string]edgeconfig.CRSProfile{}
	for _, entry := range entries {
		content, err := crsProfilePacks.ReadFile("crsprofiles/" + entry.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			return nil, err
		}
		result[profile.Ref.SHA256] = profile
	}
	return result, nil
}

// crsProfilePack is the embedded system/crs-* pack with digest.
func crsProfilePack(digest string) ([]byte, error) {
	entries, err := crsProfilePacks.ReadDir("crsprofiles")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		content, err := crsProfilePacks.ReadFile("crsprofiles/" + entry.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) == digest {
			return content, nil
		}
	}
	return nil, fmt.Errorf("no CRS profile pack %s", digest)
}
