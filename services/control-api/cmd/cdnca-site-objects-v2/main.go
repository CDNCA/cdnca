// Command cdnca-site-objects-v2 runs the control plane's site object v2
// conversion (edgepublish.BuildSiteObjectsV2FromBundle, the production code)
// on a signed site runtime v2 bundle given as a directory of files, and
// writes the site objects and the objects they reference into an object
// directory (<out>/sha256/<2>/<2>/<64>) plus <out>/sites.json (site ID ->
// digest). The dynamic routing golden renderer (tests/edge-golden) and the
// security benchmark feed node runtimes from it. It holds no secret and
// connects to nothing.
//
//	cdnca-site-objects-v2 -bundle DIR -tenant UUID -out DIR
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

func main() {
	bundleDir := flag.String("bundle", "", "directory holding the bundle files (relative paths are bundle paths)")
	tenant := flag.String("tenant", "", "scope tenant (tenants.id)")
	out := flag.String("out", "", "output object directory")
	flag.Parse()
	if err := run(*bundleDir, *tenant, *out); err != nil {
		fmt.Fprintln(os.Stderr, "cdnca-site-objects-v2:", err)
		os.Exit(1)
	}
}

func run(bundleDir, tenant, out string) error {
	tenantID, err := uuid.Parse(tenant)
	if err != nil || bundleDir == "" || out == "" {
		return fmt.Errorf("need -bundle, -tenant and -out")
	}
	files := map[string][]byte{}
	manifest := edgeconfig.Manifest{}
	err = filepath.WalkDir(bundleDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(bundleDir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		files[relative] = content
		sum := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, edgeconfig.FileManifest{Path: relative, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return err
	}
	if manifest, err = edgeconfig.NormalizeManifest(manifest); err != nil {
		return err
	}
	digest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil {
		return err
	}
	built, err := edgepublish.BuildSiteObjectsV2FromBundle(edgeconfig.Bundle{Manifest: manifest, ManifestSHA256: digest, Files: files},
		tenantID)
	if err != nil {
		return err
	}
	sites := map[string]string{}
	for _, site := range built.Sites {
		if err := put(out, site.SHA256, site.Plaintext); err != nil {
			return err
		}
		sites[site.SiteID] = site.SHA256
	}
	for digest, content := range built.Referenced {
		if err := put(out, digest, content); err != nil {
			return err
		}
	}
	index, err := json.MarshalIndent(sites, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "sites.json"), append(index, '\n'), 0o644)
}

func put(root, digest string, content []byte) error {
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("object %s does not match its digest", digest)
	}
	dir := filepath.Join(root, "sha256", digest[:2], digest[2:4])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, digest), content, 0o644)
}
