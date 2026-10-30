package enginemodule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BuildManifest describes an extension tree (for the packaging tool and
// tests): every regular file with its digest; modules and libraries 0555.
func BuildManifest(root string, base Manifest) (Manifest, error) {
	files := []FileEntry{}
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrManifest, current)
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		mode := uint32(0o444)
		if strings.HasPrefix(relative, "modules/") || strings.Contains(relative, ".so") {
			mode = 0o555
		}
		files = append(files, FileEntry{Path: filepath.ToSlash(relative), SHA256: Digest(content), Size: int64(len(content)), Mode: mode})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	base.Schema, base.Component, base.Files = ManifestSchema, Component, files
	return base, nil
}

// BuildPayload packs an extension tree as a deterministic tar.gz (sorted,
// fixed owner, mode and time).
func BuildPayload(root string, manifest Manifest) ([]byte, error) {
	var buffer bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer := tar.NewWriter(gz)
	for _, file := range manifest.Files {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, err
		}
		if err := writer.WriteHeader(&tar.Header{Name: file.Path, Mode: int64(file.Mode), Size: int64(len(content)),
			Typeflag: tar.TypeReg, Uname: "root", Gname: "root", Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(content); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ReadDirectory reads a published build directory (SHA256SUMS,
// manifest.json, signatures.json and the payload the manifest names).
func ReadDirectory(directory string) (Bundle, error) {
	read := func(name string, limit int64) ([]byte, error) {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
			return nil, fmt.Errorf("%w: %s", ErrBundle, name)
		}
		return os.ReadFile(filepath.Join(directory, name))
	}
	var bundle Bundle
	var err error
	if bundle.Sums, err = read(SumsName, MaxSumsBytes); err != nil {
		return Bundle{}, err
	}
	if bundle.Manifest, err = read(ManifestName, MaxManifestBytes); err != nil {
		return Bundle{}, err
	}
	if bundle.Signatures, err = read(SignaturesName, MaxSignaturesBytes); err != nil {
		return Bundle{}, err
	}
	manifest, err := DecodeManifest(bundle.Manifest)
	if err != nil {
		return Bundle{}, err
	}
	if bundle.Payload, err = read(manifest.Payload.Name, MaxPayloadBytes); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}
