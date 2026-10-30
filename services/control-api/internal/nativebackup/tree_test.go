package nativebackup

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingOwners struct{ chowned map[string][2]int }

func (owners *recordingOwners) Lookup(userName, groupName string, uid, gid int) (int, int, error) {
	// Simulate a target where the service account has another uid.
	if userName == "svc" || userName == "" && uid == 4242 {
		return 777, 778, nil
	}
	return os.Getuid(), os.Getgid(), nil
}

func (owners *recordingOwners) Chown(path string, uid, gid int) error {
	owners.chowned[path] = [2]int{uid, gid}
	return nil
}

func writeTree(t *testing.T, root string, files map[string]string, modes map[string]os.FileMode) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if mode, found := modes[name]; found {
			_ = os.Chmod(path, mode)
		}
	}
}

func TestTreeRoundTripPreservesContentModesAndExclusions(t *testing.T) {
	source := Layout{Root: t.TempDir()}
	writeTree(t, source.Root, map[string]string{
		"etc/cdnca-control/control.env":       "SECRET=1\n",
		"etc/cdnca-control/keys/pki/ca.pem":   "pem",
		"var/lib/cdnca-control/runtime.js":    "js",
		"var/lib/cdnca-control/nats/big.blk":  "excluded",
		"var/lib/cdnca-control/backups/x/old": "excluded",
	}, map[string]os.FileMode{"var/lib/cdnca-control/runtime.js": 0o644})
	_ = os.Symlink("releases/abc", filepath.Join(source.Root, "etc/cdnca-control/current"))
	paths := []treePath{
		{Path: "/etc/cdnca-control", Required: true},
		{Path: "/var/lib/cdnca-control", Exclude: []string{"nats", "backups"}},
		{Path: "/etc/absent"},
	}
	var archive bytes.Buffer
	stats, err := ArchiveTree(source, paths, &archive)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(stats.Present, ",") != "/etc/cdnca-control,/var/lib/cdnca-control" {
		t.Fatalf("present = %v", stats.Present)
	}
	if bytes.Contains(archive.Bytes(), []byte("excluded")) {
		t.Fatal("excluded children must not be archived")
	}
	target := Layout{Root: t.TempDir()}
	if err := CheckTreeAbsent(target, stats.Present); err != nil {
		t.Fatal(err)
	}
	owners := &recordingOwners{chowned: map[string][2]int{}}
	created, err := ExtractTree(target, paths, owners, bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 {
		t.Fatalf("created = %v", created)
	}
	data, _ := os.ReadFile(filepath.Join(target.Root, "etc/cdnca-control/control.env"))
	if string(data) != "SECRET=1\n" {
		t.Fatalf("content = %q", data)
	}
	if info, _ := os.Stat(filepath.Join(target.Root, "var/lib/cdnca-control/runtime.js")); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if info, _ := os.Stat(filepath.Join(target.Root, "etc/cdnca-control/control.env")); info.Mode().Perm() != 0o600 {
		t.Fatalf("secret mode = %v", info.Mode())
	}
	if link, _ := os.Readlink(filepath.Join(target.Root, "etc/cdnca-control/current")); link != "releases/abc" {
		t.Fatalf("symlink = %q", link)
	}
	if err := CheckTreeAbsent(target, stats.Present); err == nil {
		t.Fatal("preflight must refuse a populated target")
	}
	if _, err := ExtractTree(target, paths, owners, bytes.NewReader(archive.Bytes())); err == nil {
		t.Fatal("extract must never overwrite existing files")
	}
}

func TestExtractResolvesOwnersByNameAndRejectsEscapes(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	_ = writer.WriteHeader(&tar.Header{Name: "var/lib/svc/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 4242, Uname: "svc", Gname: "svc"})
	_ = writer.WriteHeader(&tar.Header{Name: "var/lib/svc/data", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1, Uid: 4242, Uname: "svc", Gname: "svc"})
	_, _ = writer.Write([]byte("x"))
	_ = writer.Close()
	target := Layout{Root: t.TempDir()}
	owners := &recordingOwners{chowned: map[string][2]int{}}
	if _, err := ExtractTree(target, []treePath{{Path: "/var/lib/svc"}}, owners, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got := owners.chowned[filepath.Join(target.Root, "var/lib/svc/data")]; got != [2]int{777, 778} {
		t.Fatalf("owner must be resolved by name on the target, got %v", got)
	}
	for _, name := range []string{"etc/passwd", "var/lib/svc/../../../etc/shadow"} {
		var hostile bytes.Buffer
		writer := tar.NewWriter(&hostile)
		_ = writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: 1})
		_, _ = writer.Write([]byte("x"))
		_ = writer.Close()
		if _, err := ExtractTree(Layout{Root: t.TempDir()}, []treePath{{Path: "/var/lib/svc"}}, owners, &hostile); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}
