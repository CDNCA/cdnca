package nativebackup

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The install-time backup timer runs `native-backup agent` while the installer
// runs `native-backup fingerprint`; both create the ring on first use. Every
// concurrent caller must get the same ring instead of "file exists".
func TestLoadOrCreateKeysConcurrentFirstUse(t *testing.T) {
	for round := 0; round < 20; round++ {
		layout := Layout{Root: t.TempDir()}
		const callers = 8
		var start, done sync.WaitGroup
		start.Add(1)
		fingerprints := make([]string, callers)
		recipients := make([]string, callers)
		errs := make([]error, callers)
		for index := 0; index < callers; index++ {
			done.Add(1)
			go func(index int) {
				defer done.Done()
				start.Wait()
				ring, err := LoadOrCreateKeys(layout)
				if err != nil {
					errs[index] = err
					return
				}
				fingerprints[index], recipients[index] = ring.Fingerprint(), ring.Recipient()
			}(index)
		}
		start.Done()
		done.Wait()
		for index := 0; index < callers; index++ {
			if errs[index] != nil {
				t.Fatalf("round %d caller %d: %v", round, index, errs[index])
			}
			if fingerprints[index] != fingerprints[0] || recipients[index] != recipients[0] {
				t.Fatalf("round %d caller %d got a different ring", round, index)
			}
		}
		ring, err := LoadKeys(layout)
		if err != nil || ring.Fingerprint() != fingerprints[0] || ring.Recipient() != recipients[0] {
			t.Fatalf("round %d: stored ring differs from the returned one: %v", round, err)
		}
		entries, err := os.ReadDir(layout.Path(BackupKeyDirectory))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if strings.Join(names, ",") != "identity.age-key,signing.pem" {
			t.Fatalf("round %d: key directory holds %v, want only the two key files", round, names)
		}
	}
}

// Same race as above, but between separate processes, as on the host: the
// child mode of this test creates the ring once a shared start file appears.
func TestLoadOrCreateKeysAcrossProcesses(t *testing.T) {
	if root := os.Getenv("CDNCA_KEYRACE_ROOT"); root != "" {
		for _, err := os.Stat(os.Getenv("CDNCA_KEYRACE_START")); err != nil; _, err = os.Stat(os.Getenv("CDNCA_KEYRACE_START")) {
			time.Sleep(time.Millisecond)
		}
		ring, err := LoadOrCreateKeys(Layout{Root: root})
		if err != nil {
			fmt.Printf("ring-error=%v\n", err)
			return
		}
		fmt.Printf("ring=%s %s\n", ring.Fingerprint(), ring.Recipient())
		return
	}
	for round := 0; round < 5; round++ {
		root, start := t.TempDir(), filepath.Join(t.TempDir(), "start")
		const callers = 4
		outputs := make([]bytes.Buffer, callers)
		commands := make([]*exec.Cmd, callers)
		for index := range commands {
			command := exec.Command(os.Args[0], "-test.run=^TestLoadOrCreateKeysAcrossProcesses$", "-test.count=1")
			command.Env = append(os.Environ(), "CDNCA_KEYRACE_ROOT="+root, "CDNCA_KEYRACE_START="+start)
			command.Stdout, command.Stderr = &outputs[index], &outputs[index]
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			commands[index] = command
		}
		time.Sleep(200 * time.Millisecond)
		if err := os.WriteFile(start, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		var rings []string
		for index, command := range commands {
			if err := command.Wait(); err != nil {
				t.Fatalf("round %d child %d: %v\n%s", round, index, err, outputs[index].String())
			}
			ring := ""
			for _, line := range strings.Split(outputs[index].String(), "\n") {
				if strings.HasPrefix(line, "ring=") {
					ring = line
				}
			}
			if ring == "" {
				t.Fatalf("round %d child %d got no ring:\n%s", round, index, outputs[index].String())
			}
			rings = append(rings, ring)
		}
		for index, ring := range rings {
			if ring != rings[0] {
				t.Fatalf("round %d child %d got a different ring: %q vs %q", round, index, ring, rings[0])
			}
		}
	}
}

// A first use interrupted between the two writes leaves one key file. The
// next call keeps that file as is and creates only the missing one.
func TestLoadOrCreateKeysCompletesHalfCreatedRing(t *testing.T) {
	for _, kept := range []string{"identity.age-key", "signing.pem"} {
		t.Run(kept, func(t *testing.T) {
			layout := Layout{Root: t.TempDir()}
			original, err := LoadOrCreateKeys(layout)
			if err != nil {
				t.Fatal(err)
			}
			directory := layout.Path(BackupKeyDirectory)
			removed := "signing.pem"
			if kept == "signing.pem" {
				removed = "identity.age-key"
			}
			before, err := os.ReadFile(filepath.Join(directory, kept))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(directory, removed)); err != nil {
				t.Fatal(err)
			}
			ring, err := LoadOrCreateKeys(layout)
			if err != nil {
				t.Fatalf("completing a ring with only %s: %v", kept, err)
			}
			after, err := os.ReadFile(filepath.Join(directory, kept))
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("%s was rewritten: %v", kept, err)
			}
			if kept == "identity.age-key" && ring.Recipient() != original.Recipient() {
				t.Fatal("identity was not reused")
			}
			if kept == "signing.pem" && ring.Fingerprint() != original.Fingerprint() {
				t.Fatal("signing key was not reused")
			}
			if _, err := os.Stat(filepath.Join(directory, removed)); err != nil {
				t.Fatalf("%s was not recreated: %v", removed, err)
			}
		})
	}
}

func TestWriteExclusiveNeverReplacesAndLeavesNoTemporary(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "identity.age-key")
	if err := writeExclusive(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(path, []byte("second\n")); !os.IsExist(err) {
		t.Fatalf("second write error = %v, want file exists", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first\n" {
		t.Fatalf("content = %q, %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want 1", len(entries))
	}
}
