package helper

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReceiptKeyLifecycle(t *testing.T) {
	config := testKeyConfig(t)
	key, err := EnsureReceiptKey(config, "helper-2026-01")
	if err != nil {
		t.Fatalf("EnsureReceiptKey: %v", err)
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize || key.KeyID != "helper-2026-01" {
		t.Fatalf("key = %#v", key)
	}
	if fmt.Sprintf("%v", key) != "receipt key material [REDACTED]" || fmt.Sprintf("%#v", key) != "receipt key material [REDACTED]" {
		t.Fatal("key material was not redacted by formatting")
	}
	if encoded, err := json.Marshal(key); err == nil || bytes.Contains(encoded, key.PrivateKey) {
		t.Fatalf("key material serialization = (%q, %v)", encoded, err)
	}
	assertFileMode(t, config.PrivatePath, privateKeyMode)
	assertFileMode(t, config.PublicPath, publicPinMode)

	pin, err := LoadReceiptPublicPin(config)
	if err != nil {
		t.Fatalf("LoadReceiptPublicPin: %v", err)
	}
	if pin.KeyID != key.KeyID || !bytes.Equal(pin.PublicKey, key.PrivateKey.Public().(ed25519.PublicKey)) {
		t.Fatal("public pin does not match private key")
	}
	if pair, err := LoadReceiptKeyPair(config); err != nil || !bytes.Equal(pair.PrivateKey, key.PrivateKey) {
		t.Fatalf("LoadReceiptKeyPair = (%v, %v)", pair, err)
	}
	publicContent, err := os.ReadFile(config.PublicPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicContent, []byte(privateKeyFile{PrivateKey: "private_key"}.PrivateKey)) || bytes.Contains(publicContent, key.PrivateKey) {
		t.Fatal("public pin contains private key material")
	}

	replayed, err := EnsureReceiptKey(config, key.KeyID)
	if err != nil || !bytes.Equal(replayed.PrivateKey, key.PrivateKey) {
		t.Fatalf("idempotent ensure = (%v, %v)", replayed, err)
	}
	if _, err := EnsureReceiptKey(config, "helper-2026-02"); !errors.Is(err, ErrKeyPolicy) {
		t.Fatalf("ensure with a changed id error = %v", err)
	}

	if err := os.Remove(config.PublicPath); err != nil {
		t.Fatal(err)
	}
	recovered, err := EnsureReceiptKey(config, key.KeyID)
	if err != nil || !bytes.Equal(recovered.PrivateKey, key.PrivateKey) {
		t.Fatalf("pin recovery = (%v, %v)", recovered, err)
	}

	oldPin, err := os.ReadFile(config.PublicPath)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateReceiptKey(config, "helper-2026-02")
	if err != nil {
		t.Fatalf("RotateReceiptKey: %v", err)
	}
	if bytes.Equal(rotated.PrivateKey, key.PrivateKey) || rotated.KeyID == key.KeyID {
		t.Fatal("rotation retained old key")
	}
	rotatedPin, err := LoadReceiptPublicPin(config)
	if err != nil || !publicPinMatches(rotatedPin, rotated) {
		t.Fatalf("rotated pin = (%v, %v)", rotatedPin, err)
	}
	writeTestProtectedFile(t, config.PublicPath, publicPinMode, oldPin)
	if _, err := LoadReceiptKeyPair(config); !errors.Is(err, ErrKeyPolicy) {
		t.Fatalf("interrupted rotation pair error = %v", err)
	}
	if recovered, err := EnsureReceiptKey(config, rotated.KeyID); err != nil || !bytes.Equal(recovered.PrivateKey, rotated.PrivateKey) {
		t.Fatalf("interrupted rotation recovery = (%v, %v)", recovered, err)
	}
	rotatedPin, err = LoadReceiptPublicPin(config)
	if err != nil || !publicPinMatches(rotatedPin, rotated) {
		t.Fatalf("recovered rotated pin = (%v, %v)", rotatedPin, err)
	}
	if _, err := RotateReceiptKey(config, rotated.KeyID); !errors.Is(err, ErrKeyPolicy) {
		t.Fatalf("same-id rotation error = %v", err)
	}
}

func TestReceiptKeyFilesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, config KeyConfig)
		load   func(KeyConfig) error
		want   error
	}{
		{
			name: "private-wide-mode",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				if err := os.Chmod(config.PrivatePath, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptKey(config); return err },
			want: ErrKeyPolicy,
		},
		{
			name: "public-wide-mode",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				if err := os.Chmod(config.PublicPath, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptPublicPin(config); return err },
			want: ErrKeyPolicy,
		},
		{
			name: "private-symlink",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				target := filepath.Join(filepath.Dir(config.PrivatePath), "target")
				if err := os.Rename(config.PrivatePath, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, config.PrivatePath); err != nil {
					t.Fatal(err)
				}
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptKey(config); return err },
			want: ErrKeyPolicy,
		},
		{
			name: "private-hardlink",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				if err := os.Link(config.PrivatePath, config.PrivatePath+".link"); err != nil {
					t.Fatal(err)
				}
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptKey(config); return err },
			want: ErrKeyPolicy,
		},
		{
			name: "unknown-field",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				writeTestProtectedFile(t, config.PrivatePath, privateKeyMode, []byte(`{"schema_version":1,"key_id":"helper-2026-01","private_key":"x","unknown":true}`))
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptKey(config); return err },
			want: ErrKeyCorrupt,
		},
		{
			name: "non-canonical-whitespace",
			mutate: func(t *testing.T, config KeyConfig) {
				t.Helper()
				content, err := os.ReadFile(config.PrivatePath)
				if err != nil {
					t.Fatal(err)
				}
				writeTestProtectedFile(t, config.PrivatePath, privateKeyMode, append([]byte(" "), content...))
			},
			load: func(config KeyConfig) error { _, err := LoadReceiptKey(config); return err },
			want: ErrKeyCorrupt,
		},
		{
			name:   "wrong-owner-policy",
			mutate: func(t *testing.T, config KeyConfig) {},
			load: func(config KeyConfig) error {
				config.OwnerUID++
				_, err := LoadReceiptKey(config)
				return err
			},
			want: ErrKeyPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testKeyConfig(t)
			if _, err := EnsureReceiptKey(config, "helper-2026-01"); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, config)
			if err := test.load(config); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReceiptKeyCanonicalFiles(t *testing.T) {
	config := testKeyConfig(t)
	if _, err := EnsureReceiptKey(config, "helper-2026-01"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.PrivatePath, config.PublicPath} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if path == config.PrivatePath {
			decoded = &privateKeyFile{}
		} else {
			decoded = &publicPinFile{}
		}
		if err := json.Unmarshal(content, decoded); err != nil {
			t.Fatal(err)
		}
		canonical, err := json.Marshal(decoded)
		if err != nil || !bytes.Equal(content, canonical) {
			t.Fatalf("%s is not canonical: %q", path, content)
		}
		if len(content) == 0 || content[len(content)-1] == '\n' {
			t.Fatalf("%s has a trailing newline", path)
		}
	}
}

func TestProductionKeyConfigRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("process is root")
	}
	if _, err := ProductionKeyConfig(uint32(os.Getegid())); !errors.Is(err, ErrKeyPolicy) {
		t.Fatalf("ProductionKeyConfig error = %v", err)
	}
}

func testKeyConfig(t *testing.T) KeyConfig {
	t.Helper()
	root := t.TempDir()
	privateDirectory := filepath.Join(root, "state")
	publicDirectory := filepath.Join(root, "etc")
	for _, directory := range []string{privateDirectory, publicDirectory} {
		if err := os.Mkdir(directory, stateDirMode); err != nil {
			t.Fatal(err)
		}
	}
	return KeyConfig{
		PrivatePath: filepath.Join(privateDirectory, "receipt-key.json"),
		PublicPath:  filepath.Join(publicDirectory, "helper-receipt-public.json"),
		OwnerUID:    uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), AgentGID: uint32(os.Getegid()),
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want || !info.Mode().IsRegular() {
		t.Fatalf("%s mode = %v, want %v regular", path, info.Mode(), want)
	}
}

func writeTestProtectedFile(t *testing.T, path string, mode os.FileMode, content []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
