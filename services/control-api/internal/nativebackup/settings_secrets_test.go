package nativebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	testAccessKey  = "AKIA-settings-access-7f3c"
	testSecretKey  = "s3-secret-value-9d21e0aa"
	testSFTPSecret = "sftp-password-41bb02c7"
)

func secretSettings() Settings {
	settings := DefaultSettings()
	settings.Targets = []Target{
		{Name: "offsite", Kind: "s3", Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "cdnca-backup",
			Prefix: "control/", AccessKey: testAccessKey, SecretKey: testSecretKey},
		{Name: "vault", Kind: "sftp", Host: "backup.example.com", Port: 22, Username: "backup", RemoteDir: "/srv/backup",
			HostKeySHA256: "SHA256:" + strings.Repeat("B", 43), Password: testSFTPSecret},
	}
	return settings
}

func assertNoPlainSecrets(t *testing.T, label string, data []byte) {
	t.Helper()
	for _, secret := range []string{testAccessKey, testSecretKey, testSFTPSecret} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("%s contains a target secret in plain text", label)
		}
	}
}

// writeLegacySettings writes settings the way SaveSettings did before the
// credentials were sealed: plain JSON, 0600.
func writeLegacySettings(t *testing.T, layout Layout, settings Settings) {
	t.Helper()
	path := layout.Path(SettingsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readSettingsFile(t *testing.T, layout Layout) ([]byte, os.FileMode) {
	t.Helper()
	path := layout.Path(SettingsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return data, info.Mode().Perm()
}

func TestSaveSettingsSealsTargetSecrets(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	want := secretSettings()
	if err := SaveSettings(layout, want); err != nil {
		t.Fatal(err)
	}
	data, mode := readSettingsFile(t, layout)
	if mode != 0o600 {
		t.Fatalf("settings mode = %o, want 600", mode)
	}
	assertNoPlainSecrets(t, "settings.json", data)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if sealed, _ := raw["sealed_secrets"].(string); sealed == "" {
		t.Fatal("settings.json must carry the sealed target secrets")
	}
	if want.Targets[0].SecretKey != testSecretKey {
		t.Fatal("SaveSettings must not clear the caller's secrets")
	}
	got, err := LoadSettings(layout)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip differs:\n got %+v\nwant %+v", got.Targets, want.Targets)
	}
	// No temporary file is left next to the settings.
	entries, _ := os.ReadDir(filepath.Dir(layout.Path(SettingsFile)))
	if len(entries) != 1 {
		t.Fatalf("backup settings directory holds %d entries, want only settings.json", len(entries))
	}
}

func TestSaveSettingsWithoutSecretsNeedsNoIdentity(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	if err := SaveSettings(layout, DefaultSettings()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(layout.Path(BackupKeyDirectory)); !os.IsNotExist(err) {
		t.Fatalf("saving settings without targets must not create the backup identity: %v", err)
	}
}

func TestLegacyPlaintextSettingsStayReadableAndAreSealedOnce(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	want := secretSettings()
	writeLegacySettings(t, layout, want)
	got, err := LoadSettings(layout)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy settings read differs: %+v", got.Targets)
	}
	sealed, err := SealLegacySettings(layout)
	if err != nil || !sealed {
		t.Fatalf("SealLegacySettings = %v, %v; want true, nil", sealed, err)
	}
	data, mode := readSettingsFile(t, layout)
	if mode != 0o600 {
		t.Fatalf("settings mode = %o, want 600", mode)
	}
	assertNoPlainSecrets(t, "migrated settings.json", data)
	if again, err := SealLegacySettings(layout); err != nil || again {
		t.Fatalf("second SealLegacySettings = %v, %v; want false, nil", again, err)
	}
	if after, _ := readSettingsFile(t, layout); !bytes.Equal(after, data) {
		t.Fatal("an already sealed file must not be rewritten")
	}
	got, err = LoadSettings(layout)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated settings read differs: %+v", got.Targets)
	}
}

func TestSealLegacySettingsWithoutFileIsNoop(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	if sealed, err := SealLegacySettings(layout); err != nil || sealed {
		t.Fatalf("SealLegacySettings = %v, %v", sealed, err)
	}
	if _, err := os.Stat(layout.Path(SettingsFile)); !os.IsNotExist(err) {
		t.Fatal("no settings file may be created")
	}
}

func TestAgentTickSealsLegacySettings(t *testing.T) {
	rig := newRig(t)
	settings := secretSettings()
	for index := range settings.Targets {
		settings.Targets[index].Enabled = false
	}
	writeLegacySettings(t, rig.host.Layout, settings)
	if err := rig.agent(nil).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := readSettingsFile(t, rig.host.Layout)
	assertNoPlainSecrets(t, "settings.json after an agent tick", data)
	got, err := LoadSettings(rig.host.Layout)
	if err != nil || !reflect.DeepEqual(got, settings) {
		t.Fatalf("settings after tick = %+v, %v", got.Targets, err)
	}
}

// A restore (same host or a new one) brings back the whole configuration
// tree: the sealed settings and the backup identity they are sealed to.
func TestSealedSettingsReadableAfterConfigRestoreOnNewHost(t *testing.T) {
	source := Layout{Root: t.TempDir()}
	want := secretSettings()
	if err := SaveSettings(source, want); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if _, err := ArchiveTree(source, configPaths, &archive); err != nil {
		t.Fatal(err)
	}
	target := Layout{Root: t.TempDir()}
	owners := &recordingOwners{chowned: map[string][2]int{}}
	if _, err := ExtractTree(target, configPaths, owners, &archive); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings(target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restored settings differ: %+v", got.Targets)
	}
}

func TestSealedSettingsWithoutMatchingIdentityFailClosedWithoutLeaking(t *testing.T) {
	source := Layout{Root: t.TempDir()}
	if err := SaveSettings(source, secretSettings()); err != nil {
		t.Fatal(err)
	}
	data, _ := readSettingsFile(t, source)

	// Only settings.json copied, no identity.
	bare := Layout{Root: t.TempDir()}
	path := bare.Path(SettingsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSettings(bare)
	if err == nil || !strings.Contains(err.Error(), BackupKeyDirectory) {
		t.Fatalf("missing identity must be named in the error: %v", err)
	}
	assertNoPlainSecrets(t, "missing identity error", []byte(err.Error()))
	if _, statErr := os.Stat(bare.Path(BackupKeyDirectory)); !os.IsNotExist(statErr) {
		t.Fatal("reading settings must not create a new backup identity")
	}

	// A different identity cannot open them either.
	if _, err := LoadOrCreateKeys(bare); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSettings(bare)
	if err == nil || !strings.Contains(err.Error(), BackupKeyDirectory) {
		t.Fatalf("a foreign identity must be refused with a hint: %v", err)
	}
	assertNoPlainSecrets(t, "foreign identity error", []byte(err.Error()))
	if sealed, err := SealLegacySettings(bare); err == nil || sealed {
		t.Fatalf("SealLegacySettings on unreadable settings = %v, %v", sealed, err)
	}
}
