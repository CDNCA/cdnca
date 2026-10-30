package nativebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// memoryComponent captures a fixed payload and restores it into a map, so
// orchestration (order, freeze, signing, encryption, compensation) is tested
// without external programs.
type memoryComponent struct {
	name       ComponentName
	payload    string
	restored   *map[ComponentName]string
	journal    *[]string
	failOn     string // "capture", "preflight", "restore", "compensate"
	frozenSeen *bool
	freezer    *Freezer
	detail     map[string]string // extra manifest detail (e.g. archived paths)
}

func (component memoryComponent) Name() ComponentName { return component.name }
func (component memoryComponent) Capture(_ context.Context, _ *Host, output io.Writer) (map[string]string, error) {
	if component.frozenSeen != nil {
		current, _ := component.freezer.Current()
		*component.frozenSeen = current != nil
	}
	if component.failOn == "capture" {
		return nil, errors.New("capture failed")
	}
	_, err := io.WriteString(output, component.payload)
	detail := map[string]string{"len": fmt.Sprint(len(component.payload))}
	for key, value := range component.detail {
		detail[key] = value
	}
	return detail, err
}
func (component memoryComponent) Preflight(context.Context, *Host, ComponentRecord, Manifest) error {
	*component.journal = append(*component.journal, "preflight "+string(component.name))
	if component.failOn == "preflight" {
		return errors.New("restore_target_not_empty")
	}
	return nil
}
func (component memoryComponent) Restore(_ context.Context, _ *Host, record ComponentRecord, input io.Reader) error {
	*component.journal = append(*component.journal, "restore "+string(component.name))
	data, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	if record.Detail["len"] != fmt.Sprint(len(data)) {
		return errors.New("detail mismatch")
	}
	if component.failOn == "restore" {
		return errors.New("restore failed")
	}
	(*component.restored)[component.name] = string(data)
	return nil
}
func (component memoryComponent) Compensate(context.Context, *Host, ComponentRecord) error {
	*component.journal = append(*component.journal, "compensate "+string(component.name))
	delete(*component.restored, component.name)
	if component.failOn == "compensate" {
		return errors.New("compensate failed")
	}
	return nil
}

type fakeExecutor struct{ calls []string }

func (fake *fakeExecutor) Run(_ context.Context, command Command) error {
	fake.calls = append(fake.calls, command.Path+" "+strings.Join(command.Args, " "))
	return nil
}

type testRig struct {
	t        *testing.T
	root     string
	host     *Host
	systemd  *fakeSystemd
	freezer  Freezer
	keys     KeyRing
	restored map[ComponentName]string
	journal  []string
	frozen   bool
	clock    time.Time
	details  map[ComponentName]map[string]string
}

func newRig(t *testing.T) *testRig {
	rig := &testRig{t: t, root: t.TempDir(), systemd: newFakeSystemd(t), restored: map[ComponentName]string{},
		clock: time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)}
	rig.host = &Host{Layout: Layout{Root: rig.root}, Exec: &fakeExecutor{}, Systemd: rig.systemd}
	// A Debian-family target unless a test says otherwise (restore picks the CA tool by family).
	writeFile(t, rig.host.Layout.Path("/usr/sbin/update-ca-certificates"))
	rig.freezer = Freezer{Layout: rig.host.Layout, Systemd: rig.systemd, Now: rig.now}
	keys, err := LoadOrCreateKeys(rig.host.Layout)
	if err != nil {
		t.Fatal(err)
	}
	rig.keys = keys
	return rig
}

func (rig *testRig) now() time.Time { rig.clock = rig.clock.Add(time.Second); return rig.clock }

func (rig *testRig) components(failOn map[ComponentName]string) []Component {
	var components []Component
	for _, name := range ComponentOrder {
		components = append(components, memoryComponent{name: name, payload: "payload-of-" + string(name) + strings.Repeat("x", 100),
			restored: &rig.restored, journal: &rig.journal, failOn: failOn[name], frozenSeen: &rig.frozen, freezer: &rig.freezer,
			detail: rig.details[name]})
	}
	return components
}

func (rig *testRig) backuper(failOn map[ComponentName]string) Backuper {
	return Backuper{Host: rig.host, Freezer: rig.freezer, Keys: rig.keys, Components: rig.components(failOn), Now: rig.now,
		Facts: func(context.Context, *Host) (ControlFacts, error) {
			return ControlFacts{InstallationID: "11111111-1111-4111-8111-111111111111", Version: "1.0.35", SchemaVersion: 299}, nil
		}}
}

func TestBackupSignsEncryptsAndRestartsWriters(t *testing.T) {
	rig := newRig(t)
	output := filepath.Join(rig.root, "out")
	result, err := rig.backuper(nil).Run(context.Background(), BackupRequest{Reason: "manual", OutputDirectory: output})
	if err != nil {
		t.Fatal(err)
	}
	if !rig.frozen {
		t.Fatal("components must be captured while the writers are frozen")
	}
	for _, unit := range WriterUnits {
		if !rig.systemd.states[unit].Active {
			t.Fatalf("%s must run again after a backup", unit)
		}
	}
	bundle, err := OpenBundle(result.Directory, rig.keys.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyAll(rig.keys.Identity); err != nil {
		t.Fatal(err)
	}
	// The plaintext payload must not appear in any artifact.
	entries, _ := os.ReadDir(result.Directory)
	for _, entry := range entries {
		data, _ := os.ReadFile(filepath.Join(result.Directory, entry.Name()))
		if bytes.Contains(data, []byte("payload-of-")) {
			t.Fatalf("%s contains plaintext", entry.Name())
		}
	}
	if info, _ := os.Stat(result.Directory); info.Mode().Perm() != 0o700 {
		t.Fatalf("bundle mode = %v", info.Mode())
	}
	list, err := ListBundles(output, rig.keys.Fingerprint())
	if err != nil || len(list) != 1 || !list[0].SignatureOK || list[0].SchemaVersion != 299 {
		t.Fatalf("list = %+v %v", list, err)
	}
}

func TestBackupCaptureFailureReleasesFreezeAndLeavesNoBundle(t *testing.T) {
	rig := newRig(t)
	output := filepath.Join(rig.root, "out")
	_, err := rig.backuper(map[ComponentName]string{ComponentClickHouse: "capture"}).Run(context.Background(),
		BackupRequest{Reason: "manual", OutputDirectory: output})
	if err == nil {
		t.Fatal("capture failure must fail the backup")
	}
	for _, unit := range WriterUnits {
		if !rig.systemd.states[unit].Active {
			t.Fatalf("%s must be restarted after a failed backup", unit)
		}
	}
	entries, _ := os.ReadDir(output)
	if len(entries) != 0 {
		t.Fatalf("no partial bundle may remain: %v", entries)
	}
}

func TestMigrationHoldKeepsSourceFrozenAndUnfreezeRestores(t *testing.T) {
	rig := newRig(t)
	output := filepath.Join(rig.root, "out")
	if _, err := rig.backuper(nil).Run(context.Background(), BackupRequest{Reason: "migration", Hold: true, OutputDirectory: output}); err != nil {
		t.Fatal(err)
	}
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; state.Active || state.Enabled {
			t.Fatalf("%s must stay stopped and disabled after a migration backup", unit)
		}
	}
	if err := rig.freezer.Unfreeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; !state.Active || !state.Enabled {
			t.Fatalf("%s must be restored by unfreeze", unit)
		}
	}
}

func TestMigrationHoldFailureLeavesSourceServing(t *testing.T) {
	rig := newRig(t)
	_, err := rig.backuper(map[ComponentName]string{ComponentJetStream: "capture"}).Run(context.Background(),
		BackupRequest{Reason: "migration", Hold: true, OutputDirectory: filepath.Join(rig.root, "out")})
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; !state.Active || !state.Enabled {
			t.Fatalf("%s must serve again: %+v", unit, state)
		}
	}
}

func TestExtraRecipientCanDecryptAndTamperingIsDetected(t *testing.T) {
	rig := newRig(t)
	target, err := NewEphemeralIdentity(filepath.Join(rig.root, "target", "identity"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := rig.backuper(nil).Run(context.Background(), BackupRequest{Reason: "migration",
		ExtraRecipients: []string{target.Recipient().String()}, OutputDirectory: filepath.Join(rig.root, "out")})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := OpenBundle(result.Directory, rig.keys.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.VerifyAll(target); err != nil {
		t.Fatalf("target identity must decrypt: %v", err)
	}
	if _, err := OpenBundle(result.Directory, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("a different pinned signer must be rejected: %v", err)
	}
	artifact := filepath.Join(result.Directory, "postgresql.tar.age")
	data, _ := os.ReadFile(artifact)
	data[len(data)-1] ^= 1
	_ = os.WriteFile(artifact, data, 0o600)
	if err := bundle.VerifyCiphertext(); err == nil {
		t.Fatal("a modified artifact must be detected")
	}
	signed, _ := ReadSignedManifest(result.Directory)
	signed.Payload = bytes.Replace(signed.Payload, []byte("1.0.35"), []byte("1.0.36"), 1)
	if _, err := VerifyManifest(signed, rig.keys.Fingerprint()); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("an edited manifest must fail its signature: %v", err)
	}
}

func (rig *testRig) restorer(failOn map[ComponentName]string) Restorer {
	return Restorer{Host: rig.host, Components: rig.components(failOn), Now: rig.now}
}

func (rig *testRig) backupBundle() Bundle {
	result, err := rig.backuper(nil).Run(context.Background(), BackupRequest{Reason: "manual", OutputDirectory: filepath.Join(rig.root, "out")})
	if err != nil {
		rig.t.Fatal(err)
	}
	bundle, err := OpenBundle(result.Directory, rig.keys.Fingerprint())
	if err != nil {
		rig.t.Fatal(err)
	}
	rig.journal = nil
	return bundle
}

func TestRestorePreflightsEverythingBeforeMutating(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	_, err := rig.restorer(map[ComponentName]string{ComponentObjectStore: "preflight"}).Run(context.Background(),
		RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity})
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	for _, entry := range rig.journal {
		if strings.HasPrefix(entry, "restore ") {
			t.Fatalf("no component may be restored before all preflights pass: %v", rig.journal)
		}
	}
	if len(rig.restored) != 0 {
		t.Fatal("nothing must be restored")
	}
}

func TestRestoreFailureCompensatesInReverseOrder(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	_, err := rig.restorer(map[ComponentName]string{ComponentJetStream: "restore"}).Run(context.Background(),
		RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity})
	if err == nil {
		t.Fatal("expected restore failure")
	}
	var compensated []string
	for _, entry := range rig.journal {
		if name, found := strings.CutPrefix(entry, "compensate "); found {
			compensated = append(compensated, name)
		}
	}
	want := []string{"jetstream", "clickhouse", "postgresql", "runtime", "config"}
	if !reflect.DeepEqual(compensated, want) {
		t.Fatalf("compensation order = %v", compensated)
	}
	if len(rig.restored) != 0 {
		t.Fatalf("target must be empty again: %v", rig.restored)
	}
	if _, err := os.Stat(Restorer{Host: rig.host}.intentPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a fully compensated restore leaves no intent")
	}
}

func TestRestoreCompensationFailureKeepsIntentAndBlocksRetry(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	failures := map[ComponentName]string{ComponentJetStream: "restore", ComponentPostgreSQL: "compensate"}
	if _, err := rig.restorer(failures).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); !errors.Is(err, ErrRestoreUncertain) {
		t.Fatalf("an unfinished restore must block a plain retry: %v", err)
	}
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity, Compensate: true}); err != nil {
		t.Fatalf("compensate + retry must succeed: %v", err)
	}
	if len(rig.restored) != len(ComponentOrder) {
		t.Fatalf("restored = %v", rig.restored)
	}
}

func TestRestoreSuccessStartsRestoredUnits(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	for _, unit := range []string{"cdnca-control-api.service", "cdnca-agent-gateway.service"} {
		path := rig.host.Layout.Path("/etc/systemd/system/" + unit)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte("[Unit]\n"), 0o644)
	}
	rig.systemd.calls = nil
	result, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"daemon-reload", "enable cdnca-control-api.service", "start cdnca-control-api.service",
		"enable cdnca-agent-gateway.service", "start cdnca-agent-gateway.service"}
	if !reflect.DeepEqual(rig.systemd.calls, want) {
		t.Fatalf("calls = %v", rig.systemd.calls)
	}
	if result.Version != "1.0.35" {
		t.Fatalf("result = %+v", result)
	}
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err == nil {
		t.Fatal("a second restore onto a restored host must be refused")
	}
}

func TestRecoveryKitRoundTrip(t *testing.T) {
	rig := newRig(t)
	kit, err := ExportRecoveryKit(rig.keys, "id", "correct horse battery", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportRecoveryKit(rig.keys, "id", "short", time.Now()); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatal("short passphrases must be refused")
	}
	encoded, _ := jsonMarshal(kit)
	if bytes.Contains(encoded, []byte(rig.keys.Identity.String())) {
		t.Fatal("the kit must not contain the identity in clear")
	}
	identity, opened, err := OpenRecoveryKit(encoded, "correct horse battery")
	if err != nil || identity.String() != rig.keys.Identity.String() || opened.SignerFinger != rig.keys.Fingerprint() {
		t.Fatalf("open = %v", err)
	}
	if _, _, err := OpenRecoveryKit(encoded, "wrong horse battery"); err == nil {
		t.Fatal("a wrong passphrase must fail")
	}
}

func TestRedactKeepsPublicIdentifiers(t *testing.T) {
	line := "copy: 20261017T030000Z-abcdefgh signer SHA256:" + strings.Repeat("A", 43)
	if got := Redact(line); got != line {
		t.Fatalf("public identifiers must survive: %s", got)
	}
}

func TestRedactRemovesSecrets(t *testing.T) {
	got := Redact("FATAL: password=hunter2 for user cdnca token: abcdefghijklmnopqrstuvwxyz0123\n-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----")
	for _, secret := range []string{"hunter2", "abcdefghijklmnopqrstuvwxyz0123", "AAA"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output still contains %q: %s", secret, got)
		}
	}
}

func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }
