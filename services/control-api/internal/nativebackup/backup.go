package nativebackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

const ToolVersion = "1"

// FactsReader returns the running installation's identity; production reads
// control.env and the release manifest, tests return fixed values.
type FactsReader func(context.Context, *Host) (ControlFacts, error)

type BackupRequest struct {
	Reason string
	// Hold keeps the writers stopped and disabled after the backup (migration
	// source). Otherwise they are restarted.
	Hold bool
	// ExtraRecipients receive the bundle in addition to the local identity,
	// e.g. the one-time identity of a migration target.
	ExtraRecipients []string
	OutputDirectory string
}

type BackupResult struct {
	BackupID  string
	Directory string
	Manifest  Manifest
	Signed    SignedManifest
}

type Backuper struct {
	Host       *Host
	Freezer    Freezer
	Keys       KeyRing
	Facts      FactsReader
	Components []Component
	Now        func() time.Time
	// Progress receives one line per step; it never carries secrets.
	Progress func(string)
}

func (backuper Backuper) progress(format string, values ...any) {
	if backuper.Progress != nil {
		backuper.Progress(fmt.Sprintf(format, values...))
	}
}

func (backuper Backuper) Run(ctx context.Context, request BackupRequest) (result BackupResult, err error) {
	switch request.Reason {
	case "manual", "scheduled", "migration", "pre-restore":
	default:
		return BackupResult{}, errors.New("invalid backup reason")
	}
	if len(backuper.Components) != len(ComponentOrder) {
		return BackupResult{}, errors.New("backup component set is incomplete")
	}
	unlock, err := LockRelease(backuper.Host.Layout)
	if err != nil {
		return BackupResult{}, err
	}
	defer unlock()
	backupID := NewBackupID(backuper.Now())
	recipients := append([]string{backuper.Keys.Recipient()}, request.ExtraRecipients...)
	writer, err := NewBundleWriter(request.OutputDirectory, backupID, recipients, backuper.Now)
	if err != nil {
		return BackupResult{}, err
	}
	defer func() {
		if err != nil {
			writer.Abort()
		}
	}()
	mode := FreezeBackup
	if request.Hold {
		mode = FreezeHold
	}
	previous, err := backuper.Freezer.Current()
	if err != nil {
		return BackupResult{}, err
	}
	alreadyHeld := previous != nil && previous.Mode == FreezeHold
	backuper.progress("freeze: stopping control-api, agent-gateway and the upgrade runner")
	lease, err := backuper.Freezer.Acquire(ctx, mode, backupID)
	if err != nil {
		return BackupResult{}, err
	}
	frozen := lease.Record()
	defer func() {
		var releaseErr error
		switch {
		case !request.Hold:
			// Under an existing hold this lease is a no-op.
			releaseErr = lease.Release(context.WithoutCancel(ctx))
		case err != nil && !alreadyHeld:
			// A failed migration backup must leave the source serving.
			releaseErr = backuper.Freezer.Unfreeze(context.WithoutCancel(ctx))
		}
		if releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("release freeze: %w", releaseErr))
		}
	}()
	facts, err := backuper.Facts(ctx, backuper.Host)
	if err != nil {
		return BackupResult{}, fmt.Errorf("read installation facts: %w", err)
	}
	scratch, err := os.MkdirTemp(request.OutputDirectory, ".scratch-")
	if err != nil {
		return BackupResult{}, err
	}
	defer os.RemoveAll(scratch)
	backuper.Host.Scratch = scratch
	for index, component := range backuper.Components {
		if component.Name() != ComponentOrder[index] {
			return BackupResult{}, errors.New("backup component order is invalid")
		}
		backuper.progress("capture: %s", component.Name())
		err := writer.Add(component.Name(), func(output io.Writer) (map[string]string, error) {
			return component.Capture(ctx, backuper.Host, output)
		})
		if err != nil {
			return BackupResult{}, fmt.Errorf("capture %s: %w", component.Name(), err)
		}
	}
	if postgres, found := findDetail(writer.records, ComponentPostgreSQL, "schema_version"); found {
		if value, parseErr := strconv.ParseUint(postgres, 10, 64); parseErr == nil {
			facts.SchemaVersion = value
		}
	}
	manifest := Manifest{Schema: ManifestSchema, BackupID: backupID, Reason: request.Reason,
		CreatedAt: backuper.Now().UTC(), FreezeMode: mode, FrozenAt: frozen.AcquiredAt, Control: facts,
		ToolVersion: ToolVersion}
	signed, directory, err := writer.Publish(manifest, backuper.Keys)
	if err != nil {
		return BackupResult{}, err
	}
	verified, err := VerifyManifest(signed, backuper.Keys.Fingerprint())
	if err != nil {
		return BackupResult{}, err
	}
	backuper.progress("published %s", directory)
	return BackupResult{BackupID: backupID, Directory: directory, Manifest: verified, Signed: signed}, nil
}

func findDetail(records []ComponentRecord, name ComponentName, key string) (string, bool) {
	for _, record := range records {
		if record.Name == name {
			value, found := record.Detail[key]
			return value, found
		}
	}
	return "", false
}
