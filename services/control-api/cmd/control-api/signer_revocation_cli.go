package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgesignertrustsync"
	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocation"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocationconsumer"
	"github.com/google/uuid"
)

const signerRevocationUsage = "usage: control-api signer-revocation import-checkpoint --in FILE | " +
	"import-edge-trust --in FILE"

// runSignerRevocation imports offline-root signed files on a control plane
// that cannot reach the authorization center (docs/runbooks/
// signer-revocation-offline-root.md). Both commands verify against the same
// SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_* pin the running process uses and
// write through the same stores; the running process picks the result up on
// its next refresh.
func runSignerRevocation(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(signerRevocationUsage)
	}
	flags := flag.NewFlagSet("signer-revocation "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	in := flags.String("in", "", "offline-root signed file")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(*in) == "" {
		return errors.New(signerRevocationUsage)
	}
	if args[0] != "import-checkpoint" && args[0] != "import-edge-trust" {
		return errors.New(signerRevocationUsage)
	}
	root, configured, err := signerrevocationconsumer.LoadOfflineRoot()
	if err != nil {
		return err
	}
	if !configured {
		return errors.New("SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_* is not configured")
	}
	encoded, err := readSignedRevocationFile(*in)
	if err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if args[0] == "import-edge-trust" {
		store, err := edgesignertrustsync.NewStore(pool, []edgesignertrust.RootPin{{KeyID: root.KeyID,
			Generation: root.Generation, PublicKey: root.PublicKey}}, time.Now)
		if err != nil {
			return err
		}
		accepted, err := store.Accept(ctx, encoded, edgesignertrustsync.SourceImport)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "edge signer trust imported: revision=%d replayed=%t\n", accepted.Revision, accepted.Replayed)
		return err
	}
	trustStore, err := loadEntitlementTrust(os.Getenv("ENTITLEMENT_TRUSTED_KEYS_FILE"))
	if err != nil {
		return err
	}
	if trustStore == nil {
		return errors.New("ENTITLEMENT_TRUSTED_KEYS_FILE is required")
	}
	trust, err := signerrevocationconsumer.NewDeploymentTrust(trustStore, root.TrustConfig())
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	etag := `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
	now := time.Now()
	accepted, err := signerrevocation.NewCheckpointStore(pool, trust, time.Now).AcceptV2(ctx, uuid.New(), encoded, etag, now)
	if err != nil {
		if errors.Is(err, signercheckpoint.ErrCheckpointNotCurrent) || errors.Is(err, signercheckpoint.ErrTTLExceeded) {
			return fmt.Errorf("checkpoint is expired or not yet valid; re-sign it: %w", err)
		}
		return err
	}
	_, err = fmt.Fprintf(stdout, "signer revocation checkpoint imported: revision=%d head_sequence=%d\n",
		accepted.Checkpoint.Revision, accepted.Checkpoint.HeadSequence)
	return err
}

func readSignedRevocationFile(path string) ([]byte, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("--in must be a regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, signercheckpoint.MaxCheckpointBytes+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > signercheckpoint.MaxCheckpointBytes {
		return nil, errors.New("--in is empty or too large")
	}
	return encoded, nil
}
