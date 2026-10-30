package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookruntime"
)

const pluginWebhookAttestationKeyUsage = "usage: control-api plugin-webhook-attestation-key status | rotate"

// runPluginWebhookAttestationKey reports or rotates the plugin webhook
// publication attestation key (docs/runbooks/plugin-webhook-key.md). It reads
// the same PLUGIN_WEBHOOK_ATTESTATION_* variables and DATABASE_URL as the
// running process: rotate needs the staged NEXT key, which the runtime must
// already hold, so the head advance does not interrupt publication.
func runPluginWebhookAttestationKey(args []string, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "status" && args[0] != "rotate") {
		return errors.New(pluginWebhookAttestationKeyUsage)
	}
	keys, err := config.LoadPluginWebhookAttestationKeys()
	if err != nil {
		return err
	}
	defer keys.Clear()
	current := pluginwebhookruntime.AttestationKeyPair{ID: keys.CurrentID, Key: keys.Current}
	next := pluginwebhookruntime.AttestationKeyPair{ID: keys.NextID, Key: keys.Next}
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
	if args[0] == "status" {
		status, err := pluginwebhookruntime.ReadAttestationHead(ctx, pool, current, next)
		if err != nil {
			return err
		}
		if !status.Installed {
			_, err = fmt.Fprintln(stdout, "plugin webhook attestation head: not installed (the runtime installs generation 1 on its first publication)")
			return err
		}
		matches := status.Matches
		if matches == "" {
			matches = "none (configured keys do not match; the runtime cannot publish)"
		}
		_, err = fmt.Fprintf(stdout, "plugin webhook attestation head: generation=%d key_id=%s expires_at=%s matches=%s next_staged=%t\n",
			status.Generation, status.KeyID, status.ExpiresAt.UTC().Format(time.RFC3339), matches, next.Key != nil)
		return err
	}
	rotation, err := pluginwebhookruntime.RotateAttestationKey(ctx, pool, current, next,
		"cli:plugin-webhook-attestation-key")
	if err != nil {
		return err
	}
	if rotation.AlreadyRotated {
		_, err = fmt.Fprintf(stdout, "plugin webhook attestation key already rotated: generation=%d key_id=%s\n",
			rotation.ToGeneration, rotation.ToKeyID)
		return err
	}
	_, err = fmt.Fprintf(stdout, "plugin webhook attestation key rotated: generation %d (%s) -> %d (%s), expires_at=%s\n",
		rotation.FromGeneration, rotation.FromKeyID, rotation.ToGeneration, rotation.ToKeyID,
		rotation.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}
