package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
)

// runInstallCommunity records the control installation of a cdncaCE
// community edition: the installation row other subsystems key on (node CA
// epochs, node identity, telemetry), without a signed lease (last_status
// stays uninstalled; the schema is shared with the commercial edition). The community
// entitlement is built into entitlementguard; there is no license service.
func runInstallCommunity(args []string) error {
	flags := flag.NewFlagSet("install-community", flag.ContinueOnError)
	installationID := flags.String("installation-id", "", "canonical control installation UUID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	parsed, err := uuid.Parse(strings.TrimSpace(*installationID))
	if flags.NArg() != 0 || err != nil || parsed.String() != *installationID {
		return errors.New("usage: control-api install-community --installation-id UUID")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	var stored string
	if err := pool.QueryRow(ctx, `
		INSERT INTO control_installation_entitlement (singleton, installation_id)
		VALUES (true, $1)
		ON CONFLICT (singleton) DO UPDATE SET singleton = EXCLUDED.singleton
		RETURNING installation_id`, *installationID).Scan(&stored); err != nil {
		return fmt.Errorf("record community installation: %w", err)
	}
	if stored != *installationID {
		return fmt.Errorf("control installation is already %s", stored)
	}
	fmt.Printf("community installation recorded: installation_id=%s\n", stored)
	return nil
}
