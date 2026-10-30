package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cdncaCE: rule packs, themes and plugins bought on the plugin market reach
// the community edition through the official service's per-installation
// artifact catalog (the same channel the commercial edition uses; the
// license service lists a paid entry only for what this installation
// bought). The catalog is verified with the official service's public
// signing keyset: COMMUNITY_TRUSTED_KEYS_FILE pins it (the installer
// fetches /public/v1/signing-keyset), and keyset rotations are checked
// against those pins like the commercial keyset manager does.
const communityTrustedKeysFileEnv = "COMMUNITY_TRUSTED_KEYS_FILE"

// newCommunityArtifactSyncer returns nil when the installation has not
// registered with the official service yet (community-register) or no
// trusted keys file is configured: there is nothing it could have bought.
func newCommunityArtifactSyncer(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	nodeArtifactSets *artifactsetdist.Distributor) (*artifactsync.Syncer, error) {
	if !configuredRuntimePool(pool) {
		return nil, nil
	}
	keysFile := strings.TrimSpace(os.Getenv(communityTrustedKeysFileEnv))
	if keysFile == "" {
		return nil, nil
	}
	if identity, err := loadCommunityIdentity(); err != nil || identity == nil {
		return nil, err
	}
	service := strings.TrimSpace(os.Getenv(communityServiceURLEnv))
	if service == "" {
		service = communityDefaultService
	}
	trust, err := loadEntitlementTrust(keysFile)
	if err != nil {
		return nil, fmt.Errorf("community trusted keys: %w", err)
	}
	if trust == nil {
		return nil, errors.New("community trusted keys file is empty")
	}
	keysetClient, err := entitlementsync.NewClient(service, nil)
	if err != nil {
		return nil, err
	}
	keysets, err := entitlementsync.NewKeysetManager(ctx, keysetClient, entitlementsync.NewPostgresKeysetStore(pool), trust, time.Now)
	if err != nil {
		return nil, fmt.Errorf("community signing keyset: %w", err)
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	privateKey, err := entitlementsync.LoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(privateKey)
	var encryptionKey []byte
	if cfg.ControlInstallationEncKeyFile != "" {
		// An installation older than the key has no file yet: everything but
		// encrypted packs syncs; community-register-encryption-key adds it.
		if _, statErr := os.Stat(cfg.ControlInstallationEncKeyFile); errors.Is(statErr, os.ErrNotExist) {
			slog.Warn("installation encryption key file is missing; encrypted market packs wait for "+
				"control-api community-register-encryption-key", "path", cfg.ControlInstallationEncKeyFile)
		} else if encryptionKey, err = entitlementsync.LoadEncryptionKey(cfg.ControlInstallationEncKeyFile); err != nil {
			return nil, err
		}
		defer clear(encryptionKey)
	}
	client, err := artifactsync.NewClient(service, nil)
	if err != nil {
		return nil, err
	}
	store := artifactsync.NewStore(pool, time.Now).WithFeatures(entitlementguard.NewGuard(pool, time.Now, nil)).
		WithCRSRepublisher(edgeautopublish.RuleCatalogPublisher{})
	return artifactsync.NewSyncer(artifactsync.SyncerConfig{
		Client: client, Store: store, Trust: trust, Keysets: keysets,
		InstallationID: installationID, PrivateKey: privateKey, EncryptionKey: encryptionKey, ControlVersion: cfg.ControlVersion,
		Interval: cfg.PlatformPolicySyncInterval, Logger: slog.Default().With("component", "community_artifact_sync"),
		OnChanged: func(context.Context) {
			if nodeArtifactSets != nil {
				nodeArtifactSets.Wake()
			}
			wakePluginProviderContracts()
		},
	})
}
