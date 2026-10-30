package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

var controlVersion = "development"

func openControlPlaneUpgradeHTTPRuntime(cfg config.Config, identityService *identity.Service,
	trust *entitlementguard.TrustStore) (*controlplaneupgradehttp.Handler, error) {
	return openControlPlaneUpgradeHTTPRuntimeWithDatabase(cfg, identityService, trust, nil)
}

func openControlPlaneUpgradeHTTPRuntimeWithDatabase(cfg config.Config, identityService *identity.Service,
	trust *entitlementguard.TrustStore, database controlUpgradePlanRuntimeDatabase) (*controlplaneupgradehttp.Handler, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_PLAN_WRITER_ENABLED")), "true") {
		return nil, nil
	}
	if identityService == nil || trust == nil {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	if cfg.ControlVersion != controlVersion {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	digest := strings.TrimPrefix(strings.TrimSpace(os.Getenv("CONTROL_ARTIFACT_SHA256")), "sha256:")
	replicas, err := positiveEnvironmentInt("CONTROL_UPGRADE_EXPECTED_REPLICAS")
	if err != nil {
		return nil, err
	}
	quorum, err := positiveEnvironmentInt("CONTROL_UPGRADE_QUORUM")
	if err != nil || quorum > replicas {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	protocol, err := positiveEnvironmentInt("CONTROL_UPGRADE_PROTOCOL_VERSION")
	if err != nil {
		return nil, err
	}
	token, err := os.ReadFile(strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE")))
	if err != nil {
		return nil, fmt.Errorf("read control upgrade internal token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) < 32 || len(token) > 256 {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	defer clear(token)
	planSource, err := loadControlUpgradePlanRuntimeConfig(cfg.ControlInstallationID)
	if err != nil {
		return nil, err
	}
	var repository controlplaneupgrade.SecretRepository
	if planSource.Enabled {
		if err := controlplaneupgrade.ValidateSystemdHAConfig(replicas, quorum); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), controlUpgradePlanReadyTimeout)
		defer cancel()
		if err := requireControlUpgradePlanSchema(ctx, database); err != nil {
			return nil, err
		}
		repository, err = controlplaneupgrade.NewPostgresSecretRepository(database, cfg.ControlInstallationID,
			controlplaneupgrade.SystemdControlUpgradeOperation)
	} else {
		repository, err = controlplaneupgrade.NewKubernetesSecretRepository(controlplaneupgrade.KubernetesSecretConfig{
			APIServer:  strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_KUBERNETES_API")),
			Namespace:  strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_KUBERNETES_NAMESPACE")),
			SecretName: strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_PLAN_SECRET")),
			BundleKey:  strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_PLAN_SECRET_KEY")),
			StateKey:   strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_STATE_SECRET_KEY")),
			TokenFile:  strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_KUBERNETES_TOKEN_FILE")),
			CAFile:     strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_KUBERNETES_CA_FILE")),
		})
	}
	if err != nil {
		return nil, err
	}
	publisher, err := controlplaneupgrade.NewPlanPublisher(controlplaneupgrade.PlanPublisherConfig{
		InstallationID: cfg.ControlInstallationID, Component: "control-api", CurrentVersion: cfg.ControlVersion,
		CurrentDigest: digest, ProtocolVersion: protocol, Trust: trust, Now: time.Now,
	}, repository)
	if err != nil {
		return nil, err
	}
	coordinator, err := controlplaneupgrade.NewControlCoordinator(controlplaneupgrade.ControlCoordinatorConfig{
		ReplicaID: strings.TrimSpace(os.Getenv("CONTROL_UPGRADE_REPLICA_ID")), Version: cfg.ControlVersion,
		Digest: digest, ExpectedReplicas: replicas, Quorum: quorum, ObservationTTL: 30 * time.Second, Now: time.Now,
	}, repository)
	if err != nil {
		return nil, err
	}
	authenticate := func(request *http.Request) (identity.AuthenticatedSession, error) {
		authorization := strings.TrimSpace(request.Header.Get("Authorization"))
		scheme, raw, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return identityService.AuthenticateSession(request.Context(), strings.TrimSpace(raw))
	}
	handler, err := controlplaneupgradehttp.New(controlplaneupgradehttp.Dependencies{AuthenticateSession: authenticate,
		Publisher: publisher, Coordinator: coordinator, InternalToken: token, MaxBodyBytes: 1 << 20})
	return handler, err
}

func positiveEnvironmentInt(name string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value < 1 || value > 10_000 {
		return 0, errors.New(name + " must be a positive integer")
	}
	return value, nil
}
