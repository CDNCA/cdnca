package main

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/certificatepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/certnotify"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type certificatePublicationProductionDependencies struct {
	Pool           *pgxpool.Pool
	IAM            *iamlock.Authorizer
	Enveloper      certificateasset.PrivateKeyEnveloper
	OpaqueResolver certificateasset.OpaquePublicationResolver
	Signer         certificatepublish.ArtifactSigner
	TargetResolver certificatepublish.CertificateTargetResolver
}

func buildCertificatePublicationProductionRuntime(
	dependencies certificatePublicationProductionDependencies,
	config certificatePublicationRuntimeConfig,
) (*certificatePublicationRuntime, error) {
	if !config.Enabled {
		return newCertificatePublicationRuntime(nil, nil, config)
	}
	if dependencies.Pool == nil || dependencies.IAM == nil || dependencies.Enveloper == nil ||
		dependencies.OpaqueResolver == nil ||
		dependencies.Signer == nil || dependencies.TargetResolver == nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	materials, err := certificateasset.NewStore(dependencies.Pool, dependencies.Enveloper)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	core, err := edgedeployment.NewIAMStore(dependencies.Pool, dependencies.IAM)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	deployments, err := edgedeployment.NewCertificatePublisherStore(
		core, certificatepublish.NewActorRevalidator(),
	)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	producer, err := certificatepublish.NewProducer(dependencies.Signer)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	publicationConfig := certificatepublish.DefaultPublicationConfig()
	publicationConfig.OpaqueResolver = dependencies.OpaqueResolver
	service, err := certificatepublish.NewPublicationService(
		dependencies.Pool, materials, deployments, producer, publicationConfig,
	)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	publisher, err := certificatepublish.NewPublisherAdapter(service, dependencies.TargetResolver)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	return newCertificatePublicationRuntime(dependencies.Pool, publisher, config)
}

func openCertificatePublicationProductionRuntime(
	dependencies certificatePublicationProductionDependencies,
	config certificatePublicationRuntimeConfig,
) (*certificatePublicationRuntime, error) {
	return buildCertificatePublicationProductionRuntime(dependencies, config)
}

// buildCertificateRenewalDeliverer is the automatic renewal delivery
// (fix-dnscert3 卡 2-B): system rollouts of renewed versions with the same
// envelope, key resolver and artifact signer as certificate publication,
// renewal failures noticed as certificate.renew_failed. It runs on the
// automatic edge publication loop.
// withRenewalDeliveryCanceller lets the store's user binding writes cancel the
// in-flight renewal delivery they supersede (fix-dnscert4), in their own
// transaction, as the system (job:certificate_renewal).
func withRenewalDeliveryCanceller(store *certificateasset.Store, pool *pgxpool.Pool) error {
	rollouts, err := edgedeployment.NewStoreWithClockAndAuditor(pool, time.Now, audit.New(pool))
	if err != nil {
		return err
	}
	store.WithRenewalDeliveryCanceller(func(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID,
		requestID string) error {
		return rollouts.CancelSystemSecretRolloutTx(ctx, tx, scopeID, rolloutID, requestID, "certificate_renewal")
	})
	return nil
}

func buildCertificateRenewalDeliverer(
	dependencies certificatePublicationProductionDependencies,
) (*certificatepublish.RenewalDeliverer, error) {
	if dependencies.Pool == nil || dependencies.Enveloper == nil || dependencies.OpaqueResolver == nil ||
		dependencies.Signer == nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	assets, err := certificateasset.NewStore(dependencies.Pool, dependencies.Enveloper)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	rollouts, err := edgedeployment.NewStoreWithClockAndAuditor(dependencies.Pool, time.Now, audit.New(dependencies.Pool))
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	producer, err := certificatepublish.NewProducer(dependencies.Signer)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	notices, err := notification.NewStore(dependencies.Pool)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	notify := func(ctx context.Context, tx pgx.Tx, scopeID, orderID uuid.UUID, code string) error {
		return certnotify.RenewFailedTx(ctx, tx, notices, scopeID, orderID, code)
	}
	return certificatepublish.NewRenewalDeliverer(dependencies.Pool, assets, rollouts, producer,
		certificatepublish.RenewalTargetNodes, notify, dependencies.OpaqueResolver,
		certificatepublish.DefaultRenewalDelivererConfig(), time.Now)
}
