package certificatepublish

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Automatic renewal delivery (fix-dnscert3 卡 2-B, migration 570). A renewed
// version waits pending activation while the system delivers its key
// material (a system secret rollout, the certificate publication snapshot
// and artifact format) to every node serving the certificate's sites at the
// binding revisions it reserves. Once every node reported success, the
// sites are switched to it in one transaction (activation, bindings, settled
// publication intents, order active) and the scope republished through the
// system channel (trigger certificate_renewal), for manual and automatic
// publication modes alike. Until then the old version keeps serving; a
// failed round is retried with backoff and the owner notified.

const (
	renewalStateDelivering = "delivering"
	renewalStateRetryWait  = "retry_wait"
	renewalStateActivated  = "activated"
	renewalStateSkipped    = "skipped"
	renewalStateFailed     = "failed"

	// RenewalFailureDeliveryFailed: a node did not take the new version.
	RenewalFailureDeliveryFailed = "renewal_delivery_failed"
	// RenewalFailureNoNode: no online node with an artifact key serves the sites.
	RenewalFailureNoNode = "renewal_delivery_no_node"
	// RenewalFailureMaterial: the version's key material cannot be built.
	RenewalFailureMaterial = "renewal_delivery_material_unavailable"
	// RenewalFailureWaiting: an earlier publication of a site is in flight.
	RenewalFailureWaiting = "renewal_delivery_waiting"
	// RenewalSkippedSuperseded: the renewal is no longer to be switched in.
	RenewalSkippedSuperseded = "renewal_superseded"

	auditRenewalDeliveryStart  = "certificate.renewal.deliver"
	auditRenewalDeliveryFailed = "certificate.renewal.delivery_failed"
	auditRenewalDeliverySkip   = "certificate.renewal.skipped"
)

// RenewalFailureNotifier tells the certificate's owner a delivery round
// failed (certnotify.RenewFailedTx with the delivery's failure code).
type RenewalFailureNotifier func(ctx context.Context, tx pgx.Tx, scopeID, orderID uuid.UUID, code string) error

type renewalDeliveryStore interface {
	CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
		edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
	SystemSecretRolloutReceiptTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (edgedeployment.CertificatePublicationReceipt, error)
}

type renewalAssetStore interface {
	UseRenewalMaterialsInTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID,
		[]certificateasset.RenewalSiteRevision, certificateasset.OpaquePublicationResolver,
		certificateasset.PublicationConsumer) error
	ActivateRenewalTx(context.Context, pgx.Tx, certificateasset.RenewalActivation) error
}

// RenewalNodeResolver names the nodes a renewal goes to: every online node
// with the certificate publication capabilities serving any of the sites.
type RenewalNodeResolver func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID, now time.Time) ([]uuid.UUID, error)

type RenewalDelivererConfig struct {
	HealthCheck  edgedeployment.HealthCheckPolicy
	RetryBase    time.Duration
	RetryMaximum time.Duration
	MaxAttempts  int
	// RoundTimeout bounds one delivery round (its rollout deadline).
	RoundTimeout time.Duration
}

func DefaultRenewalDelivererConfig() RenewalDelivererConfig {
	return RenewalDelivererConfig{
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Minute,
			ObservationWindow: 10 * time.Second, RequiredConsecutiveSuccesses: 1},
		RetryBase: time.Minute, RetryMaximum: 6 * time.Hour, MaxAttempts: 12, RoundTimeout: 30 * time.Minute,
	}
}

// RenewalDeliverer runs one due renewal per RunOnce (edgeautopublish.RuntimeWorker).
type RenewalDeliverer struct {
	pool     *pgxpool.Pool
	assets   renewalAssetStore
	rollouts renewalDeliveryStore
	producer *Producer
	nodes    RenewalNodeResolver
	notify   RenewalFailureNotifier
	opaque   certificateasset.OpaquePublicationResolver
	config   RenewalDelivererConfig
	now      func() time.Time
}

func NewRenewalDeliverer(pool *pgxpool.Pool, assets renewalAssetStore, rollouts renewalDeliveryStore,
	producer *Producer, nodes RenewalNodeResolver, notify RenewalFailureNotifier,
	opaque certificateasset.OpaquePublicationResolver, config RenewalDelivererConfig, now func() time.Time,
) (*RenewalDeliverer, error) {
	if pool == nil || nilPublicationDependency(assets) || nilPublicationDependency(rollouts) || producer == nil ||
		nodes == nil || now == nil || config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase ||
		config.MaxAttempts < 1 || config.MaxAttempts > 100 || config.RoundTimeout < time.Minute ||
		config.HealthCheck.ActivationTimeout <= 0 || config.HealthCheck.ObservationWindow <= 0 ||
		config.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidInput
	}
	return &RenewalDeliverer{pool: pool, assets: assets, rollouts: rollouts, producer: producer, nodes: nodes,
		notify: notify, opaque: opaque, config: config, now: now}, nil
}

type renewalCandidate struct {
	scopeID, orderID, assetID, versionID uuid.UUID
	found                                bool // a delivery row exists
	state                                string
	attempt                              int
	rolloutID                            *uuid.UUID
	siteIDs                              []uuid.UUID
	bindingRevisions                     []int64
}

// RunOnce advances one due renewal: starts its first round, reads the
// running round's receipt, or retries a failed one.
func (deliverer *RenewalDeliverer) RunOnce(ctx context.Context) (bool, error) {
	if deliverer == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	worked := false
	err := pgx.BeginFunc(ctx, deliverer.pool, func(tx pgx.Tx) error {
		candidate, found, err := claimRenewalCandidate(ctx, tx)
		if err != nil || !found {
			return err
		}
		worked = true
		return deliverer.advanceTx(ctx, tx, candidate)
	})
	return worked, err
}

// claimRenewalCandidate locks the oldest due renewal: an issued child order
// whose version waits for activation and has no delivery yet, or a delivery
// round that is due.
func claimRenewalCandidate(ctx context.Context, tx pgx.Tx) (renewalCandidate, bool, error) {
	var candidate renewalCandidate
	var state *string
	var attempt *int
	err := tx.QueryRow(ctx, `SELECT cert_order.scope_id,cert_order.id,cert_order.issued_asset_id,
			cert_order.issued_asset_version_id,delivery.state,delivery.attempt,delivery.rollout_id,
			COALESCE(delivery.site_ids,'{}'),COALESCE(delivery.binding_revisions,'{}')
		FROM certificate_orders cert_order
		LEFT JOIN certificate_renewal_deliveries delivery
		  ON delivery.scope_id=cert_order.scope_id AND delivery.order_id=cert_order.id
		WHERE cert_order.renewal_of_order_id IS NOT NULL AND cert_order.status='issued'
		  AND cert_order.issued_asset_version_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM certificate_asset_activation_facts activation
		    WHERE activation.tenant_scope_id=cert_order.scope_id AND activation.asset_id=cert_order.issued_asset_id
		      AND activation.version_id=cert_order.issued_asset_version_id)
		  AND (delivery.order_id IS NULL OR (delivery.state IN ('delivering','retry_wait','superseded_by_user')
		    AND delivery.next_attempt_at<=clock_timestamp()))
		ORDER BY COALESCE(delivery.next_attempt_at,cert_order.updated_at),cert_order.id
		LIMIT 1 FOR UPDATE OF cert_order SKIP LOCKED`).Scan(&candidate.scopeID, &candidate.orderID,
		&candidate.assetID, &candidate.versionID, &state, &attempt, &candidate.rolloutID, &candidate.siteIDs,
		&candidate.bindingRevisions)
	if errors.Is(err, pgx.ErrNoRows) {
		return renewalCandidate{}, false, nil
	}
	if err != nil {
		return renewalCandidate{}, false, fmt.Errorf("claim certificate renewal delivery: %w", err)
	}
	if state != nil {
		candidate.found, candidate.state, candidate.attempt = true, *state, *attempt
	}
	return candidate, true, nil
}

func (deliverer *RenewalDeliverer) advanceTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate) error {
	if candidate.found && candidate.state == renewalStateDelivering && candidate.rolloutID != nil {
		receipt, err := deliverer.rollouts.SystemSecretRolloutReceiptTx(ctx, tx, candidate.scopeID, *candidate.rolloutID)
		if err != nil {
			return fmt.Errorf("read certificate renewal receipt: %w", err)
		}
		switch receipt.State {
		case edgedeployment.CertificatePublicationReceiptPending:
			return deliverer.recheckLater(ctx, tx, candidate)
		case edgedeployment.CertificatePublicationReceiptSucceeded:
			return deliverer.switchTx(ctx, tx, candidate, receipt)
		default:
			return deliverer.failRoundTx(ctx, tx, candidate, RenewalFailureDeliveryFailed)
		}
	}
	return deliverer.startRoundTx(ctx, tx, candidate)
}

// startRoundTx reserves the binding revisions and creates the round's
// system secret rollout (an unbound certificate switches at once).
func (deliverer *RenewalDeliverer) startRoundTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate) error {
	now := deliverer.now().UTC()
	bindings, err := certificateasset.LoadRenewalBindingsTx(ctx, tx, candidate.scopeID, candidate.assetID,
		candidate.versionID, now)
	if errors.Is(err, certificateasset.ErrRenewalSuperseded) {
		return deliverer.skipTx(ctx, tx, candidate)
	}
	if errors.Is(err, certificateasset.ErrRenewalWaiting) {
		return deliverer.failRoundTx(ctx, tx, candidate, RenewalFailureWaiting)
	}
	if err != nil {
		return err
	}
	if len(bindings.Sites) == 0 {
		return deliverer.activateTx(ctx, tx, candidate, nil, edgedeployment.CertificatePublicationReceipt{})
	}
	siteIDs := make([]uuid.UUID, len(bindings.Sites))
	for index, site := range bindings.Sites {
		siteIDs[index] = site.SiteID
	}
	nodeIDs, err := deliverer.nodes(ctx, tx, candidate.scopeID, siteIDs, now)
	if err != nil {
		return err
	}
	if len(nodeIDs) == 0 {
		return deliverer.failRoundTx(ctx, tx, candidate, RenewalFailureNoNode)
	}
	attempt := candidate.attempt + 1
	// The revisions this round sends are reserved before any node can take
	// them: a user's later binding change is numbered past them (fix-dnscert4).
	if err := certificateasset.ReserveRenewalBindingRevisionsTx(ctx, tx, candidate.scopeID, bindings.Sites,
		renewalRequestID(candidate)); errors.Is(err, certificateasset.ErrRenewalSuperseded) {
		return deliverer.recheckLater(ctx, tx, candidate)
	} else if err != nil {
		return err
	}
	var snapshot []byte
	err = deliverer.assets.UseRenewalMaterialsInTx(ctx, tx, candidate.scopeID, candidate.assetID, candidate.versionID,
		bindings.Sites, deliverer.opaque, func(materials []certificateasset.PublicationMaterial) error {
			var buildErr error
			snapshot, buildErr = buildPublicationSnapshot(candidate.scopeID, materials)
			return buildErr
		})
	if errors.Is(err, certificateasset.ErrRenewalSuperseded) {
		return deliverer.skipTx(ctx, tx, candidate)
	}
	if err != nil {
		return deliverer.failRoundTx(ctx, tx, candidate, RenewalFailureMaterial)
	}
	defer zeroPublicationBytes(snapshot)
	builder := func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
		var artifact edgedeployment.ArtifactInput
		err := deliverer.assets.UseRenewalMaterialsInTx(ctx, tx, candidate.scopeID, candidate.assetID,
			candidate.versionID, bindings.Sites, deliverer.opaque, func(materials []certificateasset.PublicationMaterial) error {
				var buildErr error
				artifact, buildErr = deliverer.producer.Build(ctx, BuildRequest{
					EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
					ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
					RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
					Materials: materials,
				})
				return buildErr
			})
		return artifact, err
	}
	accountable, err := renewalAccountableUser(ctx, tx, candidate)
	if err != nil {
		return err
	}
	result, err := deliverer.rollouts.CreateSystemSecretRolloutTx(ctx, tx, edgedeployment.SystemSecretRolloutRequest{
		ConfigurationScopeID: candidate.scopeID, AccountableUserID: accountable, NodeIDs: nodeIDs,
		CanonicalSnapshot: snapshot, GeneratorName: defaultGeneratorName, GeneratorVersion: defaultGeneratorVersion,
		PayloadDigest: sha256.Sum256(snapshot), RequiredCapabilities: edgeautopublish.CertificatePublicationCapabilities(),
		HealthCheck: deliverer.config.HealthCheck, Deadline: now.Add(deliverer.config.RoundTimeout),
		IdempotencyKey: "certrenew." + candidate.orderID.String() + "." + strconv.Itoa(attempt),
		// The rollout's request id is a UUID (edgedeployment rejects anything else):
		// derived from the round's idempotency key, so a replay carries the same one.
		RequestID:     uuid.NewSHA1(uuid.NameSpaceOID, []byte("certrenew."+candidate.orderID.String()+"."+strconv.Itoa(attempt))).String(),
		CorrelationID: candidate.orderID.String(),
		Reason:        "certificate_renewal",
	}, builder)
	if errors.Is(err, edgedeployment.ErrNodeRecipientKeyUnavailable) || errors.Is(err, edgedeployment.ErrNodeNotFound) ||
		errors.Is(err, edgedeployment.ErrConfigurationScopeConflict) {
		return deliverer.failRoundTx(ctx, tx, candidate, RenewalFailureNoNode)
	}
	if err != nil {
		return fmt.Errorf("create certificate renewal delivery: %w", err)
	}
	revisions := make([]int64, len(bindings.Sites))
	for index, site := range bindings.Sites {
		revisions[index] = site.BindingRevision
	}
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_renewal_deliveries(
			scope_id,order_id,asset_id,version_id,state,attempt,rollout_id,site_ids,binding_revisions,next_attempt_at)
		VALUES($1,$2,$3,$4,'delivering',$5,$6,$7,$8,clock_timestamp()+interval '10 seconds')
		ON CONFLICT (scope_id,order_id) DO UPDATE SET state='delivering',attempt=EXCLUDED.attempt,
		  rollout_id=EXCLUDED.rollout_id,site_ids=EXCLUDED.site_ids,binding_revisions=EXCLUDED.binding_revisions,
		  failure_code=NULL,next_attempt_at=EXCLUDED.next_attempt_at,updated_at=clock_timestamp()`,
		candidate.scopeID, candidate.orderID, candidate.assetID, candidate.versionID, attempt, result.Rollout.ID,
		siteIDs, revisions); err != nil {
		return err
	}
	return deliverer.audit(ctx, tx, candidate, auditRenewalDeliveryStart, "success", map[string]any{
		"attempt": attempt, "rollout_id": result.Rollout.ID.String(), "site_ids": lifecycleUUIDStrings(siteIDs),
		"node_ids": lifecycleUUIDStrings(nodeIDs), "state": renewalStateDelivering,
	})
}

func (deliverer *RenewalDeliverer) switchTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate,
	receipt edgedeployment.CertificatePublicationReceipt) error {
	if len(candidate.siteIDs) != len(candidate.bindingRevisions) {
		return ErrInvalidInput
	}
	// The binding default flag is read again under lock by ActivateRenewalTx
	// (it compares the whole reservation).
	bindings, err := certificateasset.LoadRenewalBindingsTx(ctx, tx, candidate.scopeID, candidate.assetID,
		candidate.versionID, deliverer.now().UTC())
	if errors.Is(err, certificateasset.ErrRenewalSuperseded) {
		return deliverer.skipTx(ctx, tx, candidate)
	}
	if errors.Is(err, certificateasset.ErrRenewalWaiting) {
		return deliverer.recheckLater(ctx, tx, candidate)
	}
	if err != nil {
		return err
	}
	sites := make([]certificateasset.RenewalSiteRevision, len(candidate.siteIDs))
	for index, siteID := range candidate.siteIDs {
		sites[index] = certificateasset.RenewalSiteRevision{SiteID: siteID, BindingRevision: candidate.bindingRevisions[index]}
		if index < len(bindings.Sites) && bindings.Sites[index].SiteID == siteID {
			sites[index].Default = bindings.Sites[index].Default
		}
	}
	return deliverer.activateTx(ctx, tx, candidate, sites, receipt)
}

func (deliverer *RenewalDeliverer) activateTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate,
	sites []certificateasset.RenewalSiteRevision, receipt edgedeployment.CertificatePublicationReceipt) error {
	// The scope's configuration row first (publication lock order), and the
	// revision before the switch, so the republication is attributed to it.
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		candidate.scopeID).Scan(&current)
	configured := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	err = deliverer.assets.ActivateRenewalTx(ctx, tx, certificateasset.RenewalActivation{
		TenantScopeID: candidate.scopeID, OrderID: candidate.orderID, AssetID: candidate.assetID,
		VersionID: candidate.versionID, Sites: sites, RolloutID: receipt.RolloutID,
		ConfigVersionID: receipt.ConfigVersionID, RolloutRevision: receipt.RolloutRevision,
		RequestID: renewalRequestID(candidate),
	})
	if errors.Is(err, certificateasset.ErrRenewalSuperseded) {
		return deliverer.skipTx(ctx, tx, candidate)
	}
	if err != nil {
		return fmt.Errorf("switch certificate renewal: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_renewal_deliveries(
			scope_id,order_id,asset_id,version_id,state,attempt,next_attempt_at)
		VALUES($1,$2,$3,$4,'activated',$5,clock_timestamp())
		ON CONFLICT (scope_id,order_id) DO UPDATE SET state='activated',failure_code=NULL,updated_at=clock_timestamp()`,
		candidate.scopeID, candidate.orderID, candidate.assetID, candidate.versionID, max(candidate.attempt, 0)); err != nil {
		return err
	}
	if len(sites) == 0 || !configured {
		return nil // nothing published references the certificate
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, candidate.scopeID); err != nil {
		return err
	}
	_, err = edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: candidate.scopeID, Trigger: edgepublish.SystemTriggerCertificateRenewal,
		SourceResourceID: sites[0].SiteID, Operation: "site.update", SourceRequestID: renewalRequestID(candidate),
		FromRevision: current, Immediate: true,
	})
	return err
}

func (deliverer *RenewalDeliverer) recheckLater(ctx context.Context, tx pgx.Tx, candidate renewalCandidate) error {
	_, err := tx.Exec(ctx, `UPDATE certificate_renewal_deliveries SET next_attempt_at=clock_timestamp()+interval '10 seconds',
		updated_at=clock_timestamp() WHERE scope_id=$1 AND order_id=$2`, candidate.scopeID, candidate.orderID)
	return err
}

// failRoundTx keeps the old version serving, records the reason and backs
// off; the owner is told (once per round). Exhausted attempts end failed.
func (deliverer *RenewalDeliverer) failRoundTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate, code string) error {
	attempt := candidate.attempt
	if !candidate.found || candidate.state != renewalStateDelivering {
		attempt++ // a round that never started still counts
	}
	state := renewalStateRetryWait
	if attempt >= deliverer.config.MaxAttempts {
		state = renewalStateFailed
	}
	delay := deliverer.retryDelay(attempt)
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_renewal_deliveries(
			scope_id,order_id,asset_id,version_id,state,attempt,failure_code,next_attempt_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+$8::bigint*interval '1 millisecond')
		ON CONFLICT (scope_id,order_id) DO UPDATE SET state=EXCLUDED.state,attempt=EXCLUDED.attempt,rollout_id=NULL,
		  failure_code=EXCLUDED.failure_code,next_attempt_at=EXCLUDED.next_attempt_at,updated_at=clock_timestamp()`,
		candidate.scopeID, candidate.orderID, candidate.assetID, candidate.versionID, state, attempt, code,
		delay.Milliseconds()); err != nil {
		return err
	}
	if err := deliverer.audit(ctx, tx, candidate, auditRenewalDeliveryFailed, "failure", map[string]any{
		"attempt": attempt, "failure_code": code, "state": state, "retry_in_seconds": int64(delay / time.Second),
	}); err != nil {
		return err
	}
	if deliverer.notify == nil || code == RenewalFailureWaiting {
		return nil
	}
	return deliverer.notify(ctx, tx, candidate.scopeID, candidate.orderID, code)
}

func (deliverer *RenewalDeliverer) skipTx(ctx context.Context, tx pgx.Tx, candidate renewalCandidate) error {
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_renewal_deliveries(
			scope_id,order_id,asset_id,version_id,state,attempt,failure_code,next_attempt_at)
		VALUES($1,$2,$3,$4,'skipped',$5,$6,clock_timestamp())
		ON CONFLICT (scope_id,order_id) DO UPDATE SET state='skipped',rollout_id=NULL,failure_code=EXCLUDED.failure_code,
		  updated_at=clock_timestamp()`, candidate.scopeID, candidate.orderID, candidate.assetID, candidate.versionID,
		max(candidate.attempt, 0), RenewalSkippedSuperseded); err != nil {
		return err
	}
	return deliverer.audit(ctx, tx, candidate, auditRenewalDeliverySkip, "success", map[string]any{
		"reason_code": RenewalSkippedSuperseded, "state": renewalStateSkipped,
	})
}

func (deliverer *RenewalDeliverer) retryDelay(attempt int) time.Duration {
	delay := deliverer.config.RetryBase
	for step := 1; step < attempt && delay < deliverer.config.RetryMaximum; step++ {
		delay *= 2
	}
	return min(delay, deliverer.config.RetryMaximum)
}

func (deliverer *RenewalDeliverer) audit(ctx context.Context, tx pgx.Tx, candidate renewalCandidate,
	action, result string, payload map[string]any) error {
	payload["asset_id"], payload["version_id"] = candidate.assetID.String(), candidate.versionID.String()
	payload["target_scope_id"], payload["operation"] = candidate.scopeID.String(), action
	return audit.New(deliverer.pool).Append(ctx, tx, audit.Event{ScopeID: candidate.scopeID, ActorKind: "system",
		ActorRef: "job:certificate_renewal", Action: action, ResourceType: "certificate_order",
		ResourceID: candidate.orderID.String(), RequestID: renewalRequestID(candidate), Result: result, Payload: payload})
}

func renewalRequestID(candidate renewalCandidate) string {
	return "certificate-renewal:" + candidate.orderID.String()
}

// renewalAccountableUser: the rollout's accountable principal is the order's
// requester (the system acts on their certificate).
func renewalAccountableUser(ctx context.Context, tx pgx.Tx, candidate renewalCandidate) (uuid.UUID, error) {
	var userID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT created_by_user_id FROM certificate_orders WHERE scope_id=$1 AND id=$2`,
		candidate.scopeID, candidate.orderID).Scan(&userID)
	return userID, err
}

func zeroPublicationBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// RenewalTargetNodes is the production RenewalNodeResolver: the line-group
// nodes of each site (edgeautopublish.SiteTargetNodeIDsTx), kept when active,
// online and advertising the certificate publication capabilities. A node
// that cannot take the version is left out: it never served the site's TLS.
func RenewalTargetNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID,
	now time.Time) ([]uuid.UUID, error) {
	var candidates []uuid.UUID
	for _, siteID := range siteIDs {
		nodes, err := edgeautopublish.SiteTargetNodeIDsTx(ctx, tx, scopeID, siteID)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, nodes...)
	}
	slices.SortFunc(candidates, func(left, right uuid.UUID) int { return compareRenewalUUID(left, right) })
	candidates = slices.Compact(candidates)
	if len(candidates) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT node.id FROM nodes node
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		WHERE node.id=ANY($1::uuid[]) AND node.admin_state='active' ORDER BY node.id`, candidates)
	if err != nil {
		return nil, err
	}
	online, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(online) == 0 {
		return nil, err
	}
	capabilities, err := edgepublish.LoadNodePublicationCapabilities(ctx, tx, online, now)
	if err != nil {
		return nil, err
	}
	required := edgeautopublish.CertificatePublicationCapabilities()
	result := make([]uuid.UUID, 0, len(online))
	for _, nodeID := range online {
		if renewalNodeCapable(capabilities[nodeID], required) {
			result = append(result, nodeID)
		}
	}
	return result, nil
}

func renewalNodeCapable(advertised *agentv1.AgentCapabilities, required []*agentv1.Capability) bool {
	if advertised == nil {
		return false
	}
	for _, want := range required {
		if !slices.ContainsFunc(advertised.Features, func(have *agentv1.Capability) bool {
			return have != nil && have.Name == want.Name && have.ApiVersion >= want.ApiVersion
		}) {
			return false
		}
	}
	return true
}

func compareRenewalUUID(left, right uuid.UUID) int {
	for index := range left {
		if left[index] != right[index] {
			if left[index] < right[index] {
				return -1
			}
			return 1
		}
	}
	return 0
}
