//go:build integration

package certificatepublish

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-dnscert3 卡 2-B（CERT-RENEW-LIFECYCLE-01 B 后半）：自动续签的新版本由系统下发到节点，
// 全部节点回执成功后才切换网站并激活、订单 → active，审计 actor=系统；任一节点失败旧版本继续服务、
// 记录原因并退避重试与通知。不手动 Activate。

type renewalFixture struct {
	pool      *pgxpool.Pool
	tenant    publicationTenant
	assets    *certificateasset.Store
	deployer  *RenewalDeliverer
	status    *edgestatus.Store
	nodes     []publicationNode
	assetID   uuid.UUID
	oldID     uuid.UUID
	newID     uuid.UUID
	orderID   uuid.UUID
	notified  []string
	resolverN []uuid.UUID
	created   map[uuid.UUID]edgedeployment.Rollout
}

func newRenewalFixture(t *testing.T) *renewalFixture {
	t.Helper()
	pool := openPublicationIntegrationDatabase(t)
	clock := func() time.Time { return publicationIntegrationNow }
	assets, err := certificateasset.NewStoreWithDependencies(pool, integrationCertificateEnveloper{}, audit.New(pool), clock)
	if err != nil {
		t.Fatal(err)
	}
	f := &renewalFixture{pool: pool, tenant: seedPublicationTenant(t, pool), assets: assets}
	f.nodes = []publicationNode{seedPublicationNode(t, pool, f.tenant.scopeID, f.tenant.userID),
		seedPublicationNode(t, pool, f.tenant.scopeID, f.tenant.userID)}
	f.resolverN = []uuid.UUID{f.nodes[0].id, f.nodes[1].id}
	if f.status, err = edgestatus.NewStoreWithClock(pool, clock); err != nil {
		t.Fatal(err)
	}
	// 原证书：上传后改为 ACME 来源的语义由订单表达；这里直接用 ACME 资产 + 父订单 + 已签发的续签子单。
	oldPEM, oldKey := issuePublicationCertificate(t, f.tenant.domain)
	newPEM, newKey := issuePublicationCertificate(t, f.tenant.domain)
	parentID, childID := uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// The orders are facts this test starts from (issuing, then issued with the
	// imported version), not the ACME runtime's 048 state machine; its trigger
	// is ENABLE ALWAYS, so it is switched off inside the seeding transaction
	// only (as certificateasset's seedCertificateOrderFact does).
	seedOrder := func(query string, args ...any) {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			for _, statement := range []string{`SET LOCAL session_replication_role = replica`,
				`ALTER TABLE certificate_orders DISABLE TRIGGER certificate_orders_runtime_048`} {
				if _, err := tx.Exec(t.Context(), statement); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(t.Context(), query, args...); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_runtime_048`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// issuePublicationCertificate's leaf expires a day after publicationIntegrationNow;
	// an ACME import requires the issued order's not_after to be the leaf's.
	notAfter := publicationIntegrationNow.Add(24 * time.Hour)
	// The issued order carries 048's whole issuance contract; the asset ids are
	// placeholders (FKs are off while seeding) until the import names them.
	issuedOrder := `INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,status,not_after,renewal_of_order_id,
		created_by_user_id,updated_by_user_id,issued_asset_id,issued_asset_version_id,issued_at,leaf_fingerprint_sha256,
		leaf_spki_sha256,acme_directory_url,acme_account_key_ref,certificate_key_ref,external_order_url,
		authorization_urls_sha256,certificate_url)
		VALUES($1,$2,ARRAY[$3],'http-01','issued',$5,$6,$4,$4,gen_random_uuid(),gen_random_uuid(),$5::timestamptz-interval '1 day',
		decode(repeat('48',32),'hex'),decode(repeat('48',32),'hex'),'https://ca.example.test/directory','account-key','certificate-key',
		'https://ca.example.test/order',decode(repeat('48',32),'hex'),'https://ca.example.test/certificate')`
	seedOrder(issuedOrder, parentID, f.tenant.scopeID, f.tenant.domain, f.tenant.userID, notAfter, nil)
	imported := f.importACME(t, parentID, nil, 0, oldPEM, oldKey)
	f.assetID, f.oldID = imported.Asset.ID, imported.Version.ID
	seedOrder(`UPDATE certificate_orders SET issued_asset_id=$3,issued_asset_version_id=$4,revision=revision+1
		WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, parentID, f.assetID, f.oldID)
	if _, err := assets.Activate(t.Context(), f.tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: f.tenant.scopeID, AssetID: f.assetID, VersionID: f.oldID, ExpectedRevision: imported.Asset.Revision,
		IdempotencyKey: "renewal-old-activate", RequestID: "renewal-old-activate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.Bind(t.Context(), f.tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: f.tenant.scopeID, SiteID: f.tenant.siteID, AssetID: f.assetID, VersionID: f.oldID,
		IdempotencyKey: "renewal-old-bind", RequestID: "renewal-old-bind"}); err != nil {
		t.Fatal(err)
	}
	// 用户之前的发布意图视为已完成（节点上已是旧版本）。
	exec(`INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,binding_revision,sequence,state,
		attempt,idempotency_key,failure_code,occurred_at)
		SELECT tenant_scope_id,site_id,binding_revision,2,'permanent_failed',1,
		  'certificate.publication/'||tenant_scope_id||'/'||site_id||'/'||binding_revision,'legacy_reissue_required',
		  transaction_timestamp()
		FROM certificate_publication_intents WHERE tenant_scope_id=$1`, f.tenant.scopeID)
	exec(`UPDATE certificate_assets SET auto_renew=true,revision=revision+1 WHERE tenant_scope_id=$1 AND id=$2`, f.tenant.scopeID, f.assetID)
	seedOrder(issuedOrder, childID, f.tenant.scopeID, f.tenant.domain, f.tenant.userID, notAfter, parentID)
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT revision FROM certificate_assets WHERE id=$1`, f.assetID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	renewed := f.importACME(t, childID, &f.assetID, revision, newPEM, newKey)
	f.newID, f.orderID = renewed.Version.ID, childID
	seedOrder(`UPDATE certificate_orders SET issued_asset_id=$3,issued_asset_version_id=$4,revision=revision+1
		WHERE scope_id=$1 AND id=$2`, f.tenant.scopeID, childID, f.assetID, f.newID)

	signer := &integrationPublicationSigner{}
	if _, signer.private, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(signer)
	if err != nil {
		t.Fatal(err)
	}
	rollouts, err := edgedeployment.NewStoreWithClockAndAuditor(pool, clock, audit.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	// fix-dnscert4：用户改绑撤销在途续签下发（与 cmd/control-api withRenewalDeliveryCanceller 相同接线）。
	assets.WithRenewalDeliveryCanceller(func(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID, requestID string) error {
		return rollouts.CancelSystemSecretRolloutTx(ctx, tx, scopeID, rolloutID, requestID, "certificate_renewal")
	})
	config := DefaultRenewalDelivererConfig()
	config.RetryBase = time.Second
	f.created = map[uuid.UUID]edgedeployment.Rollout{}
	f.deployer, err = NewRenewalDeliverer(pool, assets, &capturingRolloutStore{Store: rollouts, created: f.created}, producer,
		func(context.Context, pgx.Tx, uuid.UUID, []uuid.UUID, time.Time) ([]uuid.UUID, error) {
			return f.resolverN, nil
		},
		func(_ context.Context, _ pgx.Tx, _ uuid.UUID, orderID uuid.UUID, code string) error {
			f.notified = append(f.notified, orderID.String()+":"+code)
			return nil
		}, nil, config, clock)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// importACME imports an issued ACME order's certificate (PEM key; the
// transactional runtime import takes only an opaque key).
func (f *renewalFixture) importACME(t *testing.T, orderID uuid.UUID, assetID *uuid.UUID, revision int64,
	certificatePEM, privateKeyPEM []byte) certificateasset.ImportResult {
	t.Helper()
	result, err := f.assets.Import(t.Context(), f.tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: f.tenant.scopeID, AssetID: assetID, ExpectedRevision: revision,
		Name: "renewal certificate", Source: certificateasset.SourceACME, ACMEOrderID: &orderID,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "acme-order:" + orderID.String(), RequestID: "acme-order-finalize:" + orderID.String()})
	if err != nil {
		t.Fatalf("import ACME certificate: %v", err)
	}
	return result
}

func (f *renewalFixture) run(t *testing.T) {
	t.Helper()
	worked, err := f.deployer.RunOnce(t.Context())
	if err != nil || !worked {
		t.Fatalf("renewal delivery worked=%t error=%v", worked, err)
	}
}

func (f *renewalFixture) delivery(t *testing.T) (state string, attempt int, rolloutID *uuid.UUID, failure *string) {
	t.Helper()
	if err := f.pool.QueryRow(t.Context(), `SELECT state,attempt,rollout_id,failure_code FROM certificate_renewal_deliveries
		WHERE scope_id=$1 AND order_id=$2`, f.tenant.scopeID, f.orderID).Scan(&state, &attempt, &rolloutID, &failure); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *renewalFixture) currentBinding(t *testing.T) uuid.UUID {
	t.Helper()
	var version uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT version_id FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY sequence DESC LIMIT 1`, f.tenant.scopeID, f.tenant.siteID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func (f *renewalFixture) rollout(t *testing.T, id uuid.UUID) edgedeployment.Rollout {
	t.Helper()
	rollout, ok := f.created[id]
	if !ok {
		t.Fatalf("rollout %s was not created by the deliverer", id)
	}
	return rollout
}

// capturingRolloutStore is the production store; it keeps the rollouts the
// deliverer creates so the test can report node statuses for them.
type capturingRolloutStore struct {
	*edgedeployment.Store
	created map[uuid.UUID]edgedeployment.Rollout
}

func (store *capturingRolloutStore) CreateSystemSecretRolloutTx(ctx context.Context, tx pgx.Tx,
	request edgedeployment.SystemSecretRolloutRequest, builder edgedeployment.SecretArtifactBuilder,
) (edgedeployment.CreateRolloutResult, error) {
	result, err := store.Store.CreateSystemSecretRolloutTx(ctx, tx, request, builder)
	if err == nil {
		store.created[result.Rollout.ID] = result.Rollout
	}
	return result, err
}

func TestRenewalDeliveryActivatesOnlyAfterEveryNodeReceivedTheNewVersion(t *testing.T) {
	f := newRenewalFixture(t)
	f.run(t)
	state, attempt, rolloutID, _ := f.delivery(t)
	if state != "delivering" || attempt != 1 || rolloutID == nil {
		t.Fatalf("first round state=%s attempt=%d rollout=%v", state, attempt, rolloutID)
	}
	if got := f.currentBinding(t); got != f.oldID {
		t.Fatalf("BUG site switched before the nodes took the version: binding=%s", got)
	}
	rollout := f.rollout(t, *rolloutID)
	if len(rollout.Deployments) != len(f.nodes) {
		t.Fatalf("delivery deployments=%d nodes=%d", len(rollout.Deployments), len(f.nodes))
	}
	projectPublicationSuccess(t, f.status, rollout.Deployments[0])
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t) // one node still pending
	if got := f.currentBinding(t); got != f.oldID {
		t.Fatalf("BUG site switched with a node pending: binding=%s", got)
	}
	projectPublicationSuccess(t, f.status, rollout.Deployments[1])
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	state, _, _, _ = f.delivery(t)
	var orderStatus string
	var intentState string
	var systemAudits int
	if err := f.pool.QueryRow(t.Context(), `SELECT status FROM certificate_orders WHERE id=$1`, f.orderID).Scan(&orderStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT state FROM certificate_publication_intent_state_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY binding_revision DESC,sequence DESC LIMIT 1`,
		f.tenant.scopeID, f.tenant.siteID).Scan(&intentState); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id IS NULL
		AND action IN ('certificate.asset.activate','certificate.asset.bind','certificate.order.transition','certificate.renewal.deliver')`,
		f.tenant.scopeID).Scan(&systemAudits); err != nil {
		t.Fatal(err)
	}
	if state != "activated" || f.currentBinding(t) != f.newID || orderStatus != "active" || intentState != "succeeded" ||
		systemAudits < 4 {
		t.Fatalf("BUG renewal not switched in: delivery=%s binding=%s new=%s order=%s intent=%s system_audits=%d",
			state, f.currentBinding(t), f.newID, orderStatus, intentState, systemAudits)
	}
	var trigger bool
	if err := f.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM edge_system_republication_heads
		WHERE scope_id=$1 AND 'certificate_renewal'=ANY(triggers))`, f.tenant.scopeID).Scan(&trigger); err != nil {
		t.Fatal(err)
	}
	if !trigger {
		t.Fatal("BUG renewed sites not queued for system republication (certificate_renewal)")
	}
}

func TestRenewalDeliveryFailureKeepsOldVersionAndRetries(t *testing.T) {
	f := newRenewalFixture(t)
	f.run(t)
	_, _, rolloutID, _ := f.delivery(t)
	rollout := f.rollout(t, *rolloutID)
	projectPublicationSuccess(t, f.status, rollout.Deployments[0])
	projectPublicationFailure(t, f.status, rollout.Deployments[1])
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	state, attempt, _, failure := f.delivery(t)
	if state != "retry_wait" || attempt != 1 || failure == nil || *failure != RenewalFailureDeliveryFailed ||
		f.currentBinding(t) != f.oldID || len(f.notified) != 1 {
		t.Fatalf("BUG failed delivery: state=%s attempt=%d failure=%v binding=%s notified=%v",
			state, attempt, failure, f.currentBinding(t), f.notified)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t) // the next round starts again
	state, attempt, rolloutID2, _ := f.delivery(t)
	if state != "delivering" || attempt != 2 || rolloutID2 == nil || *rolloutID2 == *rolloutID {
		t.Fatalf("retry round state=%s attempt=%d rollout=%v previous=%s", state, attempt, rolloutID2, rolloutID)
	}
}

func TestRenewalDeliverySkipsWhenAutoRenewTurnedOff(t *testing.T) {
	f := newRenewalFixture(t)
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_assets SET auto_renew=false,revision=revision+1 WHERE id=$1`, f.assetID); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	state, _, rolloutID, failure := f.delivery(t)
	if state != "skipped" || rolloutID != nil || failure == nil || *failure != RenewalSkippedSuperseded ||
		f.currentBinding(t) != f.oldID || len(f.notified) != 0 {
		t.Fatalf("BUG auto-renew off still delivered: state=%s rollout=%v failure=%v notified=%v", state, rolloutID, failure, f.notified)
	}
}

// fix-dnscert4：续签下发途中（新版本已到一台节点）用户把同一网站改绑到另一张证书。
// 同一事务内：本轮续签 rollout 撤销（未发出的节点命令取消），续签切换标记 superseded_by_user；
// 用户的绑定版本号跳过续签已占的号（节点上已有该号的续签版本，不会同号冲突）；
// 旧一轮回执即便全部成功也不再切换；之后按用户新绑定重新调度（站点已不绑本资产 → 无站点可切，直接激活）。
func TestRenewalDeliveryUserRebindMidDeliverySupersedesRound(t *testing.T) {
	f := newRenewalFixture(t)
	f.run(t)
	state, _, rolloutID, _ := f.delivery(t)
	if state != "delivering" || rolloutID == nil {
		t.Fatalf("first round state=%s rollout=%v", state, rolloutID)
	}
	var reserved, latest int64
	if err := f.pool.QueryRow(t.Context(), `SELECT reserved_revision FROM certificate_site_binding_reservations
		WHERE tenant_scope_id=$1 AND site_id=$2`, f.tenant.scopeID, f.tenant.siteID).Scan(&reserved); err != nil {
		t.Fatalf("BUG round did not reserve the binding revision it sends: %v", err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT max(sequence) FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2`, f.tenant.scopeID, f.tenant.siteID).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if reserved != latest+1 {
		t.Fatalf("reserved=%d latest=%d", reserved, latest)
	}
	rollout := f.rollout(t, *rolloutID)
	projectPublicationSuccess(t, f.status, rollout.Deployments[0]) // 新版本已到节点 0

	// 用户改绑：另一张上传证书。
	otherPEM, otherKey := issuePublicationCertificate(t, f.tenant.domain)
	other, err := f.assets.Import(t.Context(), f.tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: f.tenant.scopeID, Name: "user certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: otherPEM, PrivateKeyPEM: otherKey, IdempotencyKey: "rebind-import", RequestID: "rebind-import"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.assets.Activate(t.Context(), f.tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: f.tenant.scopeID, AssetID: other.Asset.ID, VersionID: other.Version.ID,
		ExpectedRevision: other.Asset.Revision, IdempotencyKey: "rebind-activate", RequestID: "rebind-activate"}); err != nil {
		t.Fatal(err)
	}
	bound, err := f.assets.Bind(t.Context(), f.tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: f.tenant.scopeID, SiteID: f.tenant.siteID, AssetID: other.Asset.ID, VersionID: other.Version.ID,
		ExpectedRevision: latest, IdempotencyKey: "rebind-bind", RequestID: "rebind-bind"})
	if err != nil {
		t.Fatalf("BUG user rebind refused while a renewal delivery is in flight: %v", err)
	}
	if bound.Revision <= reserved {
		t.Fatalf("BUG user binding revision %d collides with the renewal's reserved %d (node already holds it)",
			bound.Revision, reserved)
	}
	var intentRevision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT max(binding_revision) FROM certificate_publication_intents
		WHERE tenant_scope_id=$1 AND site_id=$2 AND request_id='rebind-bind'`, f.tenant.scopeID, f.tenant.siteID).Scan(&intentRevision); err != nil {
		t.Fatal(err)
	}
	if intentRevision != bound.Revision {
		t.Fatalf("user publication intent revision=%d binding=%d", intentRevision, bound.Revision)
	}
	state, _, _, failure := f.delivery(t)
	var rolloutStatus string
	var queued, cancelled int
	if err := f.pool.QueryRow(t.Context(), `SELECT status FROM rollouts WHERE id=$1`, *rolloutID).Scan(&rolloutStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE state='queued'),count(*) FILTER (WHERE state='cancelled')
		FROM node_deployments WHERE rollout_id=$1`, *rolloutID).Scan(&queued, &cancelled); err != nil {
		t.Fatal(err)
	}
	var supersedeAudits int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action='certificate.renewal.superseded_by_user' AND request_id='rebind-bind'`, f.tenant.scopeID).Scan(&supersedeAudits); err != nil {
		t.Fatal(err)
	}
	// 节点 0 已收到新版本（保留不用，用户的更高版本号发布会替换它）；节点 1 的命令未发出，已取消。
	if state != certificateasset.RenewalSupersededByUser || failure == nil || *failure != certificateasset.RenewalSupersededByUser ||
		rolloutStatus != "cancelled" || queued != 0 || cancelled != 1 || supersedeAudits != 1 {
		t.Fatalf("BUG in-flight renewal not withdrawn in the rebind transaction: delivery=%s failure=%v rollout=%s queued=%d cancelled=%d audits=%d",
			state, failure, rolloutStatus, queued, cancelled, supersedeAudits)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	// 重新调度：用户那次发布未结算前续签等待；结算后站点已不绑本资产 → 无站点，直接激活。
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,binding_revision,sequence,state,
		attempt,idempotency_key,failure_code,occurred_at)
		SELECT intent.tenant_scope_id,intent.site_id,intent.binding_revision,
		  (SELECT max(sequence)+1 FROM certificate_publication_intent_state_facts state WHERE state.tenant_scope_id=intent.tenant_scope_id
		    AND state.site_id=intent.site_id AND state.binding_revision=intent.binding_revision),
		  'permanent_failed',1,'certificate.publication/'||intent.tenant_scope_id||'/'||intent.site_id||'/'||intent.binding_revision,
		  'legacy_reissue_required',transaction_timestamp()
		FROM certificate_publication_intents intent WHERE intent.tenant_scope_id=$1 AND intent.site_id=$2
		  AND intent.binding_revision=$3`, f.tenant.scopeID, f.tenant.siteID, bound.Revision)
	f.run(t)
	state, _, _, _ = f.delivery(t)
	if got := f.currentBinding(t); got != other.Version.ID {
		t.Fatalf("BUG renewal overrode the user's rebind: binding=%s user=%s", got, other.Version.ID)
	}
	var sequenceAtReserved int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND sequence=$3`, f.tenant.scopeID, f.tenant.siteID, reserved).Scan(&sequenceAtReserved); err != nil {
		t.Fatal(err)
	}
	if state != "activated" || sequenceAtReserved != 0 {
		t.Fatalf("re-planned renewal: delivery=%s facts_at_reserved=%d (want activated with no site, reserved revision unused)",
			state, sequenceAtReserved)
	}
}

// fix-dnscert4：下发途中用户把网站改绑回同一资产（重新发布当前激活的旧版本）。续签让位，用户发布用新号；
// 之后续签按新绑定重新调度：再占一个更高的号、开新一轮，节点上不会出现同号不同版本。
func TestRenewalDeliveryUserRepublishSameAssetReplansAtHigherRevision(t *testing.T) {
	f := newRenewalFixture(t)
	f.run(t)
	_, _, firstRollout, _ := f.delivery(t)
	var reserved, latest int64
	if err := f.pool.QueryRow(t.Context(), `SELECT reserved_revision,(SELECT max(sequence) FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2) FROM certificate_site_binding_reservations
		WHERE tenant_scope_id=$1 AND site_id=$2`, f.tenant.scopeID, f.tenant.siteID).Scan(&reserved, &latest); err != nil {
		t.Fatal(err)
	}
	bound, err := f.assets.Bind(t.Context(), f.tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: f.tenant.scopeID, SiteID: f.tenant.siteID, AssetID: f.assetID, VersionID: f.oldID, Default: true,
		ExpectedRevision: latest, IdempotencyKey: "republish-bind", RequestID: "republish-bind"})
	if err != nil {
		t.Fatal(err)
	}
	if bound.Revision != reserved+1 {
		t.Fatalf("user republication revision=%d reserved=%d", bound.Revision, reserved)
	}
	if state, _, _, _ := f.delivery(t); state != certificateasset.RenewalSupersededByUser {
		t.Fatalf("delivery state=%s, want superseded_by_user", state)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,
		binding_revision,sequence,state,attempt,idempotency_key,failure_code,occurred_at)
		SELECT tenant_scope_id,site_id,binding_revision,2,'permanent_failed',1,
		  'certificate.publication/'||tenant_scope_id||'/'||site_id||'/'||binding_revision,'legacy_reissue_required',transaction_timestamp()
		FROM certificate_publication_intents WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3`,
		f.tenant.scopeID, f.tenant.siteID, bound.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	state, attempt, secondRollout, _ := f.delivery(t)
	var reservedAgain int64
	if err := f.pool.QueryRow(t.Context(), `SELECT reserved_revision FROM certificate_site_binding_reservations
		WHERE tenant_scope_id=$1 AND site_id=$2`, f.tenant.scopeID, f.tenant.siteID).Scan(&reservedAgain); err != nil {
		t.Fatal(err)
	}
	if state != "delivering" || attempt != 2 || secondRollout == nil || *secondRollout == *firstRollout ||
		reservedAgain != bound.Revision+1 {
		t.Fatalf("BUG renewal not re-planned from the user's binding: state=%s attempt=%d rollout=%v first=%s reserved=%d user=%d",
			state, attempt, secondRollout, firstRollout, reservedAgain, bound.Revision)
	}
	second := f.rollout(t, *secondRollout)
	for _, deployment := range second.Deployments {
		projectPublicationSuccess(t, f.status, deployment)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE certificate_renewal_deliveries SET next_attempt_at=now() WHERE order_id=$1`, f.orderID); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	var switchedAt int64
	if err := f.pool.QueryRow(t.Context(), `SELECT sequence FROM certificate_site_binding_facts WHERE tenant_scope_id=$1
		AND site_id=$2 ORDER BY sequence DESC LIMIT 1`, f.tenant.scopeID, f.tenant.siteID).Scan(&switchedAt); err != nil {
		t.Fatal(err)
	}
	if state, _, _, _ := f.delivery(t); state != "activated" || f.currentBinding(t) != f.newID || switchedAt != reservedAgain {
		t.Fatalf("BUG re-planned renewal not switched at its own reservation: state=%s binding=%s at=%d reserved=%d",
			state, f.currentBinding(t), switchedAt, reservedAgain)
	}
}
