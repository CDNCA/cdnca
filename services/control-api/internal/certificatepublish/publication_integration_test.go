//go:build integration

package certificatepublish

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var publicationIntegrationNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

type integrationPublicationSigner struct {
	private ed25519.PrivateKey
	calls   atomic.Int64
	failAt  atomic.Int64
}

func (signer *integrationPublicationSigner) ArtifactSigningKeyID() string {
	return "certificate-publication-integration-signer"
}

func (signer *integrationPublicationSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}

func (signer *integrationPublicationSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	call := signer.calls.Add(1)
	if signer.failAt.Load() == call {
		return nil, errors.New("injected publication signing failure")
	}
	return ed25519.Sign(signer.private, value), nil
}

type integrationCertificateEnveloper struct{}

func (integrationCertificateEnveloper) Seal(
	_ context.Context,
	request certificateasset.PrivateKeySealRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	return sealIntegrationEnvelope(request.Context, request.PlaintextPKCS8, "certificate-integration-kek")
}

func (integrationCertificateEnveloper) SealOpaque(
	_ context.Context,
	request certificateasset.OpaquePrivateKeySealRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	return sealIntegrationEnvelope(request.Context, request.WrappedKeyMaterial, "certificate-integration-kek")
}

func (integrationCertificateEnveloper) Unseal(
	_ context.Context,
	request certificateasset.PrivateKeyUnsealRequest,
) ([]byte, error) {
	aad, err := request.Context.CanonicalAAD()
	if err != nil {
		return nil, err
	}
	aead, err := integrationEnvelopeAEAD(request.Envelope.KeyID)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext, aad)
}

func (enveloper integrationCertificateEnveloper) Rewrap(
	ctx context.Context,
	request certificateasset.PrivateKeyRewrapRequest,
) (certificateasset.PrivateKeyEnvelope, error) {
	plaintext, err := enveloper.Unseal(ctx, certificateasset.PrivateKeyUnsealRequest{
		Context: request.Context, Envelope: request.Envelope,
	})
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	defer clearBytes(plaintext)
	return sealIntegrationEnvelope(request.Context, plaintext, request.TargetKeyID)
}

func TestPublicationRuntimeAtomicReplacementAndRevocation(t *testing.T) {
	if value := os.Getenv("CERTIFICATE_PUBLICATION_SMOKE_NOW"); value != "" {
		injected, err := time.Parse(time.RFC3339, value)
		if err != nil || injected.Location() != time.UTC {
			t.Fatal("certificate publication smoke time must be RFC3339 UTC")
		}
		previous := publicationIntegrationNow
		publicationIntegrationNow = injected
		t.Cleanup(func() { publicationIntegrationNow = previous })
	}
	pool := openPublicationIntegrationDatabase(t)
	certificates, err := certificateasset.NewStoreWithDependencies(
		pool, integrationCertificateEnveloper{}, audit.New(pool), func() time.Time { return publicationIntegrationNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	tenant := seedPublicationTenant(t, pool)
	certificatePEM, privateKeyPEM := issuePublicationCertificate(t, tenant.domain)
	imported, err := certificates.Import(t.Context(), tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: tenant.scopeID, Name: "publication certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "certificate-publication-import", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Activate(t.Context(), tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "certificate-publication-activate",
		RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	bound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "certificate-publication-bind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}

	deploymentActor, deploymentStore := seedPublicationDeploymentActor(t, pool)
	statusStore, err := edgestatus.NewStoreWithClock(pool, func() time.Time { return publicationIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	nodes := []publicationNode{
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
	}
	signer := &integrationPublicationSigner{}
	_, signer.private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(signer)
	if err != nil {
		t.Fatal(err)
	}
	// 与 cmd/control-api 的生产组装一致：证书发布走带本人复核的 CertificatePublisherStore。
	publisherStore, err := edgedeployment.NewCertificatePublisherStore(deploymentStore, NewActorRevalidator())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPublicationService(pool, certificates, publisherStore, producer, DefaultPublicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	request := publicationIntegrationRequest(t, pool, deploymentActor, tenant, nodes, bound, "certificate-publication-initial")
	created, err := service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || created.Rollout.MaxAttempts != 1 || len(created.Rollout.Deployments) != 2 {
		t.Fatalf("initial publication=%+v", created)
	}
	assertPublicationArtifacts(t, pool, created.Rollout, nodes, privateKeyPEM)
	assertNoSecretConfigState(t, pool, nodes)
	replayed, err := service.Publish(t.Context(), request)
	if err != nil || !replayed.Replayed || replayed.Rollout.ID != created.Rollout.ID || signer.calls.Load() != 2 {
		t.Fatalf("initial replay=%+v error=%v signer_calls=%d", replayed, err, signer.calls.Load())
	}
	if outputDirectory := os.Getenv("CERTIFICATE_PUBLICATION_FIXTURE_DIR"); outputDirectory != "" {
		writePublicationSmokeFixture(
			t, pool, outputDirectory, created.Rollout, nodes, signer, certificatePEM,
			tenant.scopeID, tenant.siteID, imported.Asset.ID, imported.Version.ID,
		)
	}
	for _, deployment := range created.Rollout.Deployments {
		projectPublicationFailure(t, statusStore, deployment)
	}

	oldRecipientID := nodes[1].recipientID
	nodes[1] = rotatePublicationNodeKey(t, pool, nodes[1], tenant.userID)
	retryRequest := RetryPublicationRequest{
		PublicationRequest: publicationIntegrationRequest(
			t, pool, deploymentActor, tenant, nodes, bound, "certificate-publication-replacement",
		),
		OriginalRolloutID: created.Rollout.ID, ExpectedRevision: created.Rollout.Revision,
	}
	signer.failAt.Store(signer.calls.Load() + 2)
	if _, err := service.RetryPublication(t.Context(), retryRequest); !errors.Is(err, edgedeployment.ErrUnavailable) {
		t.Fatalf("injected replacement failure=%v", err)
	}
	assertReplacementRollback(t, pool, created.Rollout.ID, created.Rollout.Revision, retryRequest.IdempotencyKey)
	signer.failAt.Store(0)
	replaced, err := service.RetryPublication(t.Context(), retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Replayed || replaced.OriginalRolloutID != created.Rollout.ID ||
		replaced.OriginalRevision != created.Rollout.Revision+1 || len(replaced.Rollout.Deployments) != 2 {
		t.Fatalf("replacement=%+v", replaced)
	}
	var rotatedRecipientID string
	for _, deployment := range replaced.Rollout.Deployments {
		if deployment.NodeID == nodes[1].id {
			rotatedRecipientID = deployment.Command.Artifacts[0].GetRecipientKeyId()
			break
		}
	}
	if got := rotatedRecipientID; got != nodes[1].recipientID || got == oldRecipientID {
		t.Fatalf("replacement recipient=%q old=%q current=%q", got, oldRecipientID, nodes[1].recipientID)
	}
	assertPublicationArtifacts(t, pool, replaced.Rollout, nodes, privateKeyPEM)
	for _, deployment := range replaced.Rollout.Deployments {
		projectPublicationFailure(t, statusStore, deployment)
	}

	concurrent := retryRequest
	concurrent.IdempotencyKey = "certificate-publication-concurrent-replacement"
	concurrent.RequestID = uuid.NewString()
	concurrent.CorrelationID = uuid.NewString()
	concurrent.ExpectedRevision = replaced.OriginalRevision
	var results [2]edgedeployment.SecretReplacementResult
	var errs [2]error
	var wait sync.WaitGroup
	wait.Add(2)
	for index := range results {
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = service.RetryPublication(context.Background(), concurrent)
		}(index)
	}
	wait.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Rollout.ID != results[1].Rollout.ID ||
		results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent replacement results=%+v errors=%v", results, errs)
	}
	for _, deployment := range results[0].Rollout.Deployments {
		projectPublicationFailure(t, statusStore, deployment)
	}
	for _, test := range []struct {
		name string
		now  time.Time
	}{
		{name: "expired", now: imported.Version.NotAfter},
		{name: "not yet valid", now: imported.Version.NotBefore.Add(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			previousNow := publicationIntegrationNow
			publicationIntegrationNow = test.now
			defer func() { publicationIntegrationNow = previousNow }()

			invalid := concurrent
			invalid.IdempotencyKey = "certificate-publication-" + strings.ReplaceAll(test.name, " ", "-") + "-replacement"
			invalid.RequestID = uuid.NewString()
			invalid.CorrelationID = uuid.NewString()
			invalid.ExpectedRevision = results[0].OriginalRevision
			invalid.Deadline = test.now.Add(time.Hour)
			if _, err := service.RetryPublication(t.Context(), invalid); !errors.Is(err, edgedeployment.ErrUnavailable) {
				t.Fatalf("%s certificate replacement error=%v", test.name, err)
			}
			assertReplacementRollback(t, pool, created.Rollout.ID, invalid.ExpectedRevision, invalid.IdempotencyKey)
		})
	}

	unbinding, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: bound.Revision,
		IdempotencyKey: "certificate-publication-unbind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Materials are pinned to a binding revision; the site's current one is
	// the unbind, which has no certificate to publish.
	unbound := concurrent
	unbound.BindingRevision = unbinding.Revision
	unbound.IdempotencyKey = "certificate-publication-unbound-replacement"
	unbound.RequestID = uuid.NewString()
	unbound.CorrelationID = uuid.NewString()
	unbound.ExpectedRevision = results[0].OriginalRevision
	if _, err := service.RetryPublication(t.Context(), unbound); !errors.Is(err, edgedeployment.ErrUnavailable) {
		t.Fatalf("unbound certificate replacement error=%v", err)
	}
	assertReplacementRollback(t, pool, created.Rollout.ID, unbound.ExpectedRevision, unbound.IdempotencyKey)

	seedPublicationCertificateRevocation(t, pool, tenant, imported.Asset.ID, imported.Version.ID, "publication integration revocation")
	revoked := concurrent
	revoked.IdempotencyKey = "certificate-publication-revoked-replacement"
	revoked.RequestID = uuid.NewString()
	revoked.CorrelationID = uuid.NewString()
	revoked.ExpectedRevision = results[0].OriginalRevision
	if _, err := service.RetryPublication(t.Context(), revoked); !errors.Is(err, edgedeployment.ErrUnavailable) {
		t.Fatalf("revoked certificate replacement error=%v", err)
	}
	assertReplacementRollback(t, pool, created.Rollout.ID, revoked.ExpectedRevision, revoked.IdempotencyKey)
	assertPublicationSensitiveValuesAbsent(t, pool, privateKeyPEM)
}

func writePublicationSmokeFixture(
	t *testing.T,
	pool *pgxpool.Pool,
	outputDirectory string,
	rollout edgedeployment.Rollout,
	nodes []publicationNode,
	signer *integrationPublicationSigner,
	certificatePEM []byte,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	certificateID uuid.UUID,
	certificateVersionID uuid.UUID,
) {
	t.Helper()
	if !filepath.IsAbs(outputDirectory) || filepath.Clean(outputDirectory) != outputDirectory {
		t.Fatal("publication smoke fixture directory must be absolute and clean")
	}
	info, err := os.Lstat(outputDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("publication smoke fixture directory must be an owner-only directory")
	}
	if len(rollout.Deployments) == 0 {
		t.Fatal("publication smoke rollout has no deployments")
	}
	deployment := rollout.Deployments[0]
	var commandBytes, wire, outboxBytes []byte
	if err := pool.QueryRow(t.Context(), `SELECT deployment.command_bytes,artifact.wire_bytes,outbox.payload
		FROM node_deployments deployment
		JOIN node_deployment_artifacts binding
		  ON binding.deployment_id=deployment.id AND binding.deployment_attempt=deployment.attempt
		JOIN configuration_artifacts artifact
		  ON artifact.config_version_id=binding.config_version_id AND artifact.id=binding.artifact_id
		JOIN edge_command_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.id=$1 AND deployment.attempt=1`, deployment.ID).Scan(
		&commandBytes, &wire, &outboxBytes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commandBytes, outboxBytes) {
		t.Fatal("publication smoke outbox did not preserve the immutable command")
	}
	var command agentv1.DeploymentCommand
	if err := proto.Unmarshal(commandBytes, &command); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&command, deployment.Command) || len(command.Artifacts) != 1 {
		t.Fatal("publication smoke command does not match the rollout result")
	}
	descriptor := command.Artifacts[0]
	digest := sha256.Sum256(wire)
	if uint64(len(wire)) != descriptor.SizeBytes || !bytes.Equal(digest[:], descriptor.Sha256) {
		t.Fatal("publication smoke artifact does not match its descriptor")
	}
	var recipientPrivateKey []byte
	for _, node := range nodes {
		if node.id == deployment.NodeID {
			recipientPrivateKey = node.privateKey
			break
		}
	}
	if len(recipientPrivateKey) != 32 {
		t.Fatal("publication smoke recipient private key is unavailable")
	}
	remaining := certificatePEM
	var rootPEM []byte
	for certificateIndex := 0; ; certificateIndex++ {
		block, rest := pem.Decode(remaining)
		if block == nil {
			if certificateIndex != 2 || len(bytes.TrimSpace(remaining)) != 0 {
				t.Fatal("publication smoke certificate chain is malformed")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatal("publication smoke certificate chain contains a non-certificate block")
		}
		if certificateIndex == 1 {
			rootPEM = pem.EncodeToMemory(block)
		}
		remaining = rest
	}
	publicSigningKey := signer.private.Public().(ed25519.PublicKey)
	evidence, err := json.MarshalIndent(map[string]any{
		"artifact_id":             descriptor.ArtifactId,
		"artifact_sha256":         hex.EncodeToString(descriptor.Sha256),
		"artifact_size":           descriptor.SizeBytes,
		"certificate_chain_count": 2,
		"certificate_id":          certificateID.String(),
		"certificate_version_id":  certificateVersionID.String(),
		"config_version_id":       command.ConfigVersionId,
		"deployment_id":           command.DeploymentId,
		"domain":                  "publication.example.test",
		"event_id":                command.Event.EventId,
		"publication_source":      "postgresql-current-head",
		"recipient_key_id":        descriptor.GetRecipientKeyId(),
		"rollout_id":              command.RolloutId,
		"signing_key_id":          descriptor.SigningKeyId,
		"site_id":                 siteID.String(),
		"tenant_scope_id":         tenantScopeID.String(),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	evidence = append(evidence, '\n')
	for _, file := range []struct {
		name  string
		value []byte
	}{
		{name: "command.pb", value: commandBytes},
		{name: "artifact.bin", value: wire},
		{name: "recipient.key", value: recipientPrivateKey},
		{name: "signing.pub", value: publicSigningKey},
		{name: "ca.pem", value: rootPEM},
		{name: "evidence.json", value: evidence},
	} {
		writePublicationSmokeFile(t, outputDirectory, file.name, file.value)
	}
}

func writePublicationSmokeFile(t *testing.T, directory, name string, value []byte) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

type publicationTenant struct {
	tenantID         uuid.UUID
	scopeID          uuid.UUID
	userID           uuid.UUID
	siteID           uuid.UUID
	domain           string
	certificateActor certificateasset.Actor
}

// seedPublicationCertificateRevocation writes a historical revocation fact the
// way the retired certificateasset Store.Revoke did (fix-certmenu, user 10-28:
// the asset revoke API is gone; revoked versions must still never publish).
func seedPublicationCertificateRevocation(t *testing.T, pool *pgxpool.Pool, tenant publicationTenant,
	assetID, versionID uuid.UUID, reason string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var revision int64
		if err := tx.QueryRow(t.Context(), `UPDATE certificate_assets SET revision=revision+1
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL RETURNING revision`,
			tenant.scopeID, assetID).Scan(&revision); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_revocation_facts(
			tenant_scope_id,asset_id,version_id,expected_asset_revision,resulting_asset_revision,
			reason,request_id,actor_scope_id,revoked_by_user_id,revoked_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$1,$8,$9)`, tenant.scopeID, assetID, versionID, revision-1, revision,
			reason, uuid.NewString(), tenant.userID, publicationIntegrationNow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

type publicationNode struct {
	id          uuid.UUID
	recipientID string
	privateKey  []byte
}

// publicationIntegrationRequest is the request the publication worker builds
// from a lease (publication_adapter.go publicationRequest): the binding being
// published and the actor/tenant revisions the publisher store revalidates.
func publicationIntegrationRequest(
	t *testing.T,
	pool *pgxpool.Pool,
	actor edgedeployment.Actor,
	tenant publicationTenant,
	nodes []publicationNode,
	binding certificateasset.Binding,
	key string,
) PublicationRequest {
	t.Helper()
	nodeIDs := make([]uuid.UUID, len(nodes))
	for index, node := range nodes {
		nodeIDs[index] = node.id
	}
	var userRevision, tenantRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT actor.revision,tenant.revision FROM users actor, tenants tenant
		WHERE actor.id=$1 AND tenant.id=$2`, actor.UserID, tenant.tenantID).Scan(&userRevision, &tenantRevision); err != nil {
		t.Fatal(err)
	}
	return PublicationRequest{
		Actor: actor, TenantScopeID: tenant.scopeID, SiteIDs: []uuid.UUID{tenant.siteID}, NodeIDs: nodeIDs,
		AssetID: binding.AssetID, VersionID: binding.VersionID, BindingRevision: binding.Revision,
		ActorUserRevision: userRevision, TargetTenantID: tenant.tenantID, TargetTenantRevision: tenantRevision,
		RequiredCapabilities: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1,
		}},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Second,
			RequiredConsecutiveSuccesses: 1,
		},
		Deadline: publicationIntegrationNow.Add(time.Hour), IdempotencyKey: key,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
}

func seedPublicationTenant(t *testing.T, pool *pgxpool.Pool) publicationTenant {
	t.Helper()
	tenant := publicationTenant{
		tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), siteID: uuid.New(),
		domain: "publication.example.test",
	}
	roleID := uuid.New()
	sessionID := uuid.New()
	refreshDigest := sha256.Sum256(sessionID[:])
	username := "certificate-publication-" + strings.ReplaceAll(tenant.userID.String(), "-", "")[:12]
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Certificate publication tenant')`, []any{tenant.tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{tenant.scopeID, tenant.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Certificate publication user','unused')`, []any{tenant.userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{tenant.scopeID, tenant.userID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			 VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{sessionID, uuid.New(), tenant.userID, tenant.scopeID,
			// The session is checked against the database clock (wall time).
			refreshDigest[:], time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour)}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','Certificate publication owner',true)`, []any{roleID, tenant.scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'certificates.read'),($1,'certificates.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{tenant.scopeID, tenant.userID, roleID}},
		{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		 VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$2,$3,$4,ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`, []any{tenant.siteID, tenant.scopeID, tenant.userID, tenant.domain}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{tenant.siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',443)`, []any{tenant.siteID}},
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	tenant.certificateActor = certificateasset.Actor{
		UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: certificateasset.ScopeTenant,
		SessionID: sessionID,
	}
	return tenant
}

func seedPublicationDeploymentActor(
	t *testing.T,
	pool *pgxpool.Pool,
) (edgedeployment.Actor, *edgedeployment.Store) {
	t.Helper()
	platformScopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	username := "publication-operator-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Publication operator','unused')`, []any{userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScopeID, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_owner','Publication operator',true)`, []any{roleID, platformScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2),($1,'certificates.manage')`, []any{roleID, edgedeployment.PermissionManage}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platformScopeID, userID, roleID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := identity.NewTokenManager("certificate-publication-integration-session-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x51}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := edgedeployment.NewIAMStoreWithClock(pool, func() time.Time { return publicationIntegrationNow }, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, platformScopeID,
		refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rawToken, _, err := tokens.Mint(userID, platformScopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := edgedeployment.NewSessionActor(
		userID, platformScopeID, edgedeployment.ScopeKindPlatform, sessionID, rawToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	return actor, store
}

func seedPublicationNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) publicationNode {
	t.Helper()
	node := publicationNode{id: uuid.New()}
	if _, err := pool.Exec(t.Context(), `
		WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
			VALUES($2,2,$5)
			ON CONFLICT(scope_id) DO UPDATE SET
				next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, node.id, scopeID,
		"publication-node-"+strings.ReplaceAll(node.id.String(), "-", "")[:12], userID, publicationIntegrationNow); err != nil {
		t.Fatal(err)
	}
	public, private := generatePublicationRecipient(t)
	node.recipientID = seedPublicationRecipientFact(t, pool, node.id, userID, public, "active")
	node.privateKey = private
	return node
}

func rotatePublicationNodeKey(
	t *testing.T,
	pool *pgxpool.Pool,
	node publicationNode,
	userID uuid.UUID,
) publicationNode {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys SET status='retired',
		deactivated_at=$2,deactivation_reason='publication integration rotation' WHERE id=$1`,
		node.recipientID, publicationIntegrationNow); err != nil {
		t.Fatal(err)
	}
	public, private := generatePublicationRecipient(t)
	node.recipientID = seedPublicationRecipientFact(t, pool, node.id, userID, public, "active")
	node.privateKey = private
	return node
}

func generatePublicationRecipient(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	public, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	private, err := privateKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func seedPublicationRecipientFact(
	t *testing.T,
	pool *pgxpool.Pool,
	nodeID, userID uuid.UUID,
	publicKey []byte,
	status string,
) string {
	t.Helper()
	tokenID, authorizationID, requestID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256(publicKey)
	keyID := "x25519:" + hex.EncodeToString(digest[:])
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,
		 expires_at,consumed_at,consume_request_id,consume_request_digest)
		 VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6,$5,$7,$8)`, []any{
			tokenID, nodeID, publicationRandomDigest(t), userID, publicationIntegrationNow.Add(-time.Minute),
			publicationIntegrationNow.Add(time.Hour), requestID.String(), publicationRandomDigest(t),
		}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, []any{
			authorizationID, tokenID, nodeID, requestID.String(), publicationRandomDigest(t), publicationIntegrationNow.Add(-30 * time.Second),
		}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,
		 token_hash,csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,
		 protocol_max_major,protocol_max_minor,selected_protocol_major,selected_protocol_minor,
		 capabilities_snapshot,capabilities_sha256,gateway_workload_identity,gateway_instance_id,
		 artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6,$7,$8,$9,1,0,1,0,1,0,$10,$11,
		 'spiffe://cdnca.test/gateway','certificate-publication-integration',$12,$13,'authorized',$14,$15)`, []any{
			authorizationID, tokenID, nodeID, requestID, publicationRandomDigest(t), publicationRandomDigest(t),
			[]byte{0x30}, publicationRandomDigest(t), publicationRandomDigest(t), []byte{0x01},
			publicationRandomDigest(t), keyID, publicKey, publicationIntegrationNow.Add(-30 * time.Second),
			publicationIntegrationNow.Add(time.Hour),
		}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	activatedAt := any(nil)
	if status == "active" {
		activatedAt = publicationIntegrationNow
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_artifact_encryption_keys(
		id,node_id,authorization_id,public_key,public_key_sha256,status,created_at,activated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, keyID, nodeID, authorizationID, publicKey, digest[:], status,
		publicationIntegrationNow.Add(-time.Second), activatedAt); err != nil {
		t.Fatal(err)
	}
	if status == "active" {
		if _, err := tx.Exec(t.Context(), `UPDATE node_identity_state SET active_artifact_key_id=$2,
			authorization_revision=authorization_revision+1,updated_at=updated_at+interval '1 microsecond'
			WHERE node_id=$1`, nodeID, keyID); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return keyID
}

func projectPublicationFailure(t *testing.T, store *edgestatus.Store, deployment edgedeployment.Deployment) {
	t.Helper()
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
	}
	for index, state := range states {
		causationID := deployment.Command.Event.EventId
		status := &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{
				EventId: uuid.NewString(), RequestId: deployment.Command.Event.RequestId,
				OccurredTime: timestamppb.New(publicationIntegrationNow), CausationId: &causationID,
				CorrelationId: deployment.Command.Event.CorrelationId,
			},
			DeploymentId: deployment.ID.String(), Attempt: 1,
			ConfigVersionId: deployment.Command.ConfigVersionId,
			State:           state, TransitionSequence: uint64(index + 1), RunningConfigUnchanged: state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		}
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
			status.Error = &commonv1.ProtocolError{
				Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "injected certificate activation failure",
			}
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		eventID := uuid.MustParse(status.Event.EventId)
		requestID := uuid.MustParse(status.Event.RequestId)
		configID := uuid.MustParse(status.ConfigVersionId)
		result, err := store.Project(t.Context(), edgestatus.Envelope{
			NodeID: deployment.NodeID, DeploymentID: deployment.ID, ConfigID: configID,
			EventID: eventID, RequestID: requestID, Status: status, Payload: payload, Digest: digest,
		})
		if err != nil || result.Outcome != edgestatus.OutcomeAdvanced {
			t.Fatalf("project publication failure state=%s result=%+v error=%v", state, result, err)
		}
	}
}

func assertPublicationArtifacts(
	t *testing.T,
	pool *pgxpool.Pool,
	rollout edgedeployment.Rollout,
	nodes []publicationNode,
	privateKeyPEM []byte,
) {
	t.Helper()
	if len(rollout.Deployments) != len(nodes) {
		t.Fatalf("deployment count=%d want=%d", len(rollout.Deployments), len(nodes))
	}
	nodesByID := make(map[uuid.UUID]publicationNode, len(nodes))
	for _, node := range nodes {
		nodesByID[node.id] = node
	}
	seenWire := make(map[string]struct{}, len(nodes))
	for _, deployment := range rollout.Deployments {
		node, ok := nodesByID[deployment.NodeID]
		if !ok {
			t.Fatalf("deployment references unknown node %s", deployment.NodeID)
		}
		descriptor := deployment.Command.Artifacts[0]
		if descriptor.GetRecipientKeyId() != node.recipientID || descriptor.ArtifactId == "" {
			t.Fatalf("artifact descriptor=%+v node=%+v", descriptor, node)
		}
		artifactID := uuid.MustParse(descriptor.ArtifactId)
		var wire []byte
		if err := pool.QueryRow(t.Context(), `SELECT wire_bytes FROM configuration_artifacts
			WHERE config_version_id=$1 AND id=$2`, rollout.ConfigVersionID, artifactID).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seenWire[string(wire)]; duplicate {
			t.Fatal("recipient-specific artifacts reused ciphertext")
		}
		seenWire[string(wire)] = struct{}{}
		metadata := artifactMetadata{
			EventID: deployment.Command.Event.EventId, DeploymentID: deployment.Command.DeploymentId,
			Attempt: deployment.Command.Attempt, ConfigVersionID: deployment.Command.ConfigVersionId,
			ArtifactID: descriptor.ArtifactId, RecipientKeyID: descriptor.GetRecipientKeyId(),
			Kind: descriptor.Kind, SizeBytes: descriptor.SizeBytes, SigningKeyID: descriptor.SigningKeyId,
			SignatureAlgorithm: descriptor.SignatureAlgorithm, Compression: descriptor.Compression,
			MediaType: descriptor.MediaType, EncryptionAlgorithm: descriptor.EncryptionAlgorithm,
		}
		info, aad := frozenConsumerContext(t, metadata)
		plaintext := decryptFrozenArtifact(t, node.privateKey, wire, info, aad)
		var document struct {
			Bundle struct {
				Bindings []struct {
					PrivateKeyPEM string `json:"private_key_pem"`
				} `json:"bindings"`
			} `json:"bundle"`
		}
		if err := json.Unmarshal(plaintext, &document); err != nil {
			clearBytes(plaintext)
			t.Fatal(err)
		}
		if len(document.Bundle.Bindings) != 1 ||
			document.Bundle.Bindings[0].PrivateKeyPEM != string(privateKeyPEM) ||
			bytes.Contains(wire, privateKeyPEM) {
			t.Fatal("certificate private key was missing from plaintext or exposed in ciphertext")
		}
		clearBytes(plaintext)
	}
}

func assertNoSecretConfigState(t *testing.T, pool *pgxpool.Pool, nodes []publicationNode) {
	t.Helper()
	for _, node := range nodes {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_state WHERE node_id=$1`, node.id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("secret publication created node_config_state for %s", node.id)
		}
	}
}

func assertReplacementRollback(
	t *testing.T,
	pool *pgxpool.Pool,
	originalRolloutID uuid.UUID,
	wantRevision int64,
	idempotencyKey string,
) {
	t.Helper()
	var revision, requests int64
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT revision FROM rollouts WHERE id=$1),
		(SELECT count(*) FROM edge_rollout_write_requests WHERE idempotency_key=$2)`,
		originalRolloutID, idempotencyKey).Scan(&revision, &requests); err != nil {
		t.Fatal(err)
	}
	if revision != wantRevision || requests != 0 {
		t.Fatalf("replacement rollback revision/requests=%d/%d want=%d/0", revision, requests, wantRevision)
	}
}

func assertPublicationSensitiveValuesAbsent(t *testing.T, pool *pgxpool.Pool, privateKey []byte) {
	t.Helper()
	queries := []string{
		`SELECT canonical_snapshot FROM config_versions`,
		`SELECT wire_bytes FROM configuration_artifacts`,
		`SELECT payload FROM edge_command_outbox`,
		`SELECT payload::text::bytea FROM audit_events`,
		`SELECT private_key_ciphertext FROM certificate_asset_private_key_envelope_facts`,
	}
	for _, query := range queries {
		rows, err := pool.Query(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var value []byte
			if err := rows.Scan(&value); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if bytes.Contains(value, privateKey) || bytes.Contains(bytes.ToLower(value), []byte("private_key_pem")) {
				rows.Close()
				t.Fatalf("sensitive publication value found for query %q", query)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
}

func issuePublicationCertificate(t *testing.T, domain string, extraDomains ...string) ([]byte, []byte) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Certificate Publication Root"},
		NotBefore: publicationIntegrationNow.Add(-24 * time.Hour),
		NotAfter:  publicationIntegrationNow.Add(365 * 24 * time.Hour),
		IsCA:      true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: domain}, DNSNames: append([]string{domain}, extraDomains...),
		NotBefore: publicationIntegrationNow.Add(-time.Hour), NotAfter: publicationIntegrationNow.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return certificatePEM, privatePEM
}

func sealIntegrationEnvelope(
	envelopeContext certificateasset.PrivateKeyEnvelopeContext,
	plaintext []byte,
	keyID string,
) (certificateasset.PrivateKeyEnvelope, error) {
	aad, err := envelopeContext.CanonicalAAD()
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	aead, err := integrationEnvelopeAEAD(keyID)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	return certificateasset.PrivateKeyEnvelope{
		KeyID: keyID, Ciphertext: aead.Seal(nil, nonce, plaintext, aad), Nonce: nonce,
		Metadata: []byte(`{"algorithm":"aes-256-gcm","provider":"certificate-publication-integration"}`),
	}, nil
}

func integrationEnvelopeAEAD(keyID string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("certificate-publication-integration-envelope:" + keyID))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func publicationRandomDigest(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, sha256.Size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func openPublicationIntegrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "certificate_publication_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^certificate_publication_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe integration schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.MaxConns = 6
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop publication integration schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
