//go:build integration

package pluginwebhookruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	runtimeDatabaseEnv  = "CDNCA_PLUGIN_WEBHOOK_RUNTIME_DATABASE_URL"
	runtimeNATSEnv      = "CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_URL"
	runtimeNATSCredsEnv = "CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_CREDS_FILE"
	runtimeNATSCAEnv    = "CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_CA_FILE"
)

func TestRuntimeNATSOptionsTLSCredentials(t *testing.T) {
	url := strings.TrimSpace(os.Getenv(runtimeNATSEnv))
	credentialsFile := strings.TrimSpace(os.Getenv(runtimeNATSCredsEnv))
	caFile := strings.TrimSpace(os.Getenv(runtimeNATSCAEnv))
	if url == "" || credentialsFile == "" || caFile == "" {
		t.Skipf("%s, %s, and %s are required", runtimeNATSEnv, runtimeNATSCredsEnv, runtimeNATSCAEnv)
	}
	if anonymous, err := nats.Connect(url, nats.RootCAs(caFile), nats.Timeout(time.Second), nats.NoReconnect()); err == nil {
		anonymous.Close()
		t.Fatal("TLS NATS accepted an anonymous connection")
	}
	config := Config{
		OperationTimeout: time.Second, NATSCredsFile: credentialsFile, NATSCAFile: caFile,
		NATSReconnectMin: 250 * time.Millisecond, NATSReconnectMax: 2 * time.Second,
	}
	connection, err := nats.Connect(url, runtimeNATSOptions(config, "cdnca-plugin-webhook-runtime-tls-test")...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	if !connection.TLSRequired() {
		t.Fatal("NATS server did not require TLS")
	}
	if err := connection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
}

type integrationDeliverer struct {
	mu            sync.Mutex
	items         []pluginwebhook.QueueItem
	secretLengths []int
	secrets       [][]byte
	result        pluginwebhook.SendResult
}

type blockingPublishJetStream struct {
	nats.JetStreamContext
	subject string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type publishReturnBlockJetStream struct {
	nats.JetStreamContext
	subject string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type postBindDriftJetStream struct {
	nats.JetStreamContext
	config       JetStreamConfig
	once         sync.Once
	subscription *nats.Subscription
}

type unknownDLQPublishJetStream struct {
	nats.JetStreamContext
	config            Config
	targetMessageID   string
	fillerBefore      int
	fillerAfter       int
	once              sync.Once
	publishedSequence uint64
	injectedErr       error
}

type blockedLostAckDeliveryJetStream struct {
	nats.JetStreamContext
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type recoverableDLQPublishJetStream struct {
	nats.JetStreamContext
	subject string

	mu       sync.Mutex
	failing  bool
	attempts int
}

type recoverableDLQReadJetStream struct {
	nats.JetStreamContext
	stream string

	mu       sync.Mutex
	failing  bool
	attempts int
}

type connectionClosingDeliverer struct {
	*integrationDeliverer
	close func()
}

type bytesAndErrorSecretProvider struct {
	secret []byte
}

func (provider *bytesAndErrorSecretProvider) Secret(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) ([]byte, error) {
	return provider.secret, errors.New("simulated secret provider failure")
}

func (provider *bytesAndErrorSecretProvider) SecretTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID) ([]byte, error) {
	return provider.secret, errors.New("simulated secret provider failure")
}

func (jetstream *blockingPublishJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	if message.Subject == jetstream.subject {
		jetstream.once.Do(func() { close(jetstream.started) })
		<-jetstream.release
	}
	return jetstream.JetStreamContext.PublishMsg(message, options...)
}

func (jetstream *publishReturnBlockJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	ack, err := jetstream.JetStreamContext.PublishMsg(message, options...)
	if message.Subject == jetstream.subject {
		jetstream.once.Do(func() { close(jetstream.started) })
		<-jetstream.release
	}
	return ack, err
}

func (jetstream *postBindDriftJetStream) PullSubscribe(subject, durable string, options ...nats.SubOpt) (*nats.Subscription, error) {
	subscription, err := jetstream.JetStreamContext.PullSubscribe(subject, durable, options...)
	if err != nil {
		return nil, err
	}
	jetstream.subscription = subscription
	jetstream.once.Do(func() {
		drift := *consumerConfig(jetstream.config)
		drift.Description = "deterministic post-bind drift"
		_, err = jetstream.JetStreamContext.UpdateConsumer(jetstream.config.DeliveryStream, &drift)
	})
	return subscription, err
}

func (jetstream *unknownDLQPublishJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	triggered := false
	jetstream.once.Do(func() {
		if message.Header.Get(nats.MsgIdHdr) != jetstream.targetMessageID {
			return
		}
		triggered = true
		last, err := publishStrictDLQFillersRaw(jetstream.JetStreamContext, jetstream.config, 20000, jetstream.fillerBefore)
		if err != nil {
			jetstream.injectedErr = err
			return
		}
		wire := &nats.Msg{Subject: message.Subject, Data: append([]byte(nil), message.Data...), Header: cloneNATSHeader(message.Header)}
		wire.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(last, 10))
		ack, err := jetstream.JetStreamContext.PublishMsg(wire,
			nats.ExpectStream(jetstream.config.JetStream.DeadLetterStream), nats.ExpectLastSequence(last))
		if err != nil || ack == nil || ack.Sequence != last+1 {
			jetstream.injectedErr = fmt.Errorf("commit unknown DLQ target: acknowledgement=%+v error=%v", ack, err)
			return
		}
		jetstream.publishedSequence = ack.Sequence
		_, jetstream.injectedErr = publishStrictDLQFillersRaw(jetstream.JetStreamContext, jetstream.config,
			21000, jetstream.fillerAfter)
	})
	if triggered {
		if jetstream.injectedErr != nil {
			return nil, jetstream.injectedErr
		}
		return nil, errors.New("simulated plugin webhook DLQ PubAck loss")
	}
	return jetstream.JetStreamContext.PublishMsg(message, options...)
}

func (jetstream *blockedLostAckDeliveryJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	triggered := false
	if message.Header.Get(deliveryRecoveryEpochHeader) != "" {
		jetstream.once.Do(func() { triggered = true })
	}
	if !triggered {
		return jetstream.JetStreamContext.PublishMsg(message, options...)
	}
	ack, err := jetstream.JetStreamContext.PublishMsg(message, options...)
	if err != nil {
		return ack, err
	}
	close(jetstream.started)
	<-jetstream.release
	return nil, errors.New("simulated delivery recovery PubAck loss")
}

func (jetstream *recoverableDLQPublishJetStream) PublishMsg(message *nats.Msg, options ...nats.PubOpt) (*nats.PubAck, error) {
	if message.Subject != jetstream.subject {
		return jetstream.JetStreamContext.PublishMsg(message, options...)
	}
	jetstream.mu.Lock()
	jetstream.attempts++
	failing := jetstream.failing
	jetstream.mu.Unlock()
	if failing {
		return nil, errors.New("simulated recoverable DLQ publish failure")
	}
	return jetstream.JetStreamContext.PublishMsg(message, options...)
}

func (jetstream *recoverableDLQPublishJetStream) setFailing(value bool) {
	jetstream.mu.Lock()
	jetstream.failing = value
	jetstream.mu.Unlock()
}

func (jetstream *recoverableDLQPublishJetStream) attemptCount() int {
	jetstream.mu.Lock()
	defer jetstream.mu.Unlock()
	return jetstream.attempts
}

func (jetstream *recoverableDLQReadJetStream) GetMsg(stream string, sequence uint64,
	options ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	if stream == jetstream.stream {
		jetstream.mu.Lock()
		jetstream.attempts++
		failing := jetstream.failing
		jetstream.mu.Unlock()
		if failing {
			return nil, errors.New("simulated recoverable DLQ read failure")
		}
	}
	return jetstream.JetStreamContext.GetMsg(stream, sequence, options...)
}

func (jetstream *recoverableDLQReadJetStream) setFailing(value bool) {
	jetstream.mu.Lock()
	jetstream.failing = value
	jetstream.mu.Unlock()
}

func (jetstream *recoverableDLQReadJetStream) attemptCount() int {
	jetstream.mu.Lock()
	defer jetstream.mu.Unlock()
	return jetstream.attempts
}

func (deliverer *connectionClosingDeliverer) DeliverV2(ctx context.Context, item pluginwebhook.QueueItem,
	attempt uint64, secret []byte) pluginwebhook.SendResult {
	result := deliverer.integrationDeliverer.DeliverV2(ctx, item, attempt, secret)
	if deliverer.close != nil {
		deliverer.close()
	}
	return result
}

func (deliverer *integrationDeliverer) Deliver(_ context.Context, item pluginwebhook.QueueItem, _ uint64) pluginwebhook.SendResult {
	deliverer.mu.Lock()
	defer deliverer.mu.Unlock()
	deliverer.items = append(deliverer.items, item)
	return deliverer.result
}

func (deliverer *integrationDeliverer) DeliverV2(_ context.Context, item pluginwebhook.QueueItem, _ uint64, secret []byte) pluginwebhook.SendResult {
	deliverer.mu.Lock()
	defer deliverer.mu.Unlock()
	deliverer.items = append(deliverer.items, item)
	deliverer.secretLengths = append(deliverer.secretLengths, len(secret))
	deliverer.secrets = append(deliverer.secrets, secret)
	return deliverer.result
}

func (deliverer *integrationDeliverer) setResult(result pluginwebhook.SendResult) {
	deliverer.mu.Lock()
	deliverer.result = result
	deliverer.mu.Unlock()
}

func (deliverer *integrationDeliverer) snapshot() []pluginwebhook.QueueItem {
	deliverer.mu.Lock()
	defer deliverer.mu.Unlock()
	return append([]pluginwebhook.QueueItem(nil), deliverer.items...)
}

func (deliverer *integrationDeliverer) assertSecretsCleared(t *testing.T) {
	t.Helper()
	deliverer.mu.Lock()
	defer deliverer.mu.Unlock()
	for index, secret := range deliverer.secrets {
		if deliverer.secretLengths[index] != 32 || !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("prepared secret %d length/clear contract failed", index)
		}
	}
}

type runtimeIntegrationFixture struct {
	admin           *pgxpool.Pool
	pool            *pgxpool.Pool
	connection      *nats.Conn
	jetstream       nats.JetStreamContext
	jetstreamConfig JetStreamConfig
	keyring         runtimeIntegrationKeyring
	store           *pluginwebhookcontrol.Store
	secrets         *pluginwebhookcontrol.RuntimeSecretProvider
	actor           pluginwebhookcontrol.Actor
	tenantID        uuid.UUID
	targetScope     uuid.UUID
}

type runtimeIntegrationKeyring struct {
	active pluginwebhookcontrol.WrappingKey
}

func (keyring runtimeIntegrationKeyring) Active(context.Context) (pluginwebhookcontrol.WrappingKey, error) {
	return keyring.active, nil
}

func (keyring runtimeIntegrationKeyring) Lookup(_ context.Context, id string) ([32]byte, error) {
	if id != keyring.active.ID {
		return [32]byte{}, pluginwebhookcontrol.ErrSecretUnavailable
	}
	return keyring.active.Key, nil
}

func newRuntimeIntegrationFixture(t *testing.T) *runtimeIntegrationFixture {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv(runtimeDatabaseEnv))
	natsURL := strings.TrimSpace(os.Getenv(runtimeNATSEnv))
	if databaseURL == "" || natsURL == "" {
		t.Skip(runtimeDatabaseEnv + " and " + runtimeNATSEnv + " are required")
	}
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if poolConfig.ConnConfig.Host == "" || poolConfig.ConnConfig.Host[0] != '/' {
		t.Fatalf("runtime smoke requires PostgreSQL Unix socket, got host %q", poolConfig.ConnConfig.Host)
	}
	admin, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	schema := "plugin_webhook_runtime_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	jetstreamConfig := DefaultJetStreamConfig()
	jetstreamConfig.DeliveryStream = "PWH_DELIVERY_" + suffix
	jetstreamConfig.DeliveryDurable = "pwh_runtime_" + suffix
	jetstreamConfig.DeliverySubjectPrefix = "cdnca.test.plugin_webhook.delivery." + suffix
	jetstreamConfig.ReadinessMaxPending = 1
	provisionRuntimeJetStream(t, jetstream, jetstreamConfig)
	keyring := runtimeIntegrationKeyring{active: pluginwebhookcontrol.WrappingKey{
		ID: "plugin-webhook-runtime-kek-v1", Key: [32]byte{1, 2, 3, 4},
	}}
	secrets, err := pluginwebhookcontrol.NewRuntimeSecretProvider(pool, keyring)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &runtimeIntegrationFixture{
		admin: admin, pool: pool, connection: connection, jetstream: jetstream,
		jetstreamConfig: jetstreamConfig, keyring: keyring, secrets: secrets,
	}
	t.Cleanup(func() {
		connection.Close()
		pool.Close()
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	t.Cleanup(func() { deleteRuntimeJetStream(t, fixture) })
	return fixture
}

func provisionRuntimeJetStream(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	if _, err := jetstream.AddStream(deliveryStreamConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddStream(deadLetterStreamConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err := jetstream.AddConsumer(config.DeliveryStream, consumerConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
}

func (fixture *runtimeIntegrationFixture) runtimeConfig() Config {
	return Config{
		Pool: fixture.pool, NATS: fixture.connection, JetStream: fixture.jetstreamConfig,
		PollInterval: 20 * time.Millisecond, OperationTimeout: time.Second,
		LeaseDuration: time.Second, ClaimTimeout: 5 * time.Second, ShutdownTimeout: 5 * time.Second,
		AttestationKeyID: runtimeTestAttestationKeyID, AttestationKey: runtimeTestAttestationKey,
	}
}

const runtimeTestAttestationKeyID = "plugin-webhook-runtime-test-key-1"

var runtimeTestAttestationKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, ed25519.SeedSize))

func (fixture *runtimeIntegrationFixture) installControl(t *testing.T) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, targetScope, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if tenantID == targetScope {
		t.Fatal("test requires distinct public tenant and target scope identities")
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Plugin runtime integration')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{targetScope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Runtime operator','unused')`, []any{userID, "plugin-runtime-" + strings.ReplaceAll(userID.String(), "-", "")[:16]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{targetScope, userID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','owner',true)`, []any{roleID, targetScope}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{targetScope, userID, roleID}},
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("r", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(userID, targetScope, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	refresh := sha256.Sum256(sessionID[:])
	if _, err = fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, targetScope,
		refresh[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x84}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	guard := installRuntimeEntitlement(t, fixture.pool, now)
	fixture.store, err = pluginwebhookcontrol.NewStore(fixture.pool, iam, guard, fixture.keyring, pluginwebhookcontrol.NewTargetValidator())
	if err != nil {
		t.Fatal(err)
	}
	fixture.actor, err = pluginwebhookcontrol.NewActor(userID, targetScope, targetScope, pluginwebhookcontrol.ScopeTenant, raw)
	if err != nil {
		t.Fatal(err)
	}
	fixture.tenantID, fixture.targetScope = tenantID, targetScope
}

type runtimeEntitlementSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer runtimeEntitlementSigner) KeyID() string { return signer.id }
func (signer runtimeEntitlementSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func installRuntimeEntitlement(t *testing.T, pool *pgxpool.Pool, now time.Time) *entitlementguard.Guard {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(24 * time.Hour)
	signer := runtimeEntitlementSigner{id: "plugin-runtime-test-key", private: private}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.id, PublicKey: public, NotBefore: now.Add(-24 * time.Hour), SignUntil: &until, VerifyUntil: &until,
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyFingerprint := sha256.Sum256(public)
	keysetPayload := []byte(fmt.Sprintf(
		`{"schema":"cdnca.signing-keyset/v2","active_key_id":%q,"keys":[`+
			`{"key_id":%q,"algorithm":"Ed25519","public_key":%q,"fingerprint":%q,`+
			`"status":"active","not_before":%q,"sign_until":%q,"verify_until":%q}],"rotations":[]}`,
		signer.id, signer.id, base64.RawURLEncoding.EncodeToString(public),
		base64.RawURLEncoding.EncodeToString(keyFingerprint[:]), now.Add(-24*time.Hour).Format(time.RFC3339Nano),
		until.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)))
	keysetDigest := sha256.Sum256(keysetPayload)
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(
		singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at
	) VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`,
		`"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, signer.id,
		keysetPayload, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(
		key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at
	) VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, public, now.Add(-24*time.Hour),
		until, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	const customer = "11111111-1111-4111-8111-111111111111"
	const installation = "22222222-2222-4222-8222-222222222222"
	const license = "33333333-3333-4333-8333-333333333333"
	issuedAt := now.Add(-time.Minute)
	revocation, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: customer, InstallationID: installation, LicenseID: license, Revision: 1,
		IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{NotBefore: now.Add(-time.Hour), SignUntil: &until, VerifyUntil: &until})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := revocation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), artifact, now); err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: customer, InstallationID: installation, LicenseID: license, Serial: 1,
		NotBefore: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: []entitlement.Feature{{Code: entitlementguard.FeatureExtensionsWebhooks}},
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaExtensionsWebhooksCount, Limit: 100}},
	}
	signed, err := entitlement.Sign(t.Context(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: installation, SignedLease: signed,
	}, now); err != nil {
		t.Fatal(err)
	}
	return entitlementguard.NewGuard(pool, func() time.Time { return now }, trust)
}

func TestRuntimePGSocketNATSFileLifecycle(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	deliverer := &integrationDeliverer{result: pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}}

	startup, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- startup.Run(runCtx) }()
	time.Sleep(100 * time.Millisecond)
	if err := startup.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("unmigrated startup readiness = %v", err)
	}
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	waitRuntimeCondition(t, 10*time.Second, func() bool { return startup.Ready() == nil }, "runtime readiness after fresh 084 migration")
	cancel()
	if err := startup.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-runErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	fixture.installControl(t)
	runtime, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if err := runtime.probeReadiness(t.Context()); err != nil {
		t.Fatal(err)
	}

	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Runtime", TargetURL: "https://runtime.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "runtime-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRuntimeSecret(t, fixture.secrets, fixture.targetScope, created.Value.Subscription.ID,
		created.Value.Subscription.ActiveSecretVersionID, created.Value.Secret)
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
	items := deliverer.snapshot()
	if len(items) != 1 || items[0].TargetScopeID != fixture.targetScope || items[0].TenantID != fixture.tenantID ||
		items[0].TargetScopeID == items[0].TenantID || items[0].SecretVersionID != created.Value.Subscription.ActiveSecretVersionID {
		t.Fatalf("first runtime item identity = %+v", items)
	}
	testClaimBeforeRotationReclaimsActiveSecret(t, fixture, runtime)

	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		rotation.Value.RotationID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-activate-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if secret, secretErr := fixture.secrets.Secret(t.Context(), fixture.targetScope, created.Value.Subscription.ID,
		created.Value.Subscription.ActiveSecretVersionID); secret != nil || !errors.Is(secretErr, pluginwebhookcontrol.ErrSecretUnavailable) {
		returned := secret != nil
		clearSecret(secret)
		t.Fatalf("retired runtime secret returned = %t, error = %v", returned, secretErr)
	}
	assertRuntimeSecret(t, fixture.secrets, fixture.targetScope, created.Value.Subscription.ID,
		rotation.Value.RotationID, rotation.Value.Secret)
	rotatedDelivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-test-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, rotatedDelivery.Value.Delivery.ID, "delivered")
	items = deliverer.snapshot()
	if len(items) != 2 || items[1].SecretVersionID != rotation.Value.RotationID {
		t.Fatalf("rotated runtime item = %+v", items)
	}

	revokedDelivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-test-3"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-revoke-1", Revision: 2}); err != nil {
		t.Fatal(err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, revokedDelivery.Value.Delivery.ID, "revoked")
	if len(deliverer.snapshot()) != 2 {
		t.Fatal("revoked queued delivery reached HTTP deliverer")
	}

	recoverySubscription := testRecoverClaimBindsDelivery(t, fixture, runtime)
	testOutboxDedupeAndDLQ(t, fixture, runtime, deliverer, recoverySubscription)
	testDeadLetterPublishDoesNotHoldPGLocks(t, fixture, runtime, deliverer)
	testDeadLetterIdentityAndWireContract(t, fixture, runtime)
	testRevokeDuringOutboxPublish(t, fixture, runtime)
	testConcurrentOutboxPublishers(t, fixture, runtime, deliverer, recoverySubscription)
	testConcurrentDeadLetterPublishers(t, fixture, runtime)
	testReadinessLagRecovery(t, fixture, runtime, deliverer)
	testMalformedResponseDigestFailsClosed(t, fixture, runtime, deliverer)
	testOutcomeFailureNAK(t, fixture, runtime, deliverer, recoverySubscription)
	runtime = testOutboxLeaseRestartRecovery(t, fixture, runtime, deliverer, recoverySubscription)
	deliverer.assertSecretsCleared(t)

	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeReadinessFailsClosedOnDLQRecoveryErrorAndRecovers(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	config.PollInterval = 10 * time.Millisecond
	runtime, err := Open(t.Context(), config, Dependencies{
		Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	row := createPendingDeadLetter(t, fixture, runtime, "readiness-recovery")
	jetstream := &recoverableDLQPublishJetStream{
		JetStreamContext: runtime.jetstream,
		subject:          config.JetStream.DeadLetterSubject,
		failing:          true,
	}
	runtime.jetstream = jetstream

	if err = runtime.reconcileDeadLetters(t.Context()); err == nil {
		t.Fatal("DLQ recovery error was swallowed")
	}
	runCtx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- runtime.Run(runCtx) }()
	waitRuntimeCondition(t, 3*time.Second, func() bool { return jetstream.attemptCount() >= 3 },
		"repeated failed DLQ recovery attempts")
	if err = runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("runtime readiness during DLQ recovery error = %v", err)
	}

	jetstream.setFailing(false)
	waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.Ready() == nil },
		"runtime readiness after DLQ recovery")
	assertDeadLetterState(t, fixture.pool, row, "acknowledged", 0)
	cancel()
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = <-runErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRuntimeReadinessFailsClosedAcrossDLQRecoveryFaults(t *testing.T) {
	t.Run("persistent broker read", func(t *testing.T) {
		fixture, runtime, rows := newPendingDLQRuntime(t, "read-fault")
		publishStrictDLQFillers(t, fixture.jetstream, runtime.config, 30000, 1)
		jetstream := &recoverableDLQReadJetStream{
			JetStreamContext: runtime.jetstream,
			stream:           runtime.config.JetStream.DeadLetterStream,
			failing:          true,
		}
		runtime.jetstream = jetstream
		startRuntimeLoop(t, runtime)
		waitRuntimeCondition(t, 3*time.Second, func() bool { return jetstream.attemptCount() >= 2 },
			"persistent DLQ read failure")
		if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("runtime readiness during DLQ read failure = %v", err)
		}
		jetstream.setFailing(false)
		waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.Ready() == nil },
			"runtime readiness after DLQ read recovery")
		assertDeadLetterState(t, fixture.pool, rows[0], "acknowledged", 0)
	})

	t.Run("persistent PG acknowledgement", func(t *testing.T) {
		fixture, runtime, rows := newPendingDLQRuntime(t, "ack-fault")
		if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION plugin_webhook_test_fail_dlq_ack_084()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				RAISE EXCEPTION 'simulated persistent DLQ acknowledgement failure';
			END;
			$$`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `CREATE TRIGGER plugin_webhook_test_fail_dlq_ack_084
			BEFORE UPDATE OF publish_state ON plugin_webhook_dead_letters
			FOR EACH ROW WHEN (NEW.publish_state = 'acknowledged')
			EXECUTE FUNCTION plugin_webhook_test_fail_dlq_ack_084()`); err != nil {
			t.Fatal(err)
		}
		jetstream := &recoverableDLQReadJetStream{
			JetStreamContext: runtime.jetstream,
			stream:           runtime.config.JetStream.DeadLetterStream,
		}
		runtime.jetstream = jetstream
		startRuntimeLoop(t, runtime)
		waitRuntimeCondition(t, 3*time.Second, func() bool { return jetstream.attemptCount() >= 2 },
			"persistent DLQ acknowledgement failure")
		if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("runtime readiness during DLQ acknowledgement failure = %v", err)
		}
		attemptsAfterException := jetstream.attemptCount()
		if _, err := fixture.pool.Exec(t.Context(), `CREATE OR REPLACE FUNCTION plugin_webhook_test_fail_dlq_ack_084()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				RETURN NULL;
			END;
			$$`); err != nil {
			t.Fatal(err)
		}
		waitRuntimeCondition(t, 3*time.Second, func() bool {
			return jetstream.attemptCount() >= attemptsAfterException+2
		}, "persistent DLQ zero-row acknowledgement CAS")
		if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("runtime readiness during zero-row DLQ acknowledgement CAS = %v", err)
		}
		assertDeadLetterState(t, fixture.pool, rows[0], "pending", 0)
		if _, err := fixture.pool.Exec(t.Context(), `CREATE OR REPLACE FUNCTION plugin_webhook_test_fail_dlq_ack_084()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				RETURN NEW;
			END;
			$$`); err != nil {
			t.Fatal(err)
		}
		waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.Ready() == nil },
			"runtime readiness after DLQ acknowledgement recovery")
		assertDeadLetterState(t, fixture.pool, rows[0], "acknowledged", 0)
	})

	t.Run("illegal row does not starve safe batch", func(t *testing.T) {
		fixture, runtime, rows := newPendingDLQRuntime(t, "illegal-first", "safe-second")
		stream, err := runtime.deadLetterStreamSnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var failedAt time.Time
		if err = fixture.pool.QueryRow(t.Context(), `SELECT failed_at FROM plugin_webhook_dead_letters
			WHERE delivery_id=$1`, rows[0].delivery).Scan(&failedAt); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.pool.Exec(t.Context(), `ALTER TABLE plugin_webhook_dead_letters
			DROP CONSTRAINT plugin_webhook_dead_letters_reconcile_084_check`); err != nil {
			t.Fatal(err)
		}
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err = tx.Exec(t.Context(), `ALTER TABLE plugin_webhook_dead_letters DISABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_dead_letters
			SET failed_at=$2::timestamptz-interval '1 day',reconcile_phase='publish_ready',
				reconcile_stream_created_unix_nano=$3::numeric,
				reconcile_high_watermark=$4::numeric,reconcile_scan_boundary=NULL,reconcile_cursor=NULL
			WHERE delivery_id=$1`, rows[0].delivery, failedAt, stream.epoch,
			"18446744073709551616"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `ALTER TABLE plugin_webhook_dead_letters ENABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		reconcileErr := runtime.reconcileDeadLetters(t.Context())
		if reconcileErr == nil || !strings.Contains(reconcileErr.Error(), "value out of range") {
			t.Fatalf("malformed numeric DLQ load error = %v", reconcileErr)
		}
		var safeState string
		if err = fixture.pool.QueryRow(t.Context(), `SELECT publish_state FROM plugin_webhook_dead_letters
			WHERE delivery_id=$1`, rows[1].delivery).Scan(&safeState); err != nil {
			t.Fatal(err)
		}
		if safeState != "acknowledged" {
			t.Fatalf("safe DLQ behind malformed numeric row = %s", safeState)
		}
		startRuntimeLoop(t, runtime)
		waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.Ready() != nil },
			"runtime readiness after malformed numeric DLQ load")
		if err = runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
			t.Fatalf("runtime readiness with illegal DLQ state = %v", err)
		}
		tx, err = fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err = tx.Exec(t.Context(), `ALTER TABLE plugin_webhook_dead_letters DISABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `UPDATE plugin_webhook_dead_letters
			SET failed_at=$2,reconcile_phase='uninitialized',reconcile_stream_created_unix_nano=NULL,
				reconcile_high_watermark=NULL,reconcile_scan_boundary=NULL,reconcile_cursor=NULL
			WHERE delivery_id=$1`, rows[0].delivery, failedAt); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(t.Context(), `ALTER TABLE plugin_webhook_dead_letters ENABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.Ready() == nil },
			"runtime readiness after illegal DLQ state recovery")
		assertDeadLetterState(t, fixture.pool, rows[0], "acknowledged", 0)
	})
}

func TestEnsureJetStreamRequiresPrecreatedResources(t *testing.T) {
	natsURL := strings.TrimSpace(os.Getenv(runtimeNATSEnv))
	if natsURL == "" {
		t.Skip(runtimeNATSEnv + " is required")
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	config := DefaultJetStreamConfig()
	config.DeliveryStream = "PWH_VERIFY_" + suffix
	config.DeliveryDurable = "pwh_verify_" + suffix
	config.DeliverySubjectPrefix = "cdnca.test.plugin_webhook.verify." + suffix
	config.OperationTimeout = time.Second
	cleanupRuntimeJetStreamResources(t, jetstream, config)

	if err = EnsureJetStream(t.Context(), connection, config); err == nil {
		t.Fatal("EnsureJetStream created missing resources")
	}
	assertRuntimeStreamMissing(t, jetstream, config.DeliveryStream)
	assertRuntimeStreamMissing(t, jetstream, config.DeadLetterStream)

	if _, err = jetstream.AddStream(deliveryStreamConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err = EnsureJetStream(t.Context(), connection, config); err == nil {
		t.Fatal("EnsureJetStream created missing dead-letter stream")
	}
	assertRuntimeStreamMissing(t, jetstream, config.DeadLetterStream)

	if _, err = jetstream.AddStream(deadLetterStreamConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err = EnsureJetStream(t.Context(), connection, config); err == nil {
		t.Fatal("EnsureJetStream created missing durable consumer")
	}
	if _, err = jetstream.ConsumerInfo(config.DeliveryStream, config.DeliveryDurable, nats.Context(t.Context())); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("missing consumer lookup error = %v", err)
	}

	if _, err = jetstream.AddConsumer(config.DeliveryStream, consumerConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err = EnsureJetStream(t.Context(), connection, config); err != nil {
		t.Fatal(err)
	}
	bindDrift := *consumerConfig(config)
	bindDrift.Description = "drift after startup verification"
	if _, err = jetstream.UpdateConsumer(config.DeliveryStream, &bindDrift, nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	bound, bindErr := newRuntimeConsumer(connection, config)
	if bindErr == nil {
		_ = bound.Close()
		t.Fatal("consumer bind accepted configuration drift after startup verification")
	}
	if _, err = jetstream.UpdateConsumer(config.DeliveryStream, consumerConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	drifting := &postBindDriftJetStream{JetStreamContext: jetstream, config: config}
	bound, bindErr = bindRuntimeConsumer(drifting, config)
	if bindErr == nil {
		_ = bound.Close()
		t.Fatal("consumer drift introduced by PullSubscribe was accepted without a post-bind check")
	}
	if drifting.subscription == nil || drifting.subscription.IsValid() {
		t.Fatal("post-bind consumer drift did not unsubscribe the local pull subscription")
	}
	if _, err = jetstream.UpdateConsumer(config.DeliveryStream, consumerConfig(config), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}

	deliveryMismatch := *deliveryStreamConfig(config)
	deliveryMismatch.NoAck = true
	deliveryRollupMismatch := *deliveryStreamConfig(config)
	deliveryRollupMismatch.AllowRollup = true
	deliverySealedMismatch := *deliveryStreamConfig(config)
	deliverySealedMismatch.Sealed = true
	deliveryTTLCodeMismatch := *deliveryStreamConfig(config)
	deliveryTTLCodeMismatch.AllowMsgTTL = true
	deliveryDenyDeleteMismatch := *deliveryStreamConfig(config)
	deliveryDenyDeleteMismatch.DenyDelete = true
	deliveryDenyPurgeMismatch := *deliveryStreamConfig(config)
	deliveryDenyPurgeMismatch.DenyPurge = true
	deliveryCompressionMismatch := *deliveryStreamConfig(config)
	deliveryCompressionMismatch.Compression = nats.S2Compression
	deliveryTransformMismatch := *deliveryStreamConfig(config)
	deliveryTransformMismatch.SubjectTransform = &nats.SubjectTransformConfig{
		Source: ">", Destination: "cdnca.transformed.>",
	}
	deliveryRepublishMismatch := *deliveryStreamConfig(config)
	deliveryRepublishMismatch.RePublish = &nats.RePublish{
		Source: ">", Destination: "cdnca.republished.>",
	}
	deliveryPerSubjectMismatch := *deliveryStreamConfig(config)
	deliveryPerSubjectMismatch.MaxMsgsPerSubject = 1
	deliveryPerSubjectMismatch.DiscardNewPerSubject = true
	deliverySourcesMismatch := *deliveryStreamConfig(config)
	deliverySourcesMismatch.Sources = []*nats.StreamSource{{Name: "PWH_VERIFY_SOURCE_" + suffix}}
	deadLetterMismatch := *deadLetterStreamConfig(config)
	deadLetterMismatch.MaxMsgsPerSubject = 1
	consumerMismatch := *consumerConfig(config)
	consumerMismatch.BackOff = []time.Duration{consumerMismatch.AckWait}
	consumerFilterSubjectsMismatch := *consumerConfig(config)
	consumerFilterSubjectsMismatch.FilterSubject = ""
	consumerFilterSubjectsMismatch.FilterSubjects = []string{config.DeliverySubjectPrefix + ".*.*"}
	consumerHeadersMismatch := *consumerConfig(config)
	consumerHeadersMismatch.HeadersOnly = true
	for _, test := range []struct {
		name       string
		delivery   *nats.StreamConfig
		deadLetter *nats.StreamConfig
		consumer   *nats.ConsumerConfig
	}{
		{name: "delivery stream behavior", delivery: &deliveryMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream rollup", delivery: &deliveryRollupMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream message ttl", delivery: &deliveryTTLCodeMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream deny delete", delivery: &deliveryDenyDeleteMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream deny purge", delivery: &deliveryDenyPurgeMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream compression", delivery: &deliveryCompressionMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream subject transform", delivery: &deliveryTransformMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream republish", delivery: &deliveryRepublishMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream discard per subject", delivery: &deliveryPerSubjectMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "delivery stream sources", delivery: &deliverySourcesMismatch, deadLetter: deadLetterStreamConfig(config), consumer: consumerConfig(config)},
		{name: "dead letter stream behavior", delivery: deliveryStreamConfig(config), deadLetter: &deadLetterMismatch, consumer: consumerConfig(config)},
		{name: "durable consumer behavior", delivery: deliveryStreamConfig(config), deadLetter: deadLetterStreamConfig(config), consumer: &consumerMismatch},
		{name: "durable consumer filter subjects", delivery: deliveryStreamConfig(config), deadLetter: deadLetterStreamConfig(config), consumer: &consumerFilterSubjectsMismatch},
		{name: "durable consumer headers only", delivery: deliveryStreamConfig(config), deadLetter: deadLetterStreamConfig(config), consumer: &consumerHeadersMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetRuntimeJetStreamResources(t, jetstream, config)
			if _, err := jetstream.AddStream(test.delivery, nats.Context(t.Context())); err != nil {
				t.Fatal(err)
			}
			if _, err := jetstream.AddStream(test.deadLetter, nats.Context(t.Context())); err != nil {
				t.Fatal(err)
			}
			if _, err := jetstream.AddConsumer(config.DeliveryStream, test.consumer, nats.Context(t.Context())); err != nil {
				t.Fatal(err)
			}
			if err := EnsureJetStream(t.Context(), connection, config); err == nil {
				t.Fatal("EnsureJetStream accepted a behaviorally mismatched precreated resource")
			}
		})
	}
	t.Run("delivery stream sealed", func(t *testing.T) {
		resetRuntimeJetStreamResources(t, jetstream, config)
		if _, err := jetstream.AddStream(deliveryStreamConfig(config), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if _, err := jetstream.UpdateStream(&deliverySealedMismatch, nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if _, err := jetstream.AddStream(deadLetterStreamConfig(config), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if _, err := jetstream.AddConsumer(config.DeliveryStream, consumerConfig(config), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if err := EnsureJetStream(t.Context(), connection, config); err == nil {
			t.Fatal("EnsureJetStream accepted a sealed delivery stream")
		}
	})
}

func assertRuntimeStreamMissing(t *testing.T, jetstream nats.JetStreamContext, stream string) {
	t.Helper()
	if _, err := jetstream.StreamInfo(stream, nats.Context(t.Context())); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("missing stream %s lookup error = %v", stream, err)
	}
}

func cleanupRuntimeJetStreamResources(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	t.Cleanup(func() {
		_ = jetstream.DeleteConsumer(config.DeliveryStream, config.DeliveryDurable, nats.Context(context.Background()))
		_ = jetstream.DeleteStream(config.DeliveryStream, nats.Context(context.Background()))
		_ = jetstream.DeleteStream(config.DeadLetterStream, nats.Context(context.Background()))
	})
}

func resetRuntimeJetStreamResources(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	if err := jetstream.DeleteConsumer(config.DeliveryStream, config.DeliveryDurable, nats.Context(t.Context())); err != nil &&
		!errors.Is(err, nats.ErrConsumerNotFound) && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal(err)
	}
	if err := jetstream.DeleteStream(config.DeliveryStream, nats.Context(t.Context())); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal(err)
	}
	if err := jetstream.DeleteStream(config.DeadLetterStream, nats.Context(t.Context())); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal(err)
	}
}

func TestRuntimeOwnedConnectionReconnectsAfterNATSServerRestart(t *testing.T) {
	serverBinary := strings.TrimSpace(os.Getenv("NATS_SERVER_BIN"))
	if serverBinary == "" {
		t.Skip("NATS_SERVER_BIN is required")
	}
	version, err := exec.Command(serverBinary, "--version").CombinedOutput()
	// The native release ships exactly this NATS (scripts/install-control.sh NATS_SERVER_VERSION).
	if err != nil || strings.TrimSpace(string(version)) != "nats-server: v2.12.15-cdnca.1" {
		t.Fatalf("NATS server must be the shipped 2.12.15-cdnca.1: version=%q error=%v", strings.TrimSpace(string(version)), err)
	}

	fixture := newRuntimeIntegrationFixture(t)
	if err = database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)

	port := 0
	serverURL := ""
	storeDirectory := t.TempDir()
	portsDirectory := t.TempDir()
	var server *exec.Cmd
	var serverLog bytes.Buffer
	stopServer := func() {
		if server == nil {
			return
		}
		command := server
		server = nil
		waited := make(chan error, 1)
		go func() { waited <- command.Wait() }()
		if signalErr := command.Process.Signal(os.Interrupt); signalErr != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-waited
			t.Fatalf("timed out stopping NATS server: %s", serverLog.String())
		}
	}
	startServer := func() {
		if server != nil {
			t.Fatal("NATS server already running")
		}
		serverLog.Reset()
		arguments := []string{"-js", "-sd", storeDirectory, "-a", "127.0.0.1", "-p", strconv.Itoa(port)}
		if port == 0 {
			arguments = append(arguments[:len(arguments)-1], "-1", "--ports_file_dir", portsDirectory)
		}
		server = exec.Command(serverBinary, arguments...)
		server.Stdout, server.Stderr = &serverLog, &serverLog
		if startErr := server.Start(); startErr != nil {
			t.Fatal(startErr)
		}
		deadline := time.Now().Add(5 * time.Second)
		for port == 0 {
			entries, readErr := os.ReadDir(portsDirectory)
			if readErr != nil {
				stopServer()
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ports") {
					continue
				}
				raw, readErr := os.ReadFile(filepath.Join(portsDirectory, entry.Name()))
				var ports struct {
					NATS []string `json:"nats"`
				}
				if readErr != nil || json.Unmarshal(raw, &ports) != nil || len(ports.NATS) != 1 ||
					!strings.HasPrefix(ports.NATS[0], "nats://") {
					continue
				}
				host, portText, splitErr := net.SplitHostPort(strings.TrimPrefix(ports.NATS[0], "nats://"))
				assignedPort, portErr := strconv.Atoi(portText)
				if splitErr == nil && portErr == nil && host == "127.0.0.1" && assignedPort > 0 {
					port, serverURL = assignedPort, ports.NATS[0]
					break
				}
			}
			if port != 0 {
				break
			}
			if time.Now().After(deadline) {
				stopServer()
				t.Fatalf("timed out discovering NATS server port: %s", serverLog.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		for {
			probe, connectErr := nats.Connect(serverURL, nats.Timeout(50*time.Millisecond), nats.NoReconnect())
			if connectErr == nil {
				probe.Close()
				return
			}
			if time.Now().After(deadline) {
				stopServer()
				t.Fatalf("timed out starting NATS server: %s", serverLog.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	t.Cleanup(stopServer)
	runtimeConfig := fixture.runtimeConfig()
	runtimeConfig.NATS = nil
	runtimeConfig.OperationTimeout = 250 * time.Millisecond
	runtimeConfig.JetStream.OperationTimeout = runtimeConfig.OperationTimeout
	runtimeConfig.JetStream.FetchTimeout = 100 * time.Millisecond
	runtimeConfig.ShutdownTimeout = 2 * time.Second
	startServer()
	runtimeConfig.NATSURL = serverURL
	setupConnection, err := nats.Connect(serverURL, nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	setupJetStream, err := setupConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		setupConnection.Close()
		t.Fatal(err)
	}
	provisionRuntimeJetStream(t, setupJetStream, runtimeConfig.JetStream)
	setupConnection.Close()
	stopServer()

	deliverer := &integrationDeliverer{result: sendResultSuccess()}
	if unavailable, openErr := Open(t.Context(), runtimeConfig, Dependencies{Deliverer: deliverer, Secrets: fixture.secrets}); unavailable != nil || openErr == nil {
		t.Fatalf("initial unavailable NATS Open() = (%v, %v)", unavailable, openErr)
	}

	startServer()
	runtime, err := Open(t.Context(), runtimeConfig, Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), runtimeConfig.ShutdownTimeout)
		defer cancel()
		if cleanupErr := runtime.Close(cleanupCtx); cleanupErr != nil {
			t.Errorf("cleanup Runtime.Close() error = %v", cleanupErr)
		}
	})
	runErr := make(chan error, 1)
	go func() { runErr <- runtime.Run(t.Context()) }()
	waitRuntimeCondition(t, 5*time.Second, func() bool { return runtime.Ready() == nil }, "owned runtime readiness")
	connection := runtime.connection

	stopServer()
	waitRuntimeCondition(t, 5*time.Second, func() bool { return runtime.Ready() != nil }, "readiness degradation during NATS outage")
	if connection.IsClosed() {
		t.Fatal("owned NATS connection closed instead of entering reconnect mode")
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Reconnect", TargetURL: "https://reconnect.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "reconnect-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "reconnect-test-1"})
	if err != nil {
		t.Fatalf("PG outbox write while NATS is unavailable: %v", err)
	}

	startServer()
	waitRuntimeCondition(t, 10*time.Second, func() bool { return runtime.Ready() == nil }, "readiness recovery after NATS restart")
	waitRuntimeCondition(t, 10*time.Second, func() bool {
		var status string
		return fixture.pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries WHERE id=$1`, delivery.Value.Delivery.ID).Scan(&status) == nil && status == "delivered"
	}, "publish and processing after NATS restart")
	if runtime.connection != connection || len(deliverer.snapshot()) != 1 {
		t.Fatalf("runtime did not recover on the original connection: same=%v deliveries=%d", runtime.connection == connection, len(deliverer.snapshot()))
	}

	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err = <-runErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !connection.IsClosed() {
		t.Fatal("owned NATS connection remained open after Close")
	}
	stopServer()
	startServer()
	time.Sleep(500 * time.Millisecond)
	if !connection.IsClosed() {
		t.Fatal("closed owned NATS connection reconnected after server restart")
	}
}

func testClaimBeforeRotationReclaimsActiveSecret(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime) {
	t.Helper()
	deliverer := &integrationDeliverer{result: pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}}
	originalDeliverer := runtime.deliverer
	runtime.deliverer = deliverer
	defer func() { runtime.deliverer = originalDeliverer }()

	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Rotation reclaim", TargetURL: "https://rotation-reclaim.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "rotation-reclaim-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "rotation-reclaim-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	messageCtx, cancelMessage := context.WithTimeout(t.Context(), 2*time.Second)
	message, err := runtime.consumer.next(messageCtx)
	cancelMessage()
	if err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "rotation-reclaim-rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, created.Value.Subscription.ID,
		rotation.Value.RotationID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: "rotation-reclaim-activate-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	originalClaim := claim
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatalf("start claim after rotation: %v", err)
	}
	wantSecret, err := base64.RawURLEncoding.DecodeString(rotation.Value.Secret)
	if err != nil {
		clearSecret(secret)
		t.Fatal(err)
	}
	if !bytes.Equal(secret, wantSecret) {
		clearSecret(secret)
		clearSecret(wantSecret)
		t.Fatal("claim after rotation did not receive the current active secret")
	}
	clearSecret(wantSecret)
	if len(deliverer.snapshot()) != 0 {
		t.Fatal("claim bound to a retired secret reached the HTTP deliverer")
	}
	var attemptStatus, attemptRevision, deliveryAttempts string
	var attemptSecret uuid.UUID
	if err = fixture.pool.QueryRow(t.Context(), `SELECT attempt.status,attempt.claimed_subscription_revision::text,
		attempt.secret_version_id,delivery.attempt_count::text
		FROM plugin_webhook_delivery_attempts attempt
		JOIN plugin_webhook_deliveries delivery ON delivery.tenant_scope_id=attempt.tenant_scope_id
		 AND delivery.subscription_id=attempt.subscription_id AND delivery.id=attempt.delivery_id
		WHERE attempt.tenant_scope_id=$1 AND attempt.subscription_id=$2
		  AND attempt.delivery_id=$3 AND attempt.attempt_number=1`,
		fixture.targetScope, created.Value.Subscription.ID, delivery.Value.Delivery.ID).Scan(
		&attemptStatus, &attemptRevision, &attemptSecret, &deliveryAttempts); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "started" || attemptRevision != "2" ||
		attemptSecret != rotation.Value.RotationID || deliveryAttempts != "1" {
		clearSecret(secret)
		t.Fatalf("rotation reclaim attempt = %s,%s,%s,%s", attemptStatus, attemptRevision, attemptSecret, deliveryAttempts)
	}
	if claim.token != originalClaim.token || claim.attempt != originalClaim.attempt ||
		claim.claimSequence <= originalClaim.claimSequence || claim.claimedRevision != 2 ||
		claim.secretVersion != rotation.Value.RotationID {
		clearSecret(secret)
		t.Fatalf("rotation reclaim identity = before:%+v after:%+v", originalClaim, claim)
	}
	if staleSecret, staleErr := runtime.start(t.Context(), &originalClaim, item.digest); staleSecret != nil || !errors.Is(staleErr, errAttemptState) {
		returned := staleSecret != nil
		clearSecret(staleSecret)
		clearSecret(secret)
		t.Fatalf("stale claim replay returned secret = %t, error = %v", returned, staleErr)
	}
	result := deliverer.DeliverV2(t.Context(), pluginwebhook.QueueItem{SecretVersionID: rotation.Value.RotationID}, claim.attempt, secret)
	clearSecret(secret)
	if err = runtime.finish(t.Context(), claim, result); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
	items := deliverer.snapshot()
	if len(items) != 1 || items[0].SecretVersionID != rotation.Value.RotationID {
		t.Fatalf("reclaimed delivery identity = %+v", items)
	}
	if err = message.ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	redeliveryCtx, cancelRedelivery := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancelRedelivery()
	if redelivery, nextErr := runtime.consumer.next(redeliveryCtx); nextErr == nil {
		t.Fatalf("reclaimed delivery was not ACKed: stream=%d", redelivery.streamSequence)
	} else if !errors.Is(nextErr, errNoMessage) && !errors.Is(nextErr, context.DeadlineExceeded) {
		t.Fatal(nextErr)
	}
	deliverer.assertSecretsCleared(t)
}

func testDeadLetterPublishDoesNotHoldPGLocks(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime, deliverer *integrationDeliverer) {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "DLQ lock", TargetURL: "https://dlq-lock.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "dlq-lock-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "dlq-lock-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}

	originalJetStream := runtime.jetstream
	blockedJetStream := &blockingPublishJetStream{
		JetStreamContext: originalJetStream, subject: runtime.config.JetStream.DeadLetterSubject,
		started: make(chan struct{}), release: make(chan struct{}),
	}
	runtime.jetstream = blockedJetStream
	deliverer.setResult(pluginwebhook.SendResult{Code: "remote_rejected", StatusCode: 401})
	processDone := make(chan error, 1)
	go func() { processDone <- runtime.processOne(context.Background()) }()
	select {
	case <-blockedJetStream.started:
	case <-time.After(3 * time.Second):
		close(blockedJetStream.release)
		t.Fatal("DLQ publish did not reach the deterministic broker block")
	}

	connection, err := fixture.pool.Acquire(t.Context())
	if err != nil {
		close(blockedJetStream.release)
		t.Fatal(err)
	}
	var waiterPID int32
	if err = connection.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&waiterPID); err != nil {
		connection.Release()
		close(blockedJetStream.release)
		t.Fatal(err)
	}
	lockStarted := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		defer connection.Release()
		tx, beginErr := connection.Begin(context.Background())
		if beginErr != nil {
			lockDone <- beginErr
			return
		}
		defer tx.Rollback(context.Background())
		close(lockStarted)
		_, lockErr := tx.Exec(context.Background(), `SELECT 1 FROM plugin_webhook_subscriptions
			WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, fixture.targetScope, created.Value.Subscription.ID)
		if lockErr == nil {
			_, lockErr = tx.Exec(context.Background(), `SELECT 1 FROM plugin_webhook_deliveries
				WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3 FOR UPDATE`,
				fixture.targetScope, created.Value.Subscription.ID, delivery.Value.Delivery.ID)
		}
		lockDone <- lockErr
	}()
	<-lockStarted

	var blockers []int32
	var lockErr error
	lockCompleted := false
	deadline := time.Now().Add(3 * time.Second)
	for !lockCompleted && len(blockers) == 0 && time.Now().Before(deadline) {
		select {
		case lockErr = <-lockDone:
			lockCompleted = true
		default:
			if err = fixture.admin.QueryRow(t.Context(), `SELECT pg_blocking_pids($1)`, waiterPID).Scan(&blockers); err != nil {
				close(blockedJetStream.release)
				t.Fatal(err)
			}
		}
	}
	completedBeforeRelease := lockCompleted
	close(blockedJetStream.release)
	if processErr := <-processDone; processErr != nil {
		t.Fatal(processErr)
	}
	if !lockCompleted {
		lockErr = <-lockDone
	}
	runtime.jetstream = originalJetStream
	deliverer.setResult(pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204})
	if lockErr != nil {
		t.Fatal(lockErr)
	}
	if len(blockers) != 0 {
		t.Fatalf("DLQ broker publish held PostgreSQL locks; waiter=%d blockers=%v", waiterPID, blockers)
	}
	if !completedBeforeRelease {
		t.Fatal("concurrent PostgreSQL lock did not complete before DLQ broker publish was released")
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "dead_lettered")
}

func testDeadLetterIdentityAndWireContract(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime) {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "DLQ identity", TargetURL: "https://dlq-identity.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "dlq-identity-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "dlq-identity-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatal(err)
	}
	clearSecret(secret)
	if err = runtime.finish(t.Context(), claim, pluginwebhook.SendResult{
		Code: "remote_rejected", StatusCode: 401,
		ResponseSHA256: strings.Repeat("ab", 32), ResponseBytes: 17,
	}); err != nil {
		t.Fatal(err)
	}
	row, err := runtime.loadDeadLetter(t.Context(), fixture.targetScope, created.Value.Subscription.ID,
		delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDeadLetterIdentity(row, cloneDeadLetterRow(row)) {
		t.Fatal("exact DLQ row identity did not compare equal")
	}
	streamState, err := runtime.deadLetterStreamSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		mutate func(*deadLetterRow)
	}{
		{"tenant_scope", func(value *deadLetterRow) { value.tenantScope = uuid.New() }},
		{"subscription", func(value *deadLetterRow) { value.subscription = uuid.New() }},
		{"delivery", func(value *deadLetterRow) { value.delivery = uuid.New() }},
		{"event", func(value *deadLetterRow) { value.eventID = uuid.New() }},
		{"attempt", func(value *deadLetterRow) { value.attempt++ }},
		{"message_id", func(value *deadLetterRow) { value.messageID += "-changed" }},
		{"subject", func(value *deadLetterRow) { value.subject += ".changed" }},
		{"stream", func(value *deadLetterRow) { value.stream += "_CHANGED" }},
		{"reason", func(value *deadLetterRow) { value.reasonCode = "different_reason" }},
		{"payload_digest_nil", func(value *deadLetterRow) { value.payloadDigest = nil }},
		{"payload_digest_value", func(value *deadLetterRow) { value.payloadDigest = bytes.Repeat([]byte{0x31}, 32) }},
		{"request_digest_nil", func(value *deadLetterRow) { value.requestDigest = nil }},
		{"request_digest_value", func(value *deadLetterRow) { value.requestDigest = bytes.Repeat([]byte{0x32}, 32) }},
		{"response_digest_nil", func(value *deadLetterRow) { value.responseDigest = nil }},
		{"response_digest_value", func(value *deadLetterRow) { value.responseDigest = bytes.Repeat([]byte{0x33}, 32) }},
		{"status_nil", func(value *deadLetterRow) { value.statusCode = nil }},
		{"status_value", func(value *deadLetterRow) { status := 503; value.statusCode = &status }},
		{"response_bytes", func(value *deadLetterRow) { value.responseBytes++ }},
	}
	for _, mutation := range mutations {
		t.Run("dlq_identity_"+mutation.name, func(t *testing.T) {
			expected := cloneDeadLetterRow(row)
			mutation.mutate(&expected)
			if sameDeadLetterIdentity(row, expected) {
				t.Fatal("mutated DLQ identity compared equal")
			}
			if ackErr := runtime.acknowledgeDeadLetter(t.Context(), expected, streamState.epoch, 1); ackErr == nil {
				t.Fatal("mutated DLQ identity was acknowledged")
			}
			assertDeadLetterState(t, fixture.pool, row, "pending", 0)
		})
	}

	originalStream := runtime.config.JetStream.DeadLetterStream
	runtime.config.JetStream.DeadLetterStream = originalStream + "_CHANGED"
	if err = runtime.acknowledgeDeadLetter(t.Context(), row, streamState.epoch, 1); err == nil {
		t.Fatal("mismatched DLQ stream was acknowledged")
	}
	runtime.config.JetStream.DeadLetterStream = originalStream
	assertDeadLetterState(t, fixture.pool, row, "pending", 0)

	if err = runtime.publishDeadLetter(t.Context(), row); err != nil {
		t.Fatal(err)
	}
	sequence := assertDeadLetterState(t, fixture.pool, row, "acknowledged", 0)
	message, err := fixture.jetstream.GetMsg(originalStream, sequence)
	if err != nil {
		t.Fatal(err)
	}
	wantBody := fmt.Sprintf(
		`{"schema":"cdnca.plugin-webhook.dead-letter/v1","delivery_id":"%s","event_id":"%s","attempt":%d,"reason_code":"%s","status_code":%d,"request_sha256":"%x","response_sha256":"%x","response_bytes":%d}`,
		row.delivery, row.eventID, row.attempt, row.reasonCode, *row.statusCode, row.requestDigest, row.responseDigest, row.responseBytes)
	wireDigest := sha256.Sum256([]byte(wantBody))
	if message.Subject != row.subject || message.Header.Get(nats.MsgIdHdr) != row.messageID ||
		message.Header.Get("X-CDNCA-Webhook-DLQ-Payload-Sha256") != fmt.Sprintf("%x", wireDigest[:]) ||
		string(message.Data) != wantBody {
		t.Fatalf("DLQ broker message mismatch: subject=%q msg_id=%q digest=%q body=%s",
			message.Subject, message.Header.Get(nats.MsgIdHdr),
			message.Header.Get("X-CDNCA-Webhook-DLQ-Payload-Sha256"), message.Data)
	}
	if err = runtime.acknowledgeDeadLetter(t.Context(), row, streamState.epoch, sequence+1); err == nil {
		t.Fatal("already-acknowledged DLQ accepted a different sequence")
	}
	assertDeadLetterState(t, fixture.pool, row, "acknowledged", sequence)
	if err = runtime.acknowledgeDeadLetter(t.Context(), row, streamState.epoch, sequence); err != nil {
		t.Fatalf("exact already-acknowledged DLQ was not idempotent: %v", err)
	}
	assertDeadLetterState(t, fixture.pool, row, "acknowledged", sequence)
	assertDeliveryStatus(t, fixture.pool, row.delivery, "dead_lettered")
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func cloneDeadLetterRow(row deadLetterRow) deadLetterRow {
	clone := row
	clone.payloadDigest = bytes.Clone(row.payloadDigest)
	clone.requestDigest = bytes.Clone(row.requestDigest)
	clone.responseDigest = bytes.Clone(row.responseDigest)
	if row.statusCode != nil {
		status := *row.statusCode
		clone.statusCode = &status
	}
	return clone
}

func assertDeadLetterState(t *testing.T, pool *pgxpool.Pool, row deadLetterRow, wantState string, wantSequence uint64) uint64 {
	t.Helper()
	var state, phase string
	var reconcileEpoch, high, boundary, cursor, terminalEpoch, sequence, ackID *string
	if err := pool.QueryRow(t.Context(), `SELECT publish_state,reconcile_phase,
		reconcile_stream_created_unix_nano::text,reconcile_high_watermark::text,
		reconcile_scan_boundary::text,reconcile_cursor::text,nats_dlq_stream_created_unix_nano::text,
		nats_dlq_sequence::text,nats_ack_id
			FROM plugin_webhook_dead_letters WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
		row.tenantScope, row.subscription, row.delivery).Scan(&state, &phase, &reconcileEpoch, &high, &boundary,
		&cursor, &terminalEpoch, &sequence, &ackID); err != nil {
		t.Fatal(err)
	}
	if state != wantState {
		t.Fatalf("DLQ publish state = %s want %s", state, wantState)
	}
	if wantState == "pending" {
		if terminalEpoch != nil || sequence != nil || ackID != nil {
			t.Fatalf("pending DLQ retained acknowledgement: epoch=%v sequence=%v ack=%v", terminalEpoch, sequence, ackID)
		}
		actual, err := loadDeadLetterForTest(t.Context(), pool, row)
		if err != nil || !sameDeadLetterIdentity(actual, row) {
			t.Fatalf("pending DLQ identity changed: %+v,%v", actual, err)
		}
		return 0
	}
	if phase != "complete" || reconcileEpoch != nil || high != nil || boundary != nil || cursor != nil ||
		terminalEpoch == nil || sequence == nil || ackID == nil {
		t.Fatalf("acknowledged DLQ terminal state is incomplete: phase=%s reconcile=%v/%v/%v/%v terminal=%v/%v/%v",
			phase, reconcileEpoch, high, boundary, cursor, terminalEpoch, sequence, ackID)
	}
	parsedEpoch, err := strconv.ParseInt(*terminalEpoch, 10, 64)
	if err != nil || parsedEpoch <= 0 {
		t.Fatalf("DLQ terminal epoch = %v,%v", parsedEpoch, err)
	}
	parsed, err := parseUint(*sequence)
	if err != nil {
		t.Fatal(err)
	}
	if wantSequence != 0 && parsed != wantSequence {
		t.Fatalf("DLQ sequence = %d want %d", parsed, wantSequence)
	}
	wantAckID := "PLUGIN_WEBHOOK_DLQ:" + *sequence
	if *ackID != wantAckID {
		t.Fatalf("DLQ ack ID = %q want %q", *ackID, wantAckID)
	}
	return parsed
}

func loadDeadLetterForTest(ctx context.Context, pool *pgxpool.Pool, expected deadLetterRow) (deadLetterRow, error) {
	var actual deadLetterRow
	var attempt string
	err := pool.QueryRow(ctx, `SELECT tenant_scope_id,subscription_id,delivery_id,event_id,
		final_attempt_number::text,nats_message_id,nats_subject,payload_sha256,reason_code,http_status,
		request_sha256,response_sha256,response_bytes,nats_stream FROM plugin_webhook_dead_letters
		WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
		expected.tenantScope, expected.subscription, expected.delivery).Scan(
		&actual.tenantScope, &actual.subscription, &actual.delivery, &actual.eventID, &attempt,
		&actual.messageID, &actual.subject, &actual.payloadDigest, &actual.reasonCode, &actual.statusCode,
		&actual.requestDigest, &actual.responseDigest, &actual.responseBytes, &actual.stream)
	if err != nil {
		return deadLetterRow{}, err
	}
	actual.attempt, err = parseUint(attempt)
	return actual, err
}

func testRevokeDuringOutboxPublish(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime) {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Revoke publish race", TargetURL: "https://revoke-publish.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "revoke-publish-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "revoke-publish-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	originalJetStream := runtime.jetstream
	blockedJetStream := &publishReturnBlockJetStream{
		JetStreamContext: originalJetStream,
		subject: deliverySubject(runtime.config.JetStream.DeliverySubjectPrefix, fixture.targetScope,
			created.Value.Subscription.ID, delivery.Value.Delivery.ID),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	runtime.jetstream = blockedJetStream
	publishDone := make(chan error, 1)
	go func() { publishDone <- runtime.publishOutbox(context.Background()) }()
	select {
	case <-blockedJetStream.started:
	case <-time.After(3 * time.Second):
		runtime.jetstream = originalJetStream
		close(blockedJetStream.release)
		t.Fatal("delivery publish did not reach post-broker block")
	}
	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "revoke-publish-revoke-1", Revision: 1}); err != nil {
		runtime.jetstream = originalJetStream
		close(blockedJetStream.release)
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "revoked")
	assertOutboxStatus(t, fixture.pool, delivery.Value.Delivery.ID, "revoked")
	close(blockedJetStream.release)
	if publishErr := <-publishDone; !errors.Is(publishErr, errNotClaimable) {
		runtime.jetstream = originalJetStream
		t.Fatalf("publish after revoke = %v want %v", publishErr, errNotClaimable)
	}
	runtime.jetstream = originalJetStream
	if item, loadErr := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID); loadErr == nil {
		t.Fatalf("revoked delivery without persisted broker sequence was accepted: sequence=%d", item.streamSequence)
	}
	stored, err := fixture.jetstream.GetLastMsg(fixture.jetstreamConfig.DeliveryStream, blockedJetStream.subject,
		nats.Context(t.Context()))
	if err != nil || stored.Sequence == 0 {
		t.Fatalf("revoked delivery broker identity = %+v,%v", stored, err)
	}

	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	consumerInfo, err := fixture.jetstream.ConsumerInfo(fixture.jetstreamConfig.DeliveryStream,
		fixture.jetstreamConfig.DeliveryDurable, nats.Context(t.Context()))
	if err != nil || consumerInfo.AckFloor.Stream < stored.Sequence {
		t.Fatalf("revoked delivery ACK floor = %+v,%v want >=%d", consumerInfo, err, stored.Sequence)
	}
	time.Sleep(1100 * time.Millisecond)
	redeliveryCtx, cancel := context.WithTimeout(t.Context(), 750*time.Millisecond)
	defer cancel()
	if message, nextErr := runtime.consumer.next(redeliveryCtx); nextErr == nil {
		t.Fatalf("revoked queued item was NAKed and redelivered: stream=%d", message.streamSequence)
	} else if !errors.Is(nextErr, errNoMessage) && !errors.Is(nextErr, context.DeadlineExceeded) {
		t.Fatal(nextErr)
	}
}

func assertOutboxStatus(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, delivery uuid.UUID, want string) {
	t.Helper()
	var got string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_outbox WHERE delivery_id=$1`, delivery).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("outbox %s status = %s want %s", delivery, got, want)
	}
}

func testConcurrentOutboxPublishers(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime,
	deliverer *integrationDeliverer, subscription uuid.UUID) {
	t.Helper()
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "outbox-concurrent-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := second.Close(context.Background()); closeErr != nil {
			t.Errorf("close second outbox publisher: %v", closeErr)
		}
	}()
	before, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	if err != nil {
		t.Fatal(err)
	}
	originalJetStream := runtime.jetstream
	blocked := &blockingPublishJetStream{
		JetStreamContext: originalJetStream,
		subject: deliverySubject(fixture.jetstreamConfig.DeliverySubjectPrefix,
			fixture.targetScope, subscription, delivery.Value.Delivery.ID),
		started: make(chan struct{}), release: make(chan struct{}),
	}
	runtime.jetstream = blocked
	defer func() { runtime.jetstream = originalJetStream }()
	firstDone := make(chan error, 1)
	go func() { firstDone <- runtime.publishOutbox(context.Background()) }()
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first outbox publisher did not reach broker")
	}
	if err = second.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(blocked.release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	after, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	if err != nil || after.State.Msgs != before.State.Msgs+1 {
		t.Fatalf("two outbox publishers stored %+v,%v before=%d", after, err, before.State.Msgs)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil || item.streamSequence == 0 {
		t.Fatalf("concurrent outbox broker sequence = %d,%v", item.streamSequence, err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
}

func testOutboxLeaseRestartRecovery(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime,
	deliverer *integrationDeliverer, subscription uuid.UUID) *Runtime {
	t.Helper()
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "outbox-restart-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := runtime.leaseOutbox(t.Context())
	if err != nil || lease.delivery != delivery.Value.Delivery.ID {
		t.Fatalf("lease before runtime restart = %+v,%v", lease, err)
	}
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(fixture.runtimeConfig().LeaseDuration + 100*time.Millisecond)
	restarted, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = restarted.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	item, loadErr := restarted.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil || loadErr != nil || after.State.LastSeq != before.State.LastSeq+1 || item.streamSequence != after.State.LastSeq {
		t.Fatalf("runtime restart outbox sequence = %+v,%v delivery=%d,%v before=%d",
			after, err, item.streamSequence, loadErr, before.State.LastSeq)
	}
	assertOutboxStatus(t, fixture.pool, delivery.Value.Delivery.ID, "published")
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
	return restarted
}

func testConcurrentDeadLetterPublishers(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime) {
	t.Helper()
	shortWindow := deadLetterStreamConfig(fixture.jetstreamConfig)
	shortWindow.Duplicates = 100 * time.Millisecond
	if _, err := fixture.jetstream.UpdateStream(shortWindow, nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, restoreErr := fixture.jetstream.UpdateStream(deadLetterStreamConfig(fixture.jetstreamConfig), nats.Context(t.Context())); restoreErr != nil {
			t.Errorf("restore concurrent DLQ duplicate window: %v", restoreErr)
		}
	}()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "DLQ concurrent", TargetURL: "https://dlq-concurrent.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "dlq-concurrent-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "dlq-concurrent-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatal(err)
	}
	clearSecret(secret)
	if err = runtime.finish(t.Context(), claim, pluginwebhook.SendResult{Code: "remote_rejected", StatusCode: 401}); err != nil {
		t.Fatal(err)
	}
	row, err := runtime.loadDeadLetter(t.Context(), fixture.targetScope, created.Value.Subscription.ID,
		delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeadLetterStream)
	if err != nil {
		t.Fatal(err)
	}
	blockedJetStream := &blockingPublishJetStream{
		JetStreamContext: runtime.jetstream, subject: fixture.jetstreamConfig.DeadLetterSubject,
		started: make(chan struct{}), release: make(chan struct{}),
	}
	second := &Runtime{config: runtime.config, pool: runtime.pool, connection: runtime.connection, jetstream: blockedJetStream}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.recoverDeadLetter(context.Background(), row) }()
	select {
	case <-blockedJetStream.started:
	case <-time.After(5 * time.Second):
		close(blockedJetStream.release)
		t.Fatal("second DLQ recoverer did not finish its empty scan")
	}
	if err = runtime.recoverDeadLetter(t.Context(), row); err != nil {
		close(blockedJetStream.release)
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	close(blockedJetStream.release)
	secondErr := <-secondDone
	after, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeadLetterStream)
	if err != nil || after.State.Msgs != before.State.Msgs+1 || after.State.LastSeq != before.State.LastSeq+1 {
		t.Fatalf("cross-window DLQ recovery CAS = %+v,%v before=%+v second=%v", after, err, before.State, secondErr)
	}
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "dead_lettered")
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func testRecoverClaimBindsDelivery(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime) uuid.UUID {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Recovery binding", TargetURL: "https://recovery-binding.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "recovery-binding-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "recovery-binding-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "recovery-binding-test-2"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = runtime.publishOutbox(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var firstDigest, secondDigest []byte
	if err = fixture.pool.QueryRow(t.Context(), `SELECT event.body_sha256
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id AND event.subscription_id=delivery.subscription_id
		 AND event.id=delivery.event_id WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		fixture.targetScope, created.Value.Subscription.ID, first.Value.Delivery.ID).Scan(&firstDigest); err != nil {
		t.Fatal(err)
	}
	if err = fixture.pool.QueryRow(t.Context(), `SELECT event.body_sha256
		FROM plugin_webhook_deliveries delivery JOIN plugin_webhook_events event
		  ON event.tenant_scope_id=delivery.tenant_scope_id AND event.subscription_id=delivery.subscription_id
		 AND event.id=delivery.event_id WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.id=$3`,
		fixture.targetScope, created.Value.Subscription.ID, second.Value.Delivery.ID).Scan(&secondDigest); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstDigest, secondDigest) {
		t.Fatal("multi-delivery recovery fixtures unexpectedly share an event digest")
	}
	item, err := runtime.loadDelivery(t.Context(), second.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.recoverClaim(t.Context(), claim); err != nil {
		t.Fatalf("recover claim selected the wrong delivery event: %v", err)
	}
	var requestDigest []byte
	if err = fixture.pool.QueryRow(t.Context(), `SELECT request_sha256
		FROM plugin_webhook_delivery_attempts WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND attempt_number=1`,
		fixture.targetScope, created.Value.Subscription.ID, second.Value.Delivery.ID).Scan(&requestDigest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestDigest, secondDigest) {
		t.Fatalf("recovered attempt digest = %x want %x", requestDigest, secondDigest)
	}
	for range 2 {
		message, nextErr := runtime.consumer.next(t.Context())
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		if ackErr := message.ack(t.Context()); ackErr != nil {
			t.Fatal(ackErr)
		}
	}
	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "recovery-binding-revoke-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	followup, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Recovery followup", TargetURL: "https://recovery-followup.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "recovery-followup-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return followup.Value.Subscription.ID
}

func testOutboxDedupeAndDLQ(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime,
	deliverer *integrationDeliverer, subscription uuid.UUID) {
	t.Helper()
	shortWindow := deliveryStreamConfig(fixture.jetstreamConfig)
	shortWindow.Duplicates = 100 * time.Millisecond
	streamInfo, err := fixture.jetstream.UpdateStream(shortWindow, nats.Context(t.Context()))
	if err != nil || streamInfo.Config.Duplicates != shortWindow.Duplicates {
		t.Fatalf("set delivery duplicate window = %+v,%v", streamInfo, err)
	}
	defer func() {
		if _, restoreErr := fixture.jetstream.UpdateStream(deliveryStreamConfig(fixture.jetstreamConfig), nats.Context(t.Context())); restoreErr != nil {
			t.Errorf("restore delivery duplicate window: %v", restoreErr)
		}
	}()
	shortDLQWindow := deadLetterStreamConfig(fixture.jetstreamConfig)
	shortDLQWindow.Duplicates = 100 * time.Millisecond
	dlqStreamInfo, err := fixture.jetstream.UpdateStream(shortDLQWindow, nats.Context(t.Context()))
	if err != nil || dlqStreamInfo.Config.Duplicates != shortDLQWindow.Duplicates {
		t.Fatalf("set DLQ duplicate window = %+v,%v", dlqStreamInfo, err)
	}
	defer func() {
		if _, restoreErr := fixture.jetstream.UpdateStream(deadLetterStreamConfig(fixture.jetstreamConfig), nats.Context(t.Context())); restoreErr != nil {
			t.Errorf("restore DLQ duplicate window: %v", restoreErr)
		}
	}()
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "dedupe-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := runtime.leaseOutbox(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	firstSequence := publishLeasedMessage(t, runtime, lease)
	time.Sleep(1100 * time.Millisecond)
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream)
	if err != nil {
		t.Fatal(err)
	}
	if after.State.Msgs != before.State.Msgs+1 {
		t.Fatalf("crash-after-publish duplicate stored %d messages, before=%d", after.State.Msgs, before.State.Msgs)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil || item.streamSequence != firstSequence {
		t.Fatalf("deduplicated delivery sequence = %d,%v want %d", item.streamSequence, err, firstSequence)
	}
	originalMessage, err := runtime.consumer.next(t.Context())
	if err != nil {
		t.Fatalf("fetch original terminal message: %v", err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatal(err)
	}
	clearSecret(secret)
	if err = runtime.finish(t.Context(), claim, pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}); err != nil {
		t.Fatal(err)
	}
	if err = originalMessage.nak(t.Context(), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatalf("process valid terminal redelivery: %v", err)
	}
	validTerminalInfo, err := fixture.jetstream.ConsumerInfo(fixture.jetstreamConfig.DeliveryStream, fixture.jetstreamConfig.DeliveryDurable, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if validTerminalInfo.AckFloor.Stream < firstSequence {
		t.Fatalf("valid terminal redelivery was not ACKed: floor=%d want >=%d", validTerminalInfo.AckFloor.Stream, firstSequence)
	}
	terminalMessageID := "terminal-sequence-" + uuid.NewString()
	terminalMessage := nats.NewMsg(deliverySubject(fixture.runtimeConfig().JetStream.DeliverySubjectPrefix,
		fixture.targetScope, subscription, delivery.Value.Delivery.ID))
	terminalMessage.Data = append([]byte(nil), item.body...)
	terminalMessage.Header.Set(nats.MsgIdHdr, terminalMessageID)
	terminalMessage.Header.Set("X-CDNCA-Webhook-Id", delivery.Value.Delivery.ID.String())
	beforeTerminalMismatch, err := fixture.jetstream.ConsumerInfo(fixture.jetstreamConfig.DeliveryStream, fixture.jetstreamConfig.DeliveryDurable, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.jetstream.PublishMsg(terminalMessage, nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatalf("process stale terminal message: %v", err)
	}
	afterTerminalMismatch, err := fixture.jetstream.ConsumerInfo(fixture.jetstreamConfig.DeliveryStream, fixture.jetstreamConfig.DeliveryDurable, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if afterTerminalMismatch.AckFloor.Stream != beforeTerminalMismatch.AckFloor.Stream {
		t.Fatalf("stale terminal broker message advanced ACK floor: before=%d after=%d", beforeTerminalMismatch.AckFloor.Stream, afterTerminalMismatch.AckFloor.Stream)
	}
	time.Sleep(1100 * time.Millisecond)
	staleContext, staleCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer staleCancel()
	staleRedelivery, err := runtime.consumer.next(staleContext)
	if err != nil {
		t.Fatalf("fetch stale terminal redelivery: %v", err)
	}
	if staleRedelivery.message.Header.Get(nats.MsgIdHdr) != terminalMessageID {
		t.Fatalf("stale terminal redelivery message ID = %q want %q", staleRedelivery.message.Header.Get(nats.MsgIdHdr), terminalMessageID)
	}
	if err = staleRedelivery.ack(t.Context()); err != nil {
		t.Fatal(err)
	}

	dlqDelivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "dedupe-test-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(t.Context(), `CREATE FUNCTION runtime_fail_dlq_ack() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'runtime test DLQ ack failure'; END $$;
		CREATE TRIGGER runtime_fail_dlq_ack BEFORE UPDATE ON plugin_webhook_dead_letters
		FOR EACH ROW WHEN (OLD.publish_state='pending' AND NEW.publish_state='acknowledged')
		EXECUTE FUNCTION runtime_fail_dlq_ack()`); err != nil {
		t.Fatal(err)
	}
	deliverer.setResult(pluginwebhook.SendResult{Code: "remote_rejected", StatusCode: 401})
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	var deliveryStatus, attemptStatus string
	var deadLetterRows int
	if err = fixture.pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries WHERE id=$1`,
		dlqDelivery.Value.Delivery.ID).Scan(&deliveryStatus); err != nil {
		t.Fatal(err)
	}
	if err = fixture.pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_delivery_attempts
		WHERE delivery_id=$1 ORDER BY attempt_number DESC LIMIT 1`, dlqDelivery.Value.Delivery.ID).Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if err = fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_dead_letters
		WHERE delivery_id=$1`, dlqDelivery.Value.Delivery.ID).Scan(&deadLetterRows); err != nil {
		t.Fatal(err)
	}
	dlqBeforeRetry, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeadLetterStream)
	if err != nil || dlqBeforeRetry.State.Msgs != 1 {
		t.Fatalf("DLQ after simulated DB ack crash = %+v,%v delivery=%s attempt=%s rows=%d",
			dlqBeforeRetry, err, deliveryStatus, attemptStatus, deadLetterRows)
	}
	if _, err = fixture.pool.Exec(t.Context(), `DROP TRIGGER runtime_fail_dlq_ack ON plugin_webhook_dead_letters;
		DROP FUNCTION runtime_fail_dlq_ack()`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	if err = runtime.publishPendingDeadLetter(t.Context(), fixture.targetScope, subscription,
		dlqDelivery.Value.Delivery.ID, true); err != nil {
		t.Fatal(err)
	}
	dlqAfterRetry, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeadLetterStream)
	if err != nil || dlqAfterRetry.State.Msgs != 1 || dlqAfterRetry.State.LastSeq != dlqBeforeRetry.State.LastSeq {
		t.Fatalf("DLQ dedupe after reconciliation = %+v,%v", dlqAfterRetry, err)
	}
	assertDeliveryStatus(t, fixture.pool, dlqDelivery.Value.Delivery.ID, "dead_lettered")
	time.Sleep(1100 * time.Millisecond)
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	deliverer.setResult(pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204})
}

func testReadinessLagRecovery(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime, deliverer *integrationDeliverer) {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Lag", TargetURL: "https://lag.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "lag-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		if _, err = fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: fmt.Sprintf("lag-test-%d", index)}); err != nil {
			t.Fatal(err)
		}
		if err = runtime.publishOutbox(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.probeReadiness(t.Context()) != nil }, "readiness degradation on pending lag")
	for index := 0; index < 2; index++ {
		if err = runtime.processOne(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	waitRuntimeCondition(t, 3*time.Second, func() bool { return runtime.probeReadiness(t.Context()) == nil }, "readiness recovery after lag drains")
	if len(deliverer.snapshot()) < 5 {
		t.Fatal("lag deliveries did not reach the deliverer")
	}
}

func testMalformedResponseDigestFailsClosed(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime, deliverer *integrationDeliverer) {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Malformed response", TargetURL: "https://malformed-response.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "malformed-response-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription := created.Value.Subscription.ID
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "malformed-response-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	deliverer.setResult(pluginwebhook.SendResult{
		Success: true, Code: "delivered", StatusCode: 204, ResponseSHA256: "not-a-sha256",
	})
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	var attemptStatus string
	var responseDigest []byte
	if err = fixture.pool.QueryRow(t.Context(), `SELECT attempt.status,attempt.response_sha256
		FROM plugin_webhook_delivery_attempts attempt WHERE attempt.tenant_scope_id=$1 AND attempt.subscription_id=$2
		AND attempt.delivery_id=$3 AND attempt.attempt_number=1`, fixture.targetScope, subscription,
		delivery.Value.Delivery.ID).Scan(&attemptStatus, &responseDigest); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "started" || responseDigest != nil {
		t.Fatalf("malformed response digest outcome = status=%s digest=%x", attemptStatus, responseDigest)
	}
	time.Sleep(1100 * time.Millisecond)
	redelivery, err := runtime.consumer.next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = redelivery.ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "malformed-response-revoke-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	originalClaimTimeout := runtime.config.ClaimTimeout
	runtime.config.ClaimTimeout = time.Millisecond
	time.Sleep(10 * time.Millisecond)
	if err = runtime.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	runtime.config.ClaimTimeout = originalClaimTimeout
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "revoked")
}

func testOutcomeFailureNAK(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime,
	deliverer *integrationDeliverer, subscription uuid.UUID) {
	t.Helper()
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "outcome-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.pool.Exec(t.Context(), `CREATE FUNCTION runtime_fail_outcome() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'runtime test outcome failure'; END $$;
		CREATE TRIGGER runtime_fail_outcome BEFORE UPDATE ON plugin_webhook_delivery_attempts
		FOR EACH ROW WHEN (OLD.status='started' AND NEW.status IN ('succeeded','temporary_failure','permanent_failure'))
		EXECUTE FUNCTION runtime_fail_outcome()`); err != nil {
		t.Fatal(err)
	}
	deliverer.setResult(pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204})
	deadline := time.Now().Add(5 * time.Second)
	for {
		var status string
		if err = fixture.pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries WHERE id=$1`,
			delivery.Value.Delivery.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "claimed" {
			break
		}
		if status != "queued" || time.Now().After(deadline) {
			t.Fatalf("PG outcome failure setup status = %s", status)
		}
		if err = runtime.processOne(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	var exhausted *runtimeMessage
	for expectedDelivery := uint64(2); expectedDelivery <= 10; expectedDelivery++ {
		redelivered, nextErr := runtime.consumer.next(t.Context())
		if nextErr != nil {
			t.Fatalf("durable redelivery %d failed: %v", expectedDelivery, nextErr)
		}
		if redelivered.attempts < expectedDelivery {
			t.Fatalf("PG outcome failure was acknowledged, deliveries=%d want >=%d", redelivered.attempts, expectedDelivery)
		}
		if expectedDelivery == 10 {
			var deliveryStatus string
			if err = fixture.pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries WHERE id=$1`, delivery.Value.Delivery.ID).Scan(&deliveryStatus); err != nil {
				t.Fatal(err)
			}
			if deliveryStatus != "claimed" {
				t.Fatalf("PG delivery left terminal on broker redelivery %d: status=%s", expectedDelivery, deliveryStatus)
			}
			exhausted = redelivered
			break
		}
		if err = redelivered.nak(t.Context(), 10*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err = fixture.pool.Exec(t.Context(), `DROP TRIGGER runtime_fail_outcome ON plugin_webhook_delivery_attempts;
		DROP FUNCTION runtime_fail_outcome()`); err != nil {
		t.Fatal(err)
	}
	runtime.config.ClaimTimeout = 10 * time.Millisecond
	if err = runtime.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if exhausted == nil {
		t.Fatal("missing exhausted broker delivery")
	}
	if err = exhausted.nak(t.Context(), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	for {
		var nextAttempt, databaseNow time.Time
		if err = fixture.pool.QueryRow(t.Context(), `SELECT next_attempt_at,clock_timestamp()
			FROM plugin_webhook_deliveries WHERE tenant_scope_id=$1 AND subscription_id=$2 AND id=$3`,
			fixture.targetScope, subscription, delivery.Value.Delivery.ID).Scan(&nextAttempt, &databaseNow); err != nil {
			t.Fatal(err)
		}
		if !nextAttempt.After(databaseNow) {
			break
		}
		delay := time.Until(nextAttempt)
		if delay > 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		time.Sleep(delay)
	}
	deliverer.setResult(pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204})
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
}

func publishLeasedMessage(t *testing.T, runtime *Runtime, lease outboxLease) uint64 {
	t.Helper()
	message := nats.NewMsg(deliverySubject(runtime.config.JetStream.DeliverySubjectPrefix,
		lease.tenantScope, lease.subscription, lease.delivery))
	message.Data = append([]byte(nil), lease.body...)
	message.Header.Set(nats.MsgIdHdr, lease.messageID)
	message.Header.Set("X-CDNCA-Webhook-Id", lease.delivery.String())
	digest := sha256.Sum256(lease.body)
	message.Header.Set("X-CDNCA-Webhook-Queue-Sha256", fmt.Sprintf("%x", digest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, runtime.config.JetStream.DeliveryStream)
	message.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	ack, err := runtime.jetstream.PublishMsg(message, nats.ExpectStream(runtime.config.JetStream.DeliveryStream),
		nats.ExpectLastSequencePerSubject(0))
	if err != nil || ack == nil || ack.Sequence == 0 {
		t.Fatalf("publish leased message = %+v,%v", ack, err)
	}
	return ack.Sequence
}

func assertDeliveryBrokerIdentity(t *testing.T, fixture *runtimeIntegrationFixture, delivery uuid.UUID) (int64, uint64) {
	t.Helper()
	var epochText, sequenceText string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT nats_stream_created_unix_nano::text,nats_stream_sequence::text
		FROM plugin_webhook_deliveries WHERE id=$1`, delivery).Scan(&epochText, &sequenceText); err != nil {
		t.Fatal(err)
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch <= 0 {
		t.Fatalf("delivery stream epoch = %q,%v", epochText, err)
	}
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil || sequence == 0 {
		t.Fatalf("delivery stream sequence = %q,%v", sequenceText, err)
	}
	info, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream, nats.Context(t.Context()))
	if err != nil || info.Created.UTC().UnixNano() != epoch {
		t.Fatalf("delivery stream identity = epoch:%d sequence:%d info:%+v err:%v", epoch, sequence, info, err)
	}
	return epoch, sequence
}

func assertRuntimeSecret(t *testing.T, provider *pluginwebhookcontrol.RuntimeSecretProvider, target, subscription, secretID uuid.UUID, encoded string) {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Secret(t.Context(), target, subscription, secretID)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("runtime secret mismatch: %v", err)
	}
	for index := range got {
		got[index] = 0
	}
	for index := range want {
		want[index] = 0
	}
}

func assertDeliveryStatus(t *testing.T, pool *pgxpool.Pool, delivery uuid.UUID, want string) {
	t.Helper()
	var got string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM plugin_webhook_deliveries WHERE id=$1`, delivery).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("delivery %s status = %s want %s", delivery, got, want)
	}
}

func waitRuntimeCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + description)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func deleteRuntimeJetStream(t *testing.T, fixture *runtimeIntegrationFixture) {
	t.Helper()
	if err := fixture.jetstream.DeleteConsumer(fixture.jetstreamConfig.DeliveryStream, fixture.jetstreamConfig.DeliveryDurable); err != nil && !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatal(err)
	}
	if err := fixture.jetstream.DeleteStream(fixture.jetstreamConfig.DeliveryStream); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal(err)
	}
	if err := fixture.jetstream.DeleteStream(fixture.jetstreamConfig.DeadLetterStream); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal(err)
	}
}

func TestRuntimePublishAckWireProgressAndLeaseFence(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	// Covers a NATS publish plus 084's in-database attestation check under load.
	config.LeaseDuration = time.Second
	runtime, err := Open(t.Context(), config, Dependencies{
		Deliverer: &integrationDeliverer{result: pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}},
		Secrets:   fixture.secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Runtime publish fences", TargetURL: "https://runtime-fences.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "runtime-fences-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription := created.Value.Subscription.ID

	t.Run("delivery publication persists exact stream identity", func(t *testing.T) {
		delivery, createErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-fences-delivery-identity-1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if publishErr := runtime.publishOutbox(t.Context()); publishErr != nil {
			t.Fatal(publishErr)
		}
		assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
	})

	t.Run("delivery broker commit recovers exact stream identity", func(t *testing.T) {
		delivery, createErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-fences-delivery-recover-1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		lease, leaseErr := runtime.leaseOutbox(t.Context())
		if leaseErr != nil || lease.delivery != delivery.Value.Delivery.ID {
			t.Fatalf("recovery lease = %+v,%v", lease, leaseErr)
		}
		sequence := publishLeasedMessage(t, runtime, lease)
		time.Sleep(config.LeaseDuration + 100*time.Millisecond)
		if publishErr := runtime.publishOutbox(t.Context()); publishErr != nil {
			t.Fatal(publishErr)
		}
		_, storedSequence := assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
		if storedSequence != sequence {
			t.Fatalf("recovered delivery sequence = %d want %d", storedSequence, sequence)
		}
	})

	t.Run("DLQ dedupe ACK requires exact wire", func(t *testing.T) {
		delivery, createErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-fences-dlq-1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if publishErr := runtime.publishOutbox(t.Context()); publishErr != nil {
			t.Fatal(publishErr)
		}
		item, loadErr := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		claim, claimErr := runtime.claim(t.Context(), item)
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		secret, startErr := runtime.start(t.Context(), &claim, item.digest)
		if startErr != nil {
			t.Fatal(startErr)
		}
		clearSecret(secret)
		if finishErr := runtime.finish(t.Context(), claim, pluginwebhook.SendResult{Code: "remote_rejected", StatusCode: 401}); finishErr != nil {
			t.Fatal(finishErr)
		}
		row, loadErr := runtime.loadDeadLetter(t.Context(), fixture.targetScope, subscription, delivery.Value.Delivery.ID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		wrongBody := []byte(`{"schema":"wrong"}`)
		wrongDigest := sha256.Sum256(wrongBody)
		wrong := nats.NewMsg(row.subject)
		wrong.Data = wrongBody
		wrong.Header.Set(nats.MsgIdHdr, row.messageID)
		wrong.Header.Set("X-CDNCA-Webhook-DLQ-Payload-Sha256", fmt.Sprintf("%x", wrongDigest[:]))
		wrong.Header.Set(nats.ExpectedStreamHdr, fixture.jetstreamConfig.DeadLetterStream)
		if _, publishErr := fixture.jetstream.PublishMsg(wrong, nats.ExpectStream(fixture.jetstreamConfig.DeadLetterStream)); publishErr != nil {
			t.Fatal(publishErr)
		}
		if publishErr := runtime.publishDeadLetter(t.Context(), row); publishErr == nil {
			t.Fatal("DLQ Msg-Id dedupe acknowledgement accepted a wrong stored wire")
		}
		assertDeadLetterState(t, fixture.pool, row, "pending", 0)
	})

	t.Run("renewed lease wins over stale recovery candidate", func(t *testing.T) {
		delivery, createErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-fences-lease-1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		lease, leaseErr := runtime.leaseOutbox(t.Context())
		if leaseErr != nil || lease.delivery != delivery.Value.Delivery.ID {
			t.Fatalf("initial outbox lease = %+v,%v", lease, leaseErr)
		}
		time.Sleep(config.LeaseDuration + 100*time.Millisecond)
		blocker, beginErr := fixture.pool.Begin(t.Context())
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer blocker.Rollback(context.Background())
		var blockerPID int32
		if queryErr := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); queryErr != nil {
			t.Fatal(queryErr)
		}
		if _, lockErr := blocker.Exec(t.Context(), `SELECT 1 FROM plugin_webhook_subscriptions
			WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, fixture.targetScope, subscription); lockErr != nil {
			t.Fatal(lockErr)
		}
		recoveryConfig := fixture.pool.Config().Copy()
		recoveryConfig.MaxConns, recoveryConfig.MinConns = 1, 1
		recoveryConfig.ConnConfig.RuntimeParams["application_name"] = "plugin_webhook_lease_recovery_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		recoveryPool, poolErr := pgxpool.NewWithConfig(t.Context(), recoveryConfig)
		if poolErr != nil {
			t.Fatal(poolErr)
		}
		defer recoveryPool.Close()
		var recoveryPID int32
		if queryErr := recoveryPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&recoveryPID); queryErr != nil {
			t.Fatal(queryErr)
		}
		recoveryRuntime := &Runtime{config: runtime.config, pool: recoveryPool}
		recovered := make(chan error, 1)
		go func() {
			_, recoverErr := recoveryRuntime.leaseOutbox(context.Background())
			recovered <- recoverErr
		}()
		var blockers []int32
		deadline := time.Now().Add(5 * time.Second)
		for len(blockers) == 0 && time.Now().Before(deadline) {
			if queryErr := fixture.admin.QueryRow(t.Context(), `SELECT pg_blocking_pids($1)`, recoveryPID).Scan(&blockers); queryErr != nil {
				t.Fatal(queryErr)
			}
		}
		if len(blockers) != 1 || blockers[0] != blockerPID {
			t.Fatalf("stale lease recovery blockers = %v want [%d]", blockers, blockerPID)
		}
		newToken := uuid.New()
		if _, updateErr := blocker.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='pending',lease_token=NULL,lease_expires_at=NULL,leased_at=NULL
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND lease_token=$4`,
			fixture.targetScope, subscription, delivery.Value.Delivery.ID, lease.leaseToken); updateErr != nil {
			t.Fatal(updateErr)
		}
		if _, updateErr := blocker.Exec(t.Context(), `UPDATE plugin_webhook_outbox
			SET status='leased',lease_token=$4,lease_expires_at=clock_timestamp()+interval '1 minute',
			    publish_attempt=publish_attempt+1
			WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3 AND status='pending'`,
			fixture.targetScope, subscription, delivery.Value.Delivery.ID, newToken); updateErr != nil {
			t.Fatal(updateErr)
		}
		if commitErr := blocker.Commit(t.Context()); commitErr != nil {
			t.Fatal(commitErr)
		}
		if recoverErr := <-recovered; !errors.Is(recoverErr, errNoOutbox) {
			t.Fatalf("stale lease recovery after renewal = %v want errNoOutbox", recoverErr)
		}
		var actualToken uuid.UUID
		if queryErr := fixture.pool.QueryRow(t.Context(), `SELECT lease_token FROM plugin_webhook_outbox
			WHERE delivery_id=$1`, delivery.Value.Delivery.ID).Scan(&actualToken); queryErr != nil || actualToken != newToken {
			t.Fatalf("renewed lease token = %s,%v want %s", actualToken, queryErr, newToken)
		}
	})

	t.Run("delivery dedupe ACK requires exact wire", func(t *testing.T) {
		delivery, createErr := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, subscription,
			pluginwebhookcontrol.WriteRequest{IdempotencyKey: "runtime-fences-delivery-1"})
		if createErr != nil {
			t.Fatal(createErr)
		}
		var messageID string
		if queryErr := fixture.pool.QueryRow(t.Context(), `SELECT message_id FROM plugin_webhook_outbox
			WHERE delivery_id=$1`, delivery.Value.Delivery.ID).Scan(&messageID); queryErr != nil {
			t.Fatal(queryErr)
		}
		wrongBody := []byte(`{"wrong":true}`)
		wrongDigest := sha256.Sum256(wrongBody)
		wrong := nats.NewMsg(deliverySubject(fixture.jetstreamConfig.DeliverySubjectPrefix,
			fixture.targetScope, subscription, delivery.Value.Delivery.ID))
		wrong.Data = wrongBody
		wrong.Header.Set(nats.MsgIdHdr, messageID)
		wrong.Header.Set("X-CDNCA-Webhook-Id", delivery.Value.Delivery.ID.String())
		wrong.Header.Set("X-CDNCA-Webhook-Queue-Sha256", fmt.Sprintf("%x", wrongDigest[:]))
		wrong.Header.Set(nats.ExpectedStreamHdr, fixture.jetstreamConfig.DeliveryStream)
		wrong.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
		if _, publishErr := fixture.jetstream.PublishMsg(wrong, nats.ExpectStream(fixture.jetstreamConfig.DeliveryStream),
			nats.ExpectLastSequencePerSubject(0)); publishErr != nil {
			t.Fatal(publishErr)
		}
		if publishErr := runtime.publishOutbox(t.Context()); publishErr == nil {
			t.Fatal("delivery Msg-Id dedupe acknowledgement accepted a wrong stored wire")
		}
		assertOutboxStatus(t, fixture.pool, delivery.Value.Delivery.ID, "leased")
	})
}

func TestRuntimeCommitUnknownRecoveryKeepsTheSameAttempt(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	runtime, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{
		Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Commit unknown", TargetURL: "https://commit-unknown.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "commit-unknown-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "commit-unknown-delivery-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	recoveredClaim, err := runtime.claim(t.Context(), item)
	if err != nil || recoveredClaim != claim {
		t.Fatalf("claim commit-unknown recovery = %+v,%v want %+v", recoveredClaim, err, claim)
	}
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatal(err)
	}
	clearSecret(secret)
	recoveredSecret, err := runtime.start(t.Context(), &recoveredClaim, item.digest)
	if err != nil || len(recoveredSecret) != 32 {
		length := len(recoveredSecret)
		clearSecret(recoveredSecret)
		t.Fatalf("start commit-unknown recovery secret length = %d, error = %v", length, err)
	}
	clearSecret(recoveredSecret)
	result := sendResultSuccess()
	if err = runtime.finish(t.Context(), claim, result); err != nil {
		t.Fatal(err)
	}
	if err = runtime.finish(t.Context(), recoveredClaim, result); err != nil {
		t.Fatalf("finish commit-unknown recovery = %v", err)
	}
	var attempts int
	if err = fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_delivery_attempts WHERE delivery_id=$1`,
		delivery.Value.Delivery.ID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("commit-unknown attempts = %d,%v want 1", attempts, err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
}

func TestRuntimeSecretProviderErrorClearsReturnedBytes(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	provider := &bytesAndErrorSecretProvider{secret: bytes.Repeat([]byte{0x5a}, 32)}
	runtime, err := Open(t.Context(), fixture.runtimeConfig(), Dependencies{
		Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Secret error", TargetURL: "https://secret-error.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "secret-error-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "secret-error-delivery-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	secret, startErr := runtime.start(t.Context(), &claim, item.digest)
	returned := secret != nil
	clearSecret(secret)
	if returned || startErr == nil {
		t.Fatalf("start with bytes+error returned secret = %t, error = %v", returned, startErr)
	}
	if !bytes.Equal(provider.secret, make([]byte, len(provider.secret))) {
		t.Fatal("secret provider error left plaintext")
	}
}

func TestRuntimeRecoversSameEpochDeliveryRetentionLoss(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	// The lease must cover a NATS publish plus 084's in-database Ed25519
	// attestation check (~40ms), and may not exceed the duplicate window.
	fixture.jetstreamConfig.DuplicateWindow = 2 * time.Second
	if _, err := fixture.jetstream.UpdateStream(deliveryStreamConfig(fixture.jetstreamConfig), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.jetstream.UpdateStream(deadLetterStreamConfig(fixture.jetstreamConfig), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	deliverer := &integrationDeliverer{result: sendResultSuccess()}
	config := fixture.runtimeConfig()
	config.LeaseDuration = 1500 * time.Millisecond
	runtime, err := Open(t.Context(), config, Dependencies{Deliverer: deliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Retention recovery", TargetURL: "https://retention-recovery.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "retention-recovery-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "retention-recovery-delivery-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	epoch, sequence := assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
	if err = fixture.jetstream.DeleteMsg(fixture.jetstreamConfig.DeliveryStream, sequence, nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if current, epochErr := runtime.deliveryStreamEpoch(t.Context()); epochErr != nil || current != epoch {
		t.Fatalf("same-epoch retention setup = %d,%v want %d", current, epochErr, epoch)
	}
	time.Sleep(2 * fixture.jetstreamConfig.DuplicateWindow)
	if err = runtime.recoverDeliveryStream(t.Context()); err != nil {
		t.Fatal(err)
	}
	info, err := fixture.jetstream.StreamInfo(fixture.jetstreamConfig.DeliveryStream, nats.Context(t.Context()))
	if err != nil || info.State.Msgs != 1 || info.State.LastSeq <= sequence {
		t.Fatalf("same-epoch recovered stream = %+v,%v old sequence %d", info, err, sequence)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
	if items := deliverer.snapshot(); len(items) != 1 || items[0].DeliveryID != delivery.Value.Delivery.ID {
		t.Fatalf("same-epoch recovered deliveries = %+v", items)
	}
}

func TestRuntimeDeliveryStreamRecreationRejectsStaleEpoch(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	dependencies := Dependencies{Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets}
	runtime, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Delivery stream epoch", TargetURL: "https://delivery-stream-epoch.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "delivery-stream-epoch-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "delivery-stream-epoch-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	oldEpoch, oldSequence := assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
	stored, err := fixture.jetstream.GetMsg(config.JetStream.DeliveryStream, oldSequence, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = fixture.jetstream.DeleteConsumer(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable); err != nil {
		t.Fatal(err)
	}
	if err = fixture.jetstream.DeleteStream(config.JetStream.DeliveryStream); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.jetstream.AddStream(deliveryStreamConfig(config.JetStream), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.jetstream.AddConsumer(config.JetStream.DeliveryStream, consumerConfig(config.JetStream), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	newEpoch, err := (&Runtime{config: config, jetstream: fixture.jetstream}).deliveryStreamEpoch(t.Context())
	if err != nil || newEpoch == oldEpoch {
		t.Fatalf("recreated delivery stream epoch = %d,%v old=%d", newEpoch, err, oldEpoch)
	}
	wire := &nats.Msg{Subject: stored.Subject, Data: append([]byte(nil), stored.Data...), Header: cloneNATSHeader(stored.Header)}
	ack, err := fixture.jetstream.PublishMsg(wire, nats.ExpectStream(config.JetStream.DeliveryStream),
		nats.ExpectLastSequencePerSubject(0))
	if err != nil || ack == nil || ack.Sequence == 0 {
		t.Fatalf("publish recreated delivery wire = %+v,%v", ack, err)
	}
	if _, err = (&Runtime{config: config, pool: fixture.pool}).loadDeliveryWithBrokerIdentity(t.Context(),
		fixture.targetScope, created.Value.Subscription.ID, delivery.Value.Delivery.ID, newEpoch, ack.Sequence); err == nil {
		t.Fatal("stale delivery stream epoch was accepted")
	}
	runtime, err = Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	info, err := fixture.jetstream.ConsumerInfo(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable,
		nats.Context(t.Context()))
	if err != nil || info.AckFloor.Stream >= ack.Sequence {
		t.Fatalf("stale delivery stream item was acknowledged: info=%+v err=%v", info, err)
	}
}

func TestRuntimeDeliveryStreamRecreationRecoversPublishedDeliveryOnce(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	deliverer := &integrationDeliverer{result: sendResultSuccess()}
	dependencies := Dependencies{Deliverer: deliverer, Secrets: fixture.secrets}
	runtime, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Delivery stream recovery", TargetURL: "https://delivery-stream-recovery.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "delivery-stream-recovery-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "delivery-stream-recovery-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	oldEpoch, oldSequence := assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = fixture.jetstream.DeleteConsumer(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable); err != nil {
		t.Fatal(err)
	}
	if err = fixture.jetstream.DeleteStream(config.JetStream.DeliveryStream); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.jetstream.AddStream(deliveryStreamConfig(config.JetStream), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.jetstream.AddConsumer(config.JetStream.DeliveryStream, consumerConfig(config.JetStream), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	newEpoch, err := (&Runtime{config: config, jetstream: fixture.jetstream}).deliveryStreamEpoch(t.Context())
	if err != nil || newEpoch == oldEpoch {
		t.Fatalf("recreated delivery stream epoch = %d,%v old=%d", newEpoch, err, oldEpoch)
	}
	runtime, err = Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	second, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	reconciled := make(chan error, 2)
	for _, candidate := range []*Runtime{runtime, second} {
		go func(candidate *Runtime) { reconciled <- candidate.reconcile(context.Background()) }(candidate)
	}
	for range 2 {
		if reconcileErr := <-reconciled; reconcileErr != nil {
			t.Fatal(reconcileErr)
		}
	}
	stream, err := fixture.jetstream.StreamInfo(config.JetStream.DeliveryStream, nats.Context(t.Context()))
	if err != nil || stream.State.Msgs != 1 {
		t.Fatalf("recovered delivery stream = %+v,%v want exactly one message", stream, err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	if items := deliverer.snapshot(); len(items) != 1 || items[0].DeliveryID != delivery.Value.Delivery.ID {
		t.Fatalf("recovered deliveries = %+v", items)
	}
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")
	var retainedEpoch, retainedSequence string
	if err = fixture.pool.QueryRow(t.Context(), `SELECT nats_stream_created_unix_nano::text,nats_stream_sequence::text
		FROM plugin_webhook_deliveries WHERE id=$1`, delivery.Value.Delivery.ID).Scan(&retainedEpoch, &retainedSequence); err != nil {
		t.Fatal(err)
	}
	if retainedEpoch != strconv.FormatInt(oldEpoch, 10) || retainedSequence != strconv.FormatUint(oldSequence, 10) {
		t.Fatalf("immutable broker identity changed to %s/%s want %d/%d", retainedEpoch, retainedSequence, oldEpoch, oldSequence)
	}
}

func TestRuntimeDeliveryStreamRecoverySurvivesCommitAndAckLoss(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	fixture.jetstreamConfig.OperationTimeout = 100 * time.Millisecond
	fixture.jetstreamConfig.FetchTimeout = 50 * time.Millisecond
	fixture.jetstreamConfig.AckWait = 500 * time.Millisecond
	if _, err := fixture.jetstream.UpdateConsumer(fixture.jetstreamConfig.DeliveryStream,
		consumerConfig(fixture.jetstreamConfig), nats.Context(t.Context())); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	baseDeliverer := &integrationDeliverer{result: sendResultSuccess()}
	dependencies := Dependencies{Deliverer: baseDeliverer, Secrets: fixture.secrets}
	runtime, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Delivery stream loss recovery", TargetURL: "https://delivery-stream-loss-recovery.example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: "delivery-stream-loss-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: "delivery-stream-loss-test-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	oldEpoch, oldSequence := assertDeliveryBrokerIdentity(t, fixture, delivery.Value.Delivery.ID)
	oldWire, err := fixture.jetstream.GetMsg(config.JetStream.DeliveryStream, oldSequence, nats.Context(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	recreateDeliveryStream := func() int64 {
		t.Helper()
		if err = fixture.jetstream.DeleteConsumer(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable); err != nil {
			t.Fatal(err)
		}
		if err = fixture.jetstream.DeleteStream(config.JetStream.DeliveryStream); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.jetstream.AddStream(deliveryStreamConfig(config.JetStream), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.jetstream.AddConsumer(config.JetStream.DeliveryStream,
			consumerConfig(config.JetStream), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		epoch, epochErr := (&Runtime{config: config, jetstream: fixture.jetstream}).deliveryStreamEpoch(t.Context())
		if epochErr != nil || epoch == oldEpoch {
			t.Fatalf("recreated delivery stream epoch = %d,%v old=%d", epoch, epochErr, oldEpoch)
		}
		return epoch
	}
	rejectedEpoch := recreateDeliveryStream()
	staleWire := &nats.Msg{Subject: oldWire.Subject, Data: append([]byte(nil), oldWire.Data...), Header: cloneNATSHeader(oldWire.Header)}
	staleAck, err := fixture.jetstream.PublishMsg(staleWire, nats.ExpectStream(config.JetStream.DeliveryStream),
		nats.ExpectLastSequencePerSubject(0))
	if err != nil || staleAck == nil || staleAck.Sequence == 0 {
		t.Fatalf("publish unmarked stale wire = %+v,%v", staleAck, err)
	}
	runtime, err = Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.processOne(t.Context()); err != nil {
		t.Fatal(err)
	}
	consumer, err := fixture.jetstream.ConsumerInfo(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable,
		nats.Context(t.Context()))
	if err != nil || consumer.AckFloor.Stream >= staleAck.Sequence {
		t.Fatalf("unmarked stale wire was acknowledged: info=%+v err=%v", consumer, err)
	}
	if err = runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	recoveryEpoch := recreateDeliveryStream()
	if recoveryEpoch == rejectedEpoch {
		t.Fatal("second delivery stream recreation did not advance epoch")
	}
	first, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	lostAck := &blockedLostAckDeliveryJetStream{
		JetStreamContext: first.jetstream, started: make(chan struct{}), release: make(chan struct{}),
	}
	first.jetstream = lostAck
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.recoverDeliveryStream(context.Background()) }()
	select {
	case <-lostAck.started:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery recovery publication did not reach PubAck-loss boundary")
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.recoverDeliveryStream(context.Background()) }()
	select {
	case secondErr := <-secondDone:
		if secondErr != nil {
			t.Fatal(secondErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent recovery publisher did not complete")
	}
	close(lostAck.release)
	if firstErr := <-firstDone; firstErr != nil {
		t.Fatal(firstErr)
	}
	recoveredStream, err := fixture.jetstream.StreamInfo(config.JetStream.DeliveryStream, nats.Context(t.Context()))
	if err != nil || recoveredStream.State.Msgs != 1 || recoveredStream.State.LastSeq == 0 {
		t.Fatalf("recovery CAS stream = %+v,%v", recoveredStream, err)
	}
	recoverySequence := recoveredStream.State.LastSeq
	if err = first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = second.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	ackLossDeliverer := &connectionClosingDeliverer{integrationDeliverer: baseDeliverer}
	ackLossConfig := config
	ackLossConfig.NATS = nil
	ackLossConfig.NATSURL = strings.TrimSpace(os.Getenv(runtimeNATSEnv))
	ackLossConfig.NATSName = "plugin-webhook-recovery-ack-loss"
	ackLossRuntime, err := Open(t.Context(), ackLossConfig,
		Dependencies{Deliverer: ackLossDeliverer, Secrets: fixture.secrets})
	if err != nil {
		t.Fatal(err)
	}
	ackLossDeliverer.close = ackLossRuntime.connection.Close
	if processErr := ackLossRuntime.processOne(t.Context()); processErr == nil {
		t.Fatal("delivery ACK loss did not surface after the HTTP outcome committed")
	}
	_ = ackLossRuntime.Close(t.Context())
	assertDeliveryStatus(t, fixture.pool, delivery.Value.Delivery.ID, "delivered")

	restarted, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close(context.Background()) })
	deadline := time.Now().Add(2 * config.JetStream.AckWait)
	for {
		processErr := restarted.processOne(t.Context())
		if processErr == nil {
			break
		}
		if (!errors.Is(processErr, errNoMessage) && !errors.Is(processErr, context.DeadlineExceeded)) ||
			time.Now().After(deadline) {
			t.Fatalf("recovery redelivery after ACK loss = %v", processErr)
		}
	}
	if items := baseDeliverer.snapshot(); len(items) != 1 || items[0].DeliveryID != delivery.Value.Delivery.ID {
		t.Fatalf("recovery HTTP deliveries = %+v", items)
	}
	var attempts, deadLetters int
	if err = fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_delivery_attempts
		WHERE delivery_id=$1`, delivery.Value.Delivery.ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err = fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_dead_letters
		WHERE delivery_id=$1`, delivery.Value.Delivery.ID).Scan(&deadLetters); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || deadLetters != 0 {
		t.Fatalf("recovery terminal facts = attempts:%d dead_letters:%d", attempts, deadLetters)
	}
	consumer, err = fixture.jetstream.ConsumerInfo(config.JetStream.DeliveryStream, config.JetStream.DeliveryDurable,
		nats.Context(t.Context()))
	if err != nil || consumer.AckFloor.Stream < recoverySequence {
		t.Fatalf("recovery redelivery was not acknowledged: info=%+v err=%v", consumer, err)
	}
	var retainedEpoch, retainedSequence string
	if err = fixture.pool.QueryRow(t.Context(), `SELECT nats_stream_created_unix_nano::text,nats_stream_sequence::text
		FROM plugin_webhook_deliveries WHERE id=$1`, delivery.Value.Delivery.ID).Scan(&retainedEpoch, &retainedSequence); err != nil {
		t.Fatal(err)
	}
	if retainedEpoch != strconv.FormatInt(oldEpoch, 10) || retainedSequence != strconv.FormatUint(oldSequence, 10) {
		t.Fatalf("immutable broker identity changed to %s/%s want %d/%d", retainedEpoch, retainedSequence, oldEpoch, oldSequence)
	}
}

func TestRuntimeDeadLetterProgressSurvivesEveryBatchRestart(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	dependencies := Dependencies{
		Deliverer: &integrationDeliverer{result: sendResultSuccess()},
		Secrets:   fixture.secrets,
	}
	runtime, err := Open(t.Context(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	row := createPendingDeadLetter(t, fixture, runtime, "persistent-dlq")

	last := publishStrictDLQFillers(t, fixture.jetstream, config, 0, 10)
	target, err := deadLetterMessage(row, config.JetStream.DeadLetterStream)
	if err != nil {
		t.Fatal(err)
	}
	target.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(last, 10))
	ack, err := fixture.jetstream.PublishMsg(target, nats.ExpectStream(config.JetStream.DeadLetterStream),
		nats.ExpectLastSequence(last))
	if err != nil || ack == nil || ack.Sequence != last+1 {
		t.Fatalf("publish crash-boundary DLQ target = %+v,%v want sequence %d", ack, err, last+1)
	}
	targetSequence := ack.Sequence
	snapshot := publishStrictDLQFillers(t, fixture.jetstream, config, 10, 81)
	for sequence := uint64(1); sequence < targetSequence; sequence++ {
		if err = fixture.jetstream.DeleteMsg(config.JetStream.DeadLetterStream, sequence); err != nil {
			t.Fatal(err)
		}
	}
	for _, sequence := range []uint64{targetSequence + 7, targetSequence + 23, targetSequence + 55} {
		if err = fixture.jetstream.DeleteMsg(config.JetStream.DeadLetterStream, sequence); err != nil {
			t.Fatal(err)
		}
	}

	var previousCursor uint64
	for batch := 0; batch < 8; batch++ {
		recoverErr := runtime.recoverDeadLetter(t.Context(), row)
		state, phase, epoch, high, boundary, cursor := loadDeadLetterProgress(t, fixture.pool, row)
		if state == "acknowledged" {
			if recoverErr != nil || phase != "complete" || epoch != nil || high != nil || boundary != nil || cursor != nil {
				t.Fatalf("completed durable DLQ recovery = state:%s phase:%s epoch:%v high:%v boundary:%v cursor:%v err:%v",
					state, phase, epoch, high, boundary, cursor, recoverErr)
			}
			assertDeadLetterState(t, fixture.pool, row, "acknowledged", targetSequence)
			return
		}
		if !errors.Is(recoverErr, errDeadLetterScanPending) {
			t.Fatalf("durable DLQ batch %d error = %v", batch, recoverErr)
		}
		if phase != "reverse_scan" || epoch == nil || high == nil || *high != snapshot || boundary == nil ||
			*boundary != targetSequence || cursor == nil {
			t.Fatalf("durable DLQ batch %d progress = state:%s phase:%s epoch:%v high:%v boundary:%v cursor:%v",
				batch, state, phase, epoch, high, boundary, cursor)
		}
		if previousCursor != 0 && *cursor >= previousCursor {
			t.Fatalf("durable DLQ cursor did not decrease across restart: before=%d after=%d", previousCursor, *cursor)
		}
		previousCursor = *cursor
		publishStrictDLQFillers(t, fixture.jetstream, config, 1000+batch*33, 33)
		if err = runtime.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		runtime, err = Open(t.Context(), config, dependencies)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("durable DLQ recovery did not reach the exact crash-boundary message")
}

func TestRuntimeDeadLetterForwardScanAndEpochReset(t *testing.T) {
	t.Run("corrupt empty state fails closed without PG progress", func(t *testing.T) {
		fixture := newRuntimeIntegrationFixture(t)
		if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
			t.Fatal(err)
		}
		fixture.installControl(t)
		config := fixture.runtimeConfig()
		runtime, err := Open(t.Context(), config, Dependencies{
			Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtime.Close(context.Background()) })
		row := createPendingDeadLetter(t, fixture, runtime, "corrupt-empty-dlq")
		stream, err := runtime.deadLetterStreamSnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		stream.messages, stream.first, stream.last = 0, 0, 7
		if resetErr := runtime.resetDeadLetterProgress(t.Context(), row, stream); !errors.Is(resetErr, errDeadLetterState) {
			t.Fatalf("corrupt empty DLQ reset = %v want errDeadLetterState", resetErr)
		}
		state, phase, epoch, high, boundary, cursor := loadDeadLetterProgress(t, fixture.pool, row)
		if state != "pending" || phase != "uninitialized" || epoch != nil || high != nil || boundary != nil || cursor != nil {
			t.Fatalf("corrupt empty DLQ persisted progress = %s/%s/%v/%v/%v/%v",
				state, phase, epoch, high, boundary, cursor)
		}
	})

	t.Run("retained empty stream publishes after last sequence", func(t *testing.T) {
		fixture := newRuntimeIntegrationFixture(t)
		if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
			t.Fatal(err)
		}
		fixture.installControl(t)
		config := fixture.runtimeConfig()
		runtime, err := Open(t.Context(), config, Dependencies{
			Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtime.Close(context.Background()) })
		last := publishStrictDLQFillers(t, fixture.jetstream, config, 24000, 3)
		for sequence := uint64(1); sequence <= last; sequence++ {
			if err = fixture.jetstream.DeleteMsg(config.JetStream.DeadLetterStream, sequence); err != nil {
				t.Fatal(err)
			}
		}
		empty, err := fixture.jetstream.StreamInfo(config.JetStream.DeadLetterStream, nats.Context(t.Context()))
		if err != nil || empty.State.Msgs != 0 || empty.State.LastSeq != last ||
			empty.State.FirstSeq != empty.State.LastSeq+1 {
			t.Fatalf("retained empty DLQ state = %+v,%v", empty, err)
		}
		row := createPendingDeadLetter(t, fixture, runtime, "retained-empty-dlq")
		if err = runtime.recoverDeadLetter(t.Context(), row); err != nil {
			t.Fatal(err)
		}
		assertDeadLetterState(t, fixture.pool, row, "acknowledged", last+1)
		published, err := fixture.jetstream.StreamInfo(config.JetStream.DeadLetterStream, nats.Context(t.Context()))
		if err != nil || published.State.Msgs != 1 || published.State.LastSeq != last+1 {
			t.Fatalf("retained empty DLQ publication = %+v,%v", published, err)
		}
	})

	t.Run("forward scan resumes after restart", func(t *testing.T) {
		fixture := newRuntimeIntegrationFixture(t)
		if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
			t.Fatal(err)
		}
		fixture.installControl(t)
		config := fixture.runtimeConfig()
		dependencies := Dependencies{Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets}
		runtime, err := Open(t.Context(), config, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtime.Close(context.Background()) })
		row := createPendingDeadLetter(t, fixture, runtime, "forward-dlq")
		stream, err := runtime.deadLetterStreamSnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = runtime.resetDeadLetterProgress(t.Context(), row, stream); err != nil {
			t.Fatal(err)
		}
		row, err = runtime.loadDeadLetter(t.Context(), row.tenantScope, row.subscription, row.delivery)
		if err != nil || row.phase != "publish_ready" || row.high == nil || *row.high != 0 {
			t.Fatalf("initial forward-scan row = %+v,%v", row, err)
		}
		unknown := &unknownDLQPublishJetStream{
			JetStreamContext: runtime.jetstream, config: config, targetMessageID: row.messageID,
			fillerBefore: 40, fillerAfter: 40,
		}
		runtime.jetstream = unknown
		if recoverErr := runtime.recoverDeadLetter(t.Context(), row); !errors.Is(recoverErr, errDeadLetterScanPending) {
			t.Fatalf("commit-unknown forward scan = %v", recoverErr)
		}
		state, phase, epoch, high, boundary, cursor := loadDeadLetterProgress(t, fixture.pool, row)
		if state != "pending" || phase != "forward_scan" || epoch == nil || high == nil || boundary == nil ||
			cursor == nil || *high != 81 || *boundary != 1 || *cursor != 33 || unknown.publishedSequence != 41 {
			t.Fatalf("persisted forward scan = state:%s phase:%s epoch:%v high:%v boundary:%v cursor:%v target:%d",
				state, phase, epoch, high, boundary, cursor, unknown.publishedSequence)
		}
		if err = runtime.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		publishStrictDLQFillers(t, fixture.jetstream, config, 22000, 33)
		runtime, err = Open(t.Context(), config, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		if err = runtime.recoverDeadLetter(t.Context(), row); err != nil {
			t.Fatal(err)
		}
		assertDeadLetterState(t, fixture.pool, row, "acknowledged", unknown.publishedSequence)
	})

	t.Run("stream recreation resets epoch", func(t *testing.T) {
		fixture := newRuntimeIntegrationFixture(t)
		if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
			t.Fatal(err)
		}
		fixture.installControl(t)
		config := fixture.runtimeConfig()
		dependencies := Dependencies{Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets}
		runtime, err := Open(t.Context(), config, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close(context.Background())
		row := createPendingDeadLetter(t, fixture, runtime, "epoch-dlq")
		publishStrictDLQFillers(t, fixture.jetstream, config, 23000, 40)
		oldStream, err := runtime.deadLetterStreamSnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = runtime.resetDeadLetterProgress(t.Context(), row, oldStream); err != nil {
			t.Fatal(err)
		}
		if err = fixture.jetstream.DeleteStream(config.JetStream.DeadLetterStream, nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		if _, err = fixture.jetstream.AddStream(deadLetterStreamConfig(config.JetStream), nats.Context(t.Context())); err != nil {
			t.Fatal(err)
		}
		newStream, err := runtime.deadLetterStreamSnapshot(t.Context())
		if err != nil || newStream.epoch == oldStream.epoch || newStream.last != 0 {
			t.Fatalf("recreated DLQ stream = %+v,%v old=%+v", newStream, err, oldStream)
		}
		if err = runtime.recoverDeadLetter(t.Context(), row); err != nil {
			t.Fatal(err)
		}
		assertDeadLetterState(t, fixture.pool, row, "acknowledged", 1)
	})
}

func newPendingDLQRuntime(t *testing.T, keys ...string) (*runtimeIntegrationFixture, *Runtime, []deadLetterRow) {
	t.Helper()
	fixture := newRuntimeIntegrationFixture(t)
	if err := database.Migrate(t.Context(), fixture.pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture.installControl(t)
	config := fixture.runtimeConfig()
	config.PollInterval = 10 * time.Millisecond
	runtime, err := Open(t.Context(), config, Dependencies{
		Deliverer: &integrationDeliverer{result: sendResultSuccess()}, Secrets: fixture.secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	rows := make([]deadLetterRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, createPendingDeadLetter(t, fixture, runtime, key))
	}
	return fixture, runtime, rows
}

func startRuntimeLoop(t *testing.T, runtime *Runtime) {
	t.Helper()
	runCtx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() { runErr <- runtime.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		if err := runtime.Close(context.Background()); err != nil {
			t.Errorf("close runtime loop: %v", err)
		}
		select {
		case err := <-runErr:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("runtime loop: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("runtime loop did not stop")
		}
	})
}

func createPendingDeadLetter(t *testing.T, fixture *runtimeIntegrationFixture, runtime *Runtime, key string) deadLetterRow {
	t.Helper()
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, pluginwebhookcontrol.CreateSubscriptionRequest{
		Name: "Durable DLQ " + key, TargetURL: "https://" + key + ".example.com/webhook",
		EventTypes: []string{pluginwebhookcontrol.EventTypeTest}, IdempotencyKey: key + "-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := fixture.store.CreateTestDelivery(t.Context(), fixture.actor, created.Value.Subscription.ID,
		pluginwebhookcontrol.WriteRequest{IdempotencyKey: key + "-delivery"})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.publishOutbox(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := runtime.loadDelivery(t.Context(), delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := runtime.claim(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := runtime.start(t.Context(), &claim, item.digest)
	if err != nil {
		t.Fatal(err)
	}
	clearSecret(secret)
	if err = runtime.finish(t.Context(), claim, pluginwebhook.SendResult{Code: "remote_rejected", StatusCode: 401}); err != nil {
		t.Fatal(err)
	}
	row, err := runtime.loadDeadLetter(t.Context(), fixture.targetScope, created.Value.Subscription.ID, delivery.Value.Delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func publishStrictDLQFillers(t *testing.T, jetstream nats.JetStreamContext, config Config, start, count int) uint64 {
	t.Helper()
	last, err := publishStrictDLQFillersRaw(jetstream, config, start, count)
	if err != nil {
		t.Fatal(err)
	}
	return last
}

func publishStrictDLQFillersRaw(jetstream nats.JetStreamContext, config Config, start, count int) (uint64, error) {
	info, err := jetstream.StreamInfo(config.JetStream.DeadLetterStream)
	if err != nil {
		return 0, err
	}
	last := info.State.LastSeq
	for index := 0; index < count; index++ {
		message := nats.NewMsg(config.JetStream.DeadLetterSubject)
		message.Data = []byte(fmt.Sprintf(`{"filler":%d}`, start+index))
		message.Header.Set(nats.MsgIdHdr, "plugin-webhook-dlq-v1-"+fmt.Sprintf("%064x", 100000+start+index))
		message.Header.Set(nats.ExpectedStreamHdr, config.JetStream.DeadLetterStream)
		message.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(last, 10))
		digest := sha256.Sum256(message.Data)
		message.Header.Set("X-CDNCA-Webhook-DLQ-Payload-Sha256", fmt.Sprintf("%x", digest[:]))
		ack, publishErr := jetstream.PublishMsg(message, nats.ExpectStream(config.JetStream.DeadLetterStream),
			nats.ExpectLastSequence(last))
		if publishErr != nil || ack == nil || ack.Sequence != last+1 {
			return 0, fmt.Errorf("publish strict DLQ filler %d = %+v,%v want sequence %d", start+index, ack, publishErr, last+1)
		}
		last = ack.Sequence
	}
	return last, nil
}

func loadDeadLetterProgress(t *testing.T, pool *pgxpool.Pool, row deadLetterRow) (
	string, string, *string, *uint64, *uint64, *uint64,
) {
	t.Helper()
	var state, phase string
	var epochText, highText, boundaryText, cursorText *string
	if err := pool.QueryRow(t.Context(), `SELECT publish_state,reconcile_phase,
		reconcile_stream_created_unix_nano::text,reconcile_high_watermark::text,
		reconcile_scan_boundary::text,reconcile_cursor::text
		FROM plugin_webhook_dead_letters WHERE tenant_scope_id=$1 AND subscription_id=$2 AND delivery_id=$3`,
		row.tenantScope, row.subscription, row.delivery).Scan(
		&state, &phase, &epochText, &highText, &boundaryText, &cursorText); err != nil {
		t.Fatal(err)
	}
	parse := func(name string, value *string) *uint64 {
		if value == nil {
			return nil
		}
		parsed, err := strconv.ParseUint(*value, 10, 64)
		if err != nil {
			t.Fatalf("parse DLQ %s %q: %v", name, *value, err)
		}
		return &parsed
	}
	return state, phase, epochText, parse("high watermark", highText), parse("scan boundary", boundaryText),
		parse("cursor", cursorText)
}

func TestRuntimePGTwoConnectionLockOrdering(t *testing.T) {
	databaseURL := os.Getenv(runtimeDatabaseEnv)
	if databaseURL == "" {
		t.Skip(runtimeDatabaseEnv + " is required")
	}
	adminConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if adminConfig.ConnConfig.Host == "" || adminConfig.ConnConfig.Host[0] != '/' {
		t.Fatalf("lock-order test requires PostgreSQL Unix socket, got host %q", adminConfig.ConnConfig.Host)
	}
	admin, err := pgxpool.NewWithConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "plugin_webhook_runtime_lock_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE")
	})
	config := adminConfig
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 1
	config.MinConns = 1
	first, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	setup, err := admin.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Release()
	if _, err := setup.Exec(t.Context(), "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE plugin_webhook_subscriptions (
			tenant_scope_id uuid NOT NULL, id uuid NOT NULL, status text NOT NULL,
			revision numeric NOT NULL, lifecycle_sequence numeric NOT NULL,
			active_secret_version_id uuid NOT NULL, revoke_sequence numeric, revoked_at timestamptz,
			PRIMARY KEY (tenant_scope_id,id))`,
		`CREATE TABLE plugin_webhook_deliveries (
			tenant_scope_id uuid NOT NULL, subscription_id uuid NOT NULL, id uuid NOT NULL,
			status text NOT NULL, attempt_count numeric NOT NULL, next_attempt_at timestamptz,
			PRIMARY KEY (tenant_scope_id,subscription_id,id))`,
		`CREATE TABLE plugin_webhook_delivery_attempts (
			tenant_scope_id uuid NOT NULL, subscription_id uuid NOT NULL, delivery_id uuid NOT NULL,
			claim_token uuid NOT NULL, attempt_number numeric NOT NULL, claim_sequence numeric NOT NULL,
			claimed_subscription_revision numeric NOT NULL, secret_version_id uuid NOT NULL,
			status text NOT NULL, claimed_at timestamptz, started_at timestamptz, plugin_webhook_recorded_at timestamptz,
			request_sha256 bytea, http_status integer, failure_code text, response_sha256 bytea, response_bytes integer,
			PRIMARY KEY (tenant_scope_id,subscription_id,delivery_id,attempt_number))`,
	} {
		if _, err := setup.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	tenantScope, subscription, delivery, secretVersion, token := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := setup.Exec(t.Context(), `INSERT INTO plugin_webhook_subscriptions
		(tenant_scope_id,id,status,revision,lifecycle_sequence,active_secret_version_id)
		VALUES($1,$2,'active',3,9,$3)`, tenantScope, subscription, secretVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(t.Context(), `INSERT INTO plugin_webhook_deliveries
		(tenant_scope_id,subscription_id,id,status,attempt_count) VALUES($1,$2,$3,'claimed',1)`, tenantScope, subscription, delivery); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(t.Context(), `INSERT INTO plugin_webhook_delivery_attempts
		(tenant_scope_id,subscription_id,delivery_id,claim_token,attempt_number,claim_sequence,
		claimed_subscription_revision,secret_version_id,status,claimed_at,started_at,plugin_webhook_recorded_at)
		VALUES($1,$2,$3,$4,1,9,3,$5,'started',clock_timestamp(),clock_timestamp(),clock_timestamp())`,
		tenantScope, subscription, delivery, token, secretVersion); err != nil {
		t.Fatal(err)
	}
	claim := claimRow{tenantScope: tenantScope, subscription: subscription, delivery: delivery,
		token: token, secretVersion: secretVersion, attempt: 1, claimSequence: 9, claimedRevision: 3}
	exercise := func(lockAttemptSecond bool) {
		t.Helper()
		firstTx, beginErr := first.Begin(t.Context())
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		if _, lockErr := lockSubscription(t.Context(), firstTx, tenantScope, subscription); lockErr != nil {
			t.Fatal(lockErr)
		}
		if _, _, _, lockErr := lockDelivery(t.Context(), firstTx, tenantScope, subscription, delivery); lockErr != nil {
			t.Fatal(lockErr)
		}
		if _, lockErr := lockAttempt(t.Context(), firstTx, claim); lockErr != nil {
			t.Fatal(lockErr)
		}
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			secondTx, secondErr := second.Begin(context.Background())
			if secondErr != nil {
				done <- secondErr
				return
			}
			close(started)
			_, secondErr = lockSubscription(context.Background(), secondTx, tenantScope, subscription)
			if secondErr == nil {
				_, _, _, secondErr = lockDelivery(context.Background(), secondTx, tenantScope, subscription, delivery)
			}
			if secondErr == nil && lockAttemptSecond {
				_, secondErr = lockAttempt(context.Background(), secondTx, claim)
			}
			if rollbackErr := secondTx.Rollback(context.Background()); secondErr == nil && rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				secondErr = rollbackErr
			}
			done <- secondErr
		}()
		<-started
		if err := firstTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("second transaction did not complete after first lock commit")
		}
	}
	exercise(false)
	exercise(true)
}
