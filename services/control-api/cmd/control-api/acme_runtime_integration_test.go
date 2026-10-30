//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/cdnca/cdnca/services/control-api/internal/acmehttp01"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestConfiguredACMEProcessRuntimeLeavesSiteScopedOverlayBacklogNetworkZero(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	backlog := seedSiteScopedOverlayBacklog(t, pool, "cdnca.agent.commands.acme-http01")
	before := readSiteScopedOverlayBacklog(t, pool, backlog.outboxID)

	cfg := validACMERuntimeConfig()
	cfg.ACMEPollInterval = 10 * time.Millisecond
	setValidACMEDNSHandleEnvironment(t)
	runtime, err := openConfiguredACMEProcessRuntime(t.Context(), cfg, pool)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || runtime.ArtifactStore() != nil {
		t.Fatalf("DNS-only runtime=%v artifact_store=%v", runtime, runtime.ArtifactStore())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for runtime.Ready() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := runtime.Ready(); err != nil {
		cancel()
		t.Fatalf("DNS-only runtime readiness = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	after := readSiteScopedOverlayBacklog(t, pool, backlog.outboxID)
	if after != before {
		cancel()
		t.Fatalf("site-scoped backlog changed: before=%+v after=%+v", before, after)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DNS-only runtime cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS-only runtime did not stop")
	}
	if runtime.Ready() == nil {
		t.Fatal("stopped DNS-only runtime remained ready")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
}

func TestACMEHTTP01DispatcherReconcilesExpiredPublicationBeforeClaim(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	pool := openControlRuntimeDatabase(t)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	subjectPrefix := "cdnca.test." + suffix + ".acme-http01"
	backlog := seedSiteScopedOverlayBacklog(t, pool, subjectPrefix)

	connection, err := nats.Connect(natsURL, nats.Name("acme-http01-dispatch-order-test"), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	stream := "ACME_HTTP01_" + suffix
	if _, err := jetstream.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{subjectPrefix + ".>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jetstream.DeleteStream(stream) }()

	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifactConfig := acmehttp01.DefaultArtifactConfig()
	artifactConfig.Clock = func() time.Time { return backlog.now }
	artifactConfig.SigningKeyID = "dispatch-order-key"
	artifactConfig.SigningKey = signingKey
	artifacts, err := acmehttp01.NewArtifactStore(pool, backlog.cipher, artifactConfig)
	if err != nil {
		t.Fatal(err)
	}
	dispatchConfig := acmehttp01.DefaultDispatcherConfig()
	dispatchConfig.Clock = func() time.Time { return backlog.now.Add(11 * time.Minute) }
	dispatchConfig.Stream = stream
	dispatchConfig.OperationTimeout = time.Second
	dispatchConfig.LeaseDuration = 5 * time.Second
	dispatcher, err := acmehttp01.NewDispatcher(backlog.service, artifacts, connection, dispatchConfig)
	if err != nil {
		t.Fatal(err)
	}
	published, err := dispatcher.PublishBatch(t.Context())
	if err != nil || published != 0 {
		t.Fatalf("PublishBatch() published=%d error=%v", published, err)
	}
	state := readSiteScopedOverlayBacklog(t, pool, backlog.outboxID)
	if state.Status != "exhausted" || state.PublishAttempts != 0 ||
		state.AttemptEvents != 1 || state.LatestState != acmeedge.DeploymentTimedOut {
		t.Fatalf("reconciled backlog = %+v", state)
	}
	streamInfo, err := jetstream.StreamInfo(stream)
	if err != nil {
		t.Fatal(err)
	}
	if streamInfo.State.Msgs != 0 {
		t.Fatalf("expired site-scoped command messages = %d", streamInfo.State.Msgs)
	}
}

type processOverlayAuthorizer struct {
	now time.Time
}

func (a processOverlayAuthorizer) AuthorizeOverlay(
	context.Context,
	pgx.Tx,
	acmeedge.EntitlementRequest,
) (acmeedge.EntitlementDecision, error) {
	return acmeedge.EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: acmeedge.EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: a.now,
	}, nil
}

type siteScopedOverlayBacklog struct {
	Status          string
	PublishAttempts int
	AttemptEvents   int
	LatestState     string
}

type seededSiteScopedOverlayBacklog struct {
	outboxID uuid.UUID
	service  *acmeedge.Service
	cipher   *acmehttp01.Cipher
	now      time.Time
}

func readSiteScopedOverlayBacklog(t *testing.T, pool *pgxpool.Pool, outboxID uuid.UUID) siteScopedOverlayBacklog {
	t.Helper()
	var state siteScopedOverlayBacklog
	if err := pool.QueryRow(t.Context(), `
		SELECT outbox_state.status,outbox_state.publish_attempts,
		       (SELECT count(*) FROM acme_http01_overlay_outbox_attempts attempt
		        WHERE attempt.outbox_id=outbox.id),
		       (SELECT event.state FROM acme_http01_overlay_deployment_events event
		        WHERE event.deployment_id=outbox.deployment_id
		          AND event.deployment_attempt=outbox.deployment_attempt
		        ORDER BY event.sequence DESC LIMIT 1)
		FROM acme_http01_overlay_outbox outbox
		JOIN acme_http01_overlay_outbox_states outbox_state ON outbox_state.outbox_id=outbox.id
		WHERE outbox.id=$1`, outboxID).Scan(
		&state.Status, &state.PublishAttempts, &state.AttemptEvents, &state.LatestState,
	); err != nil {
		t.Fatal(err)
	}
	return state
}

func seedSiteScopedOverlayBacklog(
	t *testing.T,
	pool *pgxpool.Pool,
	subjectPrefix string,
) seededSiteScopedOverlayBacklog {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT statement_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	siteID, nodeID, operationID, attemptID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	domain := "network-zero.example.test"
	username := "network-zero-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	tokenDigest := sha256.Sum256([]byte("network-zero-token/" + uuid.NewString()))
	thumbprintDigest := sha256.Sum256([]byte("network-zero-thumbprint/" + uuid.NewString()))
	token := base64.RawURLEncoding.EncodeToString(tokenDigest[:])
	exactValue := token + "." + base64.RawURLEncoding.EncodeToString(thumbprintDigest[:])
	leaseToken := uuid.New()
	accountKeyRef, certificateKeyRef := "network-zero-account", "network-zero-certificate"
	requestSnapshot, err := json.Marshal(map[string]any{
		"TenantID": tenantID.String(), "ScopeID": scopeID.String(), "OperationID": operationID.String(),
		"DirectoryURL": "https://ca.example/directory", "CertificateKeyRef": certificateKeyRef,
		"ActorUserID": userID.String(), "AccountKeyRef": accountKeyRef, "ProviderRef": "",
		"Domains": []string{domain}, "ChallengeType": "http-01",
	})
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(requestSnapshot)
	accountURI := "https://ca.example/account/" + operationID.String()
	orderURL := "https://ca.example/order/" + operationID.String()
	finalizeURL := "https://ca.example/finalize/" + operationID.String()
	authorizationURL := "https://ca.example/authorization/" + operationID.String()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Network zero tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Network zero actor','unused')`, []any{userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`WITH allocated AS (
		  INSERT INTO site_display_id_sequences(scope_id,next_value) VALUES($2,2)
		  ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1
		  RETURNING next_value-1 AS display_id
		) INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,origins,origin_hosts,
		  created_by_user_id,updated_by_user_id,display_id)
		  SELECT $1,$2,$3,$4,ARRAY['80'],ARRAY['192.0.2.1'],ARRAY['192.0.2.1'],$3,$3,display_id
		  FROM allocated`, []any{siteID, scopeID, userID, domain}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.1',80)`, []any{siteID}},
		{`WITH allocated AS (
		  INSERT INTO node_display_id_sequences(scope_id,next_value) VALUES($2,2)
		  ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1
		  RETURNING next_value-1 AS display_id
		) INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		  SELECT $1,$2,$3,'active',$4,display_id FROM allocated`, []any{nodeID, scopeID, "network-zero-node", userID}},
		{`INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,created_by_user_id,updated_by_user_id)
		  VALUES($1,$2,$3,'http-01',$4,$4)`, []any{operationID, scopeID, []string{domain}, userID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	var accountKeyID uuid.UUID
	for index, key := range []struct {
		ref, purpose string
	}{{accountKeyRef, "account"}, {certificateKeyRef, "certificate"}} {
		keyID := uuid.New()
		if key.purpose == "account" {
			accountKeyID = keyID
		}
		publicDigest := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", operationID, index)))
		if _, err := tx.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
			tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
			external_key_reference,created_by_user_id
		) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)`, scopeID, keyID, key.ref,
			key.purpose, publicDigest[:], "kms://network-zero/"+key.ref, userID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO acme_account_registration_facts(
		tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
		terms_agreed_at,registered_at,created_by_user_id
	) VALUES($1,$2,$3,'https://ca.example/directory',$4,ARRAY['mailto:ops@example.test'],$5,$5,$6)`,
		scopeID, uuid.New(), accountKeyID, accountURI, now, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_operations(
		tenant_scope_id,operation_id,request_digest,request_snapshot,directory_url,
		certificate_key_ref,certificate_order_id,actor_user_id,dns_provider_id,account_key_ref,created_at
	) VALUES($1,$2,$3,$4,'https://ca.example/directory',$5,$6,$7,NULL,$8,$9)`,
		scopeID, operationID.String(), requestDigest[:], requestSnapshot, certificateKeyRef,
		operationID, userID, accountKeyRef, now); err != nil {
		t.Fatal(err)
	}
	events := []struct {
		revision    int
		eventType   string
		phase       string
		orderIntent bool
		accountURI  *string
		orderURL    *string
		finalizeURL *string
		authURLs    []string
	}{
		{revision: 1, eventType: "claim_created", phase: "claimed", authURLs: []string{}},
		{revision: 2, eventType: "account_registered", phase: "claimed", accountURI: &accountURI, authURLs: []string{}},
		{revision: 3, eventType: "order_intent", phase: "claimed", orderIntent: true, accountURI: &accountURI, authURLs: []string{}},
		{revision: 4, eventType: "order_created", phase: "ordered", accountURI: &accountURI,
			orderURL: &orderURL, finalizeURL: &finalizeURL, authURLs: []string{authorizationURL}},
		{revision: 5, eventType: "authorizing", phase: "authorizing", accountURI: &accountURI,
			orderURL: &orderURL, finalizeURL: &finalizeURL, authURLs: []string{authorizationURL}},
	}
	for _, event := range events {
		if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_operation_events(
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,account_uri,order_url,
			finalize_url,authorization_urls,occurred_at
		) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$6,$8,$9,$10,$11,$12,$13)`,
			scopeID, operationID.String(), event.revision, event.eventType, event.phase,
			leaseToken, event.orderIntent, now.Add(time.Hour), event.accountURI, event.orderURL,
			event.finalizeURL, event.authURLs, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_attempts(
		tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
		challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
	) VALUES($1,$2,$3,1,$4,$5,'http-01',$6,false,$6,$7,$8,$9)`, scopeID,
		operationID.String(), attemptID, authorizationURL,
		"https://ca.example/challenge/"+attemptID.String(), domain, token, exactValue, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
		tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,occurred_at
	) VALUES($1,$2,$3,1,'intent',$4,$5)`, scopeID, operationID.String(), attemptID, leaseToken, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	cipher, err := acmehttp01.NewCipher("network-zero-key", bytes.Repeat([]byte{13}, 32))
	if err != nil {
		t.Fatal(err)
	}
	overlayConfig := acmeedge.DefaultConfig()
	overlayConfig.Clock = func() time.Time { return now }
	overlayConfig.Cipher = cipher
	overlayConfig.EntitlementAuthorizer = processOverlayAuthorizer{now: now}
	overlayConfig.SubjectPrefix = subjectPrefix
	service, err := acmeedge.NewService(pool, overlayConfig)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := service.PublishSnapshot(t.Context(), acmeedge.PublishRequest{
		Mode: acmeedge.ModeApply, TenantScopeID: scopeID, SiteID: siteID,
		ExpectedRevision: 0,
		Challenges:       []acmeedge.ChallengeReference{{OperationID: operationID.String(), AttemptID: attemptID}},
		NodeIDs:          []uuid.UUID{nodeID}, MaxAttempts: 3, Deadline: now.Add(10 * time.Minute),
		IdempotencyKey: "network-zero-backlog", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var outboxID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM acme_http01_overlay_outbox WHERE version_id=$1`,
		publication.VersionID).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	return seededSiteScopedOverlayBacklog{
		outboxID: outboxID, service: service, cipher: cipher, now: now,
	}
}

func TestConfiguredACMERunnerRejectsSuccessBeforeIssuedDatabaseFact(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	var version string
	if err := pool.QueryRow(t.Context(), `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "17.") {
		t.Fatalf("PostgreSQL version = %q, want 17.x", version)
	}
	outboxID := seedConfiguredACMEOutbox(t, pool)
	cfg := validACMERuntimeConfig()
	cfg.ACMEPollInterval = time.Hour
	setValidACMEDNSHandleEnvironment(t)
	runtime, err := openConfiguredACMERuntimeWithProviders(t.Context(), cfg, pool, acmeRuntimeProviders{
		http01:         inertHTTP01Provider{},
		issuerOverride: successfulACMEIssuer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	// claim 先把 outbox 置为 processing，订单推进到 validating 在随后的构建请求事务里；
	// 两者都到位（或 outbox 已离开 processing）才读终态，避免读到中间态
	deadline := time.Now().Add(10 * time.Second)
	var orderStatus string
	var orderRevision int64
	for {
		var status string
		var attempts int
		var lastError string
		if err := pool.QueryRow(t.Context(), `SELECT outbox.status,outbox.attempts,COALESCE(outbox.last_error_code,''),
			certificate_order.status,certificate_order.revision
			FROM dns_acme_outbox outbox
			JOIN certificate_orders certificate_order
			  ON certificate_order.scope_id=outbox.scope_id AND certificate_order.id=outbox.aggregate_id
			WHERE outbox.id=$1`, outboxID).Scan(&status, &attempts, &lastError, &orderStatus, &orderRevision); err != nil {
			t.Fatal(err)
		}
		if status == "processing" && attempts == 1 && orderStatus != "pending" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("outbox status=%q attempts=%d last_error_code=%q order=%s/%d before timeout",
				status, attempts, lastError, orderStatus, orderRevision)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if orderStatus != "validating" || orderRevision != 2 {
		t.Fatalf("uncommitted issuer order status=%s revision=%d, want validating/2",
			orderStatus, orderRevision)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("active runtime readiness = %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runtime cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not join after cancellation")
	}
}

func TestConfiguredACMERuntimeFailsClosedWithoutHTTP01ProductionProvider(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	setValidACMEDNSHandleEnvironment(t)
	_, err := openConfiguredACMERuntime(t.Context(), validACMERuntimeConfig(), pool)
	if err == nil || err.Error() != "ACME runtime HTTP-01 provider is not configured" {
		t.Fatalf("production HTTP-01 boundary error = %v", err)
	}
}

func TestConfiguredACMEDNSStartupFailsClosedWhenOutstandingSourceIsUnreadable(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	setValidACMEDNSHandleEnvironment(t)
	if _, err := pool.Exec(t.Context(), `ALTER TABLE acme_issuance_challenge_events
		RENAME TO acme_issuance_challenge_events_unreadable`); err != nil {
		t.Fatal(err)
	}
	_, err := openConfiguredACMERuntimeWithProviders(
		t.Context(), validACMERuntimeConfig(), pool,
		acmeRuntimeProviders{http01: inertHTTP01Provider{}},
	)
	if err == nil || err.Error() != "open ACME DNS-01 provider" ||
		dnsproviderremote.ErrorCodeOf(err) != dnsproviderremote.CodeSourceUnavailable {
		t.Fatalf("unreadable outstanding handle source error = %v", err)
	}
}

func seedConfiguredACMEOutbox(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	tenantID, scopeID, actorID := uuid.New(), uuid.New(), uuid.New()
	orderID, outboxID := uuid.New(), uuid.New()
	username := "configured-acme-" + strings.ReplaceAll(actorID.String(), "-", "")[:12]
	statements := []struct {
		query string
		args  []any
	}{
		// 新订单的 CA 目录按平台默认签发方选择（读平台作用域的系统配置），安装时平台作用域必然存在
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{uuid.New()}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Configured ACME tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		 VALUES($1,$2,'Configured ACME actor','test-hash')`, []any{actorID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, actorID}},
		{`INSERT INTO certificate_orders(
		 id,scope_id,domains,challenge_type,auto_renew,created_by_user_id,updated_by_user_id
		 ) VALUES($1,$2,$3,'http-01',true,$4,$4)`, []any{orderID, scopeID, []string{"runtime.example.test"}, actorID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(struct {
		OrderID       uuid.UUID `json:"order_id"`
		ChallengeType string    `json:"challenge_type"`
		Domains       []string  `json:"domains"`
	}{OrderID: orderID, ChallengeType: "http-01", Domains: []string{"runtime.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_acme_outbox(
		id,scope_id,aggregate_type,aggregate_id,event_type,payload
	) VALUES($1,$2,'certificate_order',$3,'certificate.order.requested',$4)`,
		outboxID, scopeID, orderID, payload); err != nil {
		t.Fatal(err)
	}
	return outboxID
}

type successfulACMEIssuer struct{}

// Issue 返回能通过 acmeruntime.validIssueResult 的自签证书（链/PEM/指纹/域名一致），
// 让用例走到“签发成功但库里没有 issued 事实”的分支，而不是在结果校验处失败。
func (successfulACMEIssuer) Issue(
	_ context.Context,
	request acmeworker.IssueRequest,
) (acmeworker.IssueResult, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: request.Domains[0]},
		DNSNames: slices.Clone(request.Domains), NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return acmeworker.IssueResult{Certificate: acmeworker.IssuedCertificate{
		RequestDigest: "sha256:configured-runner", CertificateKeyRef: request.CertificateKeyRef,
		PublicKeySPKISHA256: "sha256:" + hex.EncodeToString(spki[:]), LeafDER: leafDER,
		ChainDER:        [][]byte{leafDER},
		CertificatePEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		CertificateURL:  "https://ca.example/cert/" + request.CertificateOrderID.String(),
		LeafFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
		SerialNumber:    leaf.SerialNumber.String(), DNSNames: slices.Clone(request.Domains),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
	}}, nil
}

func setValidACMEDNSHandleEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_ID", "integration-active")
	t.Setenv("ACME_DNS_HANDLE_ACTIVE_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	unsetTestEnvironment(t, "ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON")
}
