//go:build integration

package main

// Control half of tests/license-ban-e2e/run.sh (ADR 0014 LIC-BAN-07): the license process (production licensing +
// operator/controller API over HTTPS), this control plane (production installationban Client/Store/Runtime as the
// entitlement revocation loop drives them, production Distributor over NATS, production HTTP server's lock
// middleware), agent-gateway (production installation ban bus) and the edge-agent in the node runtime container
// (production gateway client, signer trust runtime, installationban.Runtime with the daemon's dynroute serving).
//
// The scenario drives the shared clock offset ($DYNROUTE_E2E_DIR/clock-offset, seconds) read by the license
// service, this control plane's ban runtime and the node's ban runtime.
//
// ① baseline: the node serves, holds a ticket; control writes pass the lock
// ② the operator bans permanently (step-up over HTTP): control writes 423 installation_locked with reason; the
//    node answers 503 with the fixed page
// ③ lift: control unlocks, the node serves again (new ticket)
// ④ the control plane goes offline for the node (no more deliveries) and the clock moves past the 30 day ticket:
//    the node freezes (service_ticket_expired) and keeps serving its sites (200)
// ⑤ the control plane is back: a fresh ticket reaches the node and it serves
// ⑥ a timed ban (until = now + 1h): locked and stopped with Retry-After; the clock passes until, the license
//    expiry worker lifts it, control unlocks and the node serves
// ⑦ recoverable refusal: the node answers persistence_failed twice for the timed ban's
//    revision (edge half /fail); control keeps delivered ≠ applied with a backoff, sends the same revision again
//    and records it applied once the node takes it, and the node then enforces it (503)
// ⑧ deposit loss → automatic ban (small-1035f F1): the market stand-in in the license process reports an executed
//    seller default case; the license seller default ban worker bans the installation as the system
//    (seller_absconded, created_by null); control 423, node 503, the case is reported banned

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/installationban"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type licenseBanHandoff struct {
	URL              string `json:"url"`
	CAFile           string `json:"ca_file"`
	InstallationID   string `json:"installation_id"`
	InstallationSeed string `json:"installation_key_seed_file"`
	SigningKeyID     string `json:"signing_key_id"`
	SigningPublicKey string `json:"signing_public_key"`
	SessionToken     string `json:"session_token"`
	SessionCookie    string `json:"session_cookie"`
	Origin           string `json:"origin"`
	Password         string `json:"password"`
	TOTPSecret       string `json:"totp_secret"`
	LoginTOTPStep    int64  `json:"login_totp_step"`
}

type licenseBanFlow struct {
	*dynRouteFlow
	directory   string
	license     licenseBanHandoff
	licenseHTTP *http.Client
	runtime     *installationban.Runtime
	distributor *installationban.Distributor
	api         http.Handler
	offset      time.Duration
	lastStep    int64
	host        string
}

func TestLicenseBanControlProcess(t *testing.T) {
	directory := os.Getenv("DYNROUTE_E2E_DIR")
	if directory == "" || os.Getenv("LICENSE_BAN_E2E") != "1" {
		t.Skip("run tests/license-ban-e2e/run.sh")
	}
	flow := &licenseBanFlow{directory: directory}
	flow.setClock(0)
	waitJSONFile(t, filepath.Join(directory, "license-ban.json"), &flow.license)
	flow.lastStep = flow.license.LoginTOTPStep
	flow.dynRouteFlow = startDynRouteControl(t, &dynRouteControlHooks{
		beforeServe: func(connection *nats.Conn, _ nats.JetStreamContext, pool *pgxpool.Pool,
			publisher *edgepublish.E2EPublisherForTest, runCtx context.Context) {
			flow.startBanRuntime(t, connection, pool, runCtx)
			flow.writeSignerTrustBundle(t, publisher)
		},
	})
	flow.run()
}

// setClock writes the shared offset (the license service, this runtime and the node read it).
func (flow *licenseBanFlow) setClock(offset time.Duration) {
	flow.offset = offset
	path := filepath.Join(flow.directory, "clock-offset")
	if err := os.WriteFile(path+".tmp", []byte(strconv.FormatInt(int64(offset/time.Second), 10)), 0o644); err != nil {
		panic(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		panic(err)
	}
	if flow.dynRouteFlow != nil {
		// The node's clock: over its control HTTP (the container may see the shared file stale).
		response, err := http.Post(fmt.Sprintf("%s/clock?offset=%d", flow.stateURL, int64(offset/time.Second)), "text/plain", nil)
		if err != nil || response.StatusCode != http.StatusNoContent {
			flow.t.Fatalf("set node clock offset: %v %v", response, err)
		}
		response.Body.Close()
	}
}

func (flow *licenseBanFlow) now() time.Time { return time.Now().Add(flow.offset) }

// startBanRuntime builds the production state client, store and runtime (openEntitlementRevocationRuntime) and
// the production NATS distributor (installationBanDistributor), against the license process.
func (flow *licenseBanFlow) startBanRuntime(t *testing.T, connection *nats.Conn, pool *pgxpool.Pool, runCtx context.Context) {
	t.Helper()
	installationID := uuid.MustParse(flow.license.InstallationID)
	seed, err := os.ReadFile(flow.license.InstallationSeed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seed)))
	if err != nil || len(decoded) != ed25519.SeedSize {
		t.Fatalf("installation key seed: %v", err)
	}
	ca, err := os.ReadFile(flow.license.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	flow.licenseHTTP = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := installationban.NewClient(flow.license.URL, installationID, ed25519.NewKeyFromSeed(decoded), flow.licenseHTTP)
	if err != nil {
		t.Fatal(err)
	}
	licenseKey, err := base64.StdEncoding.DecodeString(flow.license.SigningPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// entitlementguard.TrustStore.PublicKey in production: the license lease key by ID.
	store, err := installationban.NewStore(pool, installationID, func(keyID string) (ed25519.PublicKey, bool) {
		return ed25519.PublicKey(licenseKey), keyID == flow.license.SigningKeyID
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's lease has a 2 hour grace; the scenario moves the clock by days. Keep the lease reason out of
	// the lock so every locked state below is the ban's own (lease expiry is LIC-BAN-04's separate case).
	if _, err := pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET grace_until=now()+interval '400 days'`); err != nil {
		t.Logf("lease grace not widened (lock may report lease_expired after the clock moves): %v", err)
	}
	flow.runtime = &installationban.Runtime{Fetcher: client, Store: store, Now: flow.now, Logger: slog.Default()}
	if err := flow.runtime.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	commands, err := installationban.NewNATSCommands(connection, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	flow.distributor = &installationban.Distributor{Store: store, Nodes: installationban.ActiveNodes(pool),
		Commands: offlineCommands{NATSCommands: commands, offline: flow.offline}, Interval: time.Second, RetryAfter: 5 * time.Second, Now: flow.now, Logger: slog.Default()}
	flow.runtime.Changed = flow.distributor.Wake
	go func() {
		if err := flow.distributor.Run(runCtx); err != nil && runCtx.Err() == nil {
			t.Errorf("installation ban distributor: %v", err)
		}
	}()
	// The entitlement revocation loop's poll (every minute in production; 1 second here). It stops while the
	// control plane is "offline" (scenario ④).
	go func() {
		for runCtx.Err() == nil {
			if !flow.offline() {
				if err := flow.runtime.SyncOnce(runCtx); err != nil && runCtx.Err() == nil {
					t.Logf("installation state sync: %v", err)
				}
			}
			select {
			case <-runCtx.Done():
			case <-time.After(time.Second):
			}
		}
	}()
	// The production HTTP server's middleware chain (server.go Handler: withInstallationLock).
	flow.api = httpapi.New(nil, nil, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		InstallationLockCheck: flow.runtime.SyncOnce}).Handler()
}

// offlineCommands drops publications while the control plane is "offline" for the node (scenario ④): the node
// gets nothing new, as if the control plane were unreachable. Receipts still flow.
type offlineCommands struct {
	*installationban.NATSCommands
	offline func() bool
}

func (commands offlineCommands) Publish(ctx context.Context, command *agentv1.InstallationBanCommand) error {
	if commands.offline() {
		return fmt.Errorf("control plane offline (scenario)")
	}
	return commands.NATSCommands.Publish(ctx, command)
}

func (flow *licenseBanFlow) offline() bool {
	_, err := os.Stat(filepath.Join(flow.directory, "control-offline"))
	return err == nil
}

// writeSignerTrustBundle writes the offline-signed node signer trust document carrying the license lease key
// (usage installation-ban) inside a control bundle signed by the edge publication key (the node trusts it).
func (flow *licenseBanFlow) writeSignerTrustBundle(t *testing.T, publisher *edgepublish.E2EPublisherForTest) {
	t.Helper()
	licenseKey, _ := base64.StdEncoding.DecodeString(flow.license.SigningPublicKey)
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(licenseKey))
	if err != nil {
		t.Fatal(err)
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	document, err := edgesignertrust.Normalize(edgesignertrust.Document{Schema: edgesignertrust.DocumentSchema,
		Revision: 1, IssuedAt: edgesignertrust.CanonicalTime(time.Now()), RevokedKeys: []edgesignertrust.RevokedKey{},
		TrustedKeys: []edgesignertrust.TrustedKey{{KeyID: flow.license.SigningKeyID, Usage: edgesignertrust.UsageInstallationBan,
			PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := edgesignertrust.Sign(document, "license-ban-e2e-root", 1, root)
	if err != nil {
		t.Fatal(err)
	}
	var pki artifactSetPKIFixture
	waitJSONFile(t, filepath.Join(flow.directory, "pki.json"), &pki)
	signer := publisher.Signer()
	bundle, err := edgesignertrust.NewBundle(pki.NodeID, signed, signer.KeyID(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := edgesignertrust.BundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(t.Context(), payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := edgesignertrust.SealBundle(bundle, signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flow.directory, "signer-trust-bundle.json"), sealed, 0o644); err != nil {
		t.Fatal(err)
	}
}

type licenseBanNodeState struct {
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
	Keys    int    `json:"installation_ban_keys"`
	Offset  int64  `json:"clock_offset"`
}

func (flow *licenseBanFlow) nodeBan() licenseBanNodeState {
	flow.t.Helper()
	response, err := http.Get(flow.stateURL + "/ban")
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	var state licenseBanNodeState
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		flow.t.Fatal(err)
	}
	return state
}

// write is one console write through the production middleware: 423 while locked (before any authentication),
// otherwise the route itself answers (401 without a session).
func (flow *licenseBanFlow) write() (int, map[string]any) {
	request := httptest.NewRequest(http.MethodPost, "/v1/sites", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	flow.api.ServeHTTP(response, request)
	var body struct {
		Error map[string]any `json:"error"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	return response.Code, body.Error
}

// read is a console read; reads pass the lock.
func (flow *licenseBanFlow) read() int {
	request := httptest.NewRequest(http.MethodGet, "/v1/sites", nil)
	response := httptest.NewRecorder()
	flow.api.ServeHTTP(response, request)
	return response.Code
}

// licenseBanTOTP is RFC 6238 (SHA-1, 6 digits, 30 s) at step.
func licenseBanTOTP(secret string, step int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
}

// operator calls one license operator route; writes re-authenticate first (password + a fresh TOTP step: the
// service refuses a step it already accepted).
func (flow *licenseBanFlow) operator(method, path string, body any, idempotencyKey string) (int, []byte) {
	t := flow.t
	t.Helper()
	send := func(method, path string, payload []byte, key string) (int, []byte) {
		request, _ := http.NewRequest(method, flow.license.URL+path, bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", flow.license.Origin)
		request.AddCookie(&http.Cookie{Name: flow.license.SessionCookie, Value: flow.license.SessionToken})
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response, err := flow.licenseHTTP.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, raw
	}
	if method != http.MethodGet {
		// The operator identity service runs on the wall clock (only licensing takes the offset).
		step := time.Now().Unix() / 30
		for step <= flow.lastStep {
			time.Sleep(time.Second)
			step = time.Now().Unix() / 30
		}
		reauth, _ := json.Marshal(map[string]string{"current_password": flow.license.Password,
			"totp_code": licenseBanTOTP(flow.license.TOTPSecret, step)})
		if status, raw := send(http.MethodPost, "/operator/v1/session/reauthenticate", reauth, ""); status != http.StatusNoContent {
			t.Fatalf("operator re-authentication: %d %s", status, raw)
		}
		flow.lastStep = step
	}
	payload, _ := json.Marshal(body)
	if body == nil {
		payload = nil
	}
	return send(method, path, payload, idempotencyKey)
}

func (flow *licenseBanFlow) await(what string, timeout time.Duration, done func() bool) {
	flow.t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			flow.t.Fatalf("timed out waiting for %s (lock %+v, node %+v)", what, installationlock.Current(), flow.nodeBan())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (flow *licenseBanFlow) nodeReceipt() (revision int64, status string) {
	flow.t.Helper()
	_ = flow.pool.QueryRow(flow.t.Context(), `SELECT revision, status FROM installation_ban_node_state WHERE node_id=$1`,
		flow.nodeID).Scan(&revision, &status)
	return revision, status
}

func (flow *licenseBanFlow) serving(label string) {
	flow.t.Helper()
	flow.await(label+": node serving", 90*time.Second, func() bool {
		answer := flow.get(flow.host, "/index.html")
		return flow.nodeBan().Status == "serving" && answer.Status == 200
	})
	flow.expect(flow.host, "/index.html", 200, "origin "+flow.host+" /index.html")
}

func (flow *licenseBanFlow) stopped(label, status string, retryAfter bool) {
	flow.t.Helper()
	flow.await(label+": node stopped ("+status+")", 90*time.Second, func() bool {
		return flow.nodeBan().Status == status && flow.get(flow.host, "/index.html").Status == 503
	})
	answer := flow.get(flow.host, "/index.html")
	if answer.Status != 503 || !strings.HasPrefix(edgeskeleton.MaintenancePage, answer.Body[:min(len(answer.Body), 60)]) ||
		(answer.RetryAfter != "") != retryAfter {
		flow.t.Fatalf("%s: stopped node answered %+v, want 503 fixed page (Retry-After %v)", label, answer, retryAfter)
	}
}

func (flow *licenseBanFlow) locked(label, reason string) map[string]any {
	flow.t.Helper()
	flow.await(label+": control locked", 30*time.Second, func() bool {
		lock := installationlock.Current()
		return lock.Locked && lock.Reason == reason
	})
	status, body := flow.write()
	if status != http.StatusLocked || body["code"] != "installation_locked" || body["reason"] != reason {
		flow.t.Fatalf("%s: console write answered %d %v, want 423 installation_locked/%s", label, status, body, reason)
	}
	if code := flow.read(); code == http.StatusLocked {
		flow.t.Fatalf("%s: console read answered 423", label)
	}
	return body
}

func (flow *licenseBanFlow) unlocked(label string) {
	flow.t.Helper()
	flow.await(label+": control unlocked", 30*time.Second, func() bool { return !installationlock.Current().Locked })
	if status, body := flow.write(); status == http.StatusLocked {
		flow.t.Fatalf("%s: console write still 423 %v", label, body)
	}
}

func (flow *licenseBanFlow) ban(until *time.Time, key string) uuid.UUID {
	flow.t.Helper()
	body := map[string]any{"reason_code": "abuse", "reason_text": "LIC-BAN-07 联调", "until": nil}
	if until != nil {
		body["until"] = until.UTC().Format(time.RFC3339)
	}
	status, raw := flow.operator(http.MethodPost, "/operator/v1/installations/"+flow.license.InstallationID+"/bans", body, key)
	var created struct {
		ID             uuid.UUID `json:"id"`
		NoticeRevision uint64    `json:"notice_revision"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == uuid.Nil {
		flow.t.Fatalf("ban: %d %s", status, raw)
	}
	return created.ID
}

func (flow *licenseBanFlow) run() {
	t := flow.t
	flow.waitFor("session declaring SITE_RUNTIME 9 and INSTALLATION_BAN_TICKET", func() bool {
		return flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, 9) &&
			flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET, 1)
	})
	flow.host = "shop.license-ban-e2e.test"
	flow.publisher.CreateSite(t, flow.host, dynRouteE2ESitePort, "127.0.0.1", dynRouteE2EOriginPort)
	if state := flow.publish("site"); state != "healthy" {
		t.Fatalf("site release: deployment %s", state)
	}

	// ① baseline
	flow.await("① ticket accepted by control and node", 60*time.Second, func() bool {
		revision, status := flow.nodeReceipt()
		return revision > 0 && status == "serving"
	})
	flow.unlocked("①")
	flow.serving("①")
	revision, _ := flow.nodeReceipt()
	t.Logf("PASS ① baseline: ticket revision %d on the node (receipt serving), site 200, console write not locked", revision)

	// ② permanent ban
	banID := flow.ban(nil, "license-ban-e2e-ban-1")
	body := flow.locked("②", installationlock.ReasonBanned)
	if body["ban_id"] != banID.String() || body["reason_code"] != "abuse" || body["until"] != nil {
		t.Fatalf("② 423 body %v, want ban %s abuse permanent", body, banID)
	}
	flow.stopped("②", "banned", false)
	flow.await("② node receipt banned", 30*time.Second, func() bool { _, status := flow.nodeReceipt(); return status == "banned" })
	t.Logf("PASS ② permanent ban %s: console write 423 installation_locked (reason banned, until null), read passes; "+
		"node 503 fixed maintenance page without Retry-After, receipt banned", banID)

	// ③ lift
	if status, raw := flow.operator(http.MethodPost, "/operator/v1/installation-bans/"+banID.String()+"/lift",
		map[string]string{"reason": "已处理"}, "license-ban-e2e-lift-1"); status != http.StatusOK {
		t.Fatalf("lift: %d %s", status, raw)
	}
	flow.unlocked("③")
	flow.serving("③")
	t.Log("PASS ③ lifted: console unlocked, node serves again with the new ticket (200)")

	// ④ control plane offline for the node; the clock passes the 30 day ticket: frozen, still serving
	if err := os.WriteFile(filepath.Join(flow.directory, "control-offline"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	flow.setClock(contract.DefaultNodeOfflineTolerance + 2*time.Minute)
	flow.await("④: node frozen (service_ticket_expired)", 90*time.Second, func() bool {
		return flow.nodeBan().Status == "service_ticket_expired"
	})
	flow.expect(flow.host, "/index.html", 200, "④ frozen node keeps serving "+flow.host)
	t.Log("PASS ④ control offline, clock +30d2m: node frozen (service_ticket_expired), sites keep serving (200)")

	// ⑤ back online: a fresh ticket reaches the node
	if err := os.Remove(filepath.Join(flow.directory, "control-offline")); err != nil {
		t.Fatal(err)
	}
	flow.serving("⑤")
	t.Log("PASS ⑤ control back: fresh ticket delivered, node serves (200)")

	// ⑥ timed ban, expiry worker lift
	until := flow.now().Add(time.Hour).Truncate(time.Second)
	banID = flow.ban(&until, "license-ban-e2e-ban-2")
	body = flow.locked("⑥", installationlock.ReasonBanned)
	if body["until"] == nil {
		t.Fatalf("⑥ 423 body %v, want until", body)
	}
	flow.stopped("⑥", "banned", true)
	flow.setClock(flow.offset + time.Hour + 2*time.Minute)
	flow.unlocked("⑥ expiry")
	flow.serving("⑥ expiry")
	t.Logf("PASS ⑥ timed ban %s until %s: locked with until, node 503 with Retry-After; clock +1h2m: expiry worker "+
		"lifted it, console unlocked, node serves", banID, until.Format(time.RFC3339))

	// ⑦ recoverable refusal: same revision redelivered after the backoff, then applied
	if response, err := http.Post(flow.stateURL+"/fail?count=2", "text/plain", nil); err != nil ||
		response.StatusCode != http.StatusNoContent {
		t.Fatalf("⑦ arm node failures: %v %v", response, err)
	} else {
		response.Body.Close()
	}
	banID = flow.ban(nil, "license-ban-e2e-ban-3")
	flow.locked("⑦", installationlock.ReasonBanned)
	var refused int64
	flow.await("⑦ refusal recorded as retryable", 60*time.Second, func() bool {
		var class string
		var applied int64
		_ = flow.pool.QueryRow(flow.t.Context(), `SELECT revision, applied_revision, failure_class FROM installation_ban_node_state
			WHERE node_id=$1`, flow.nodeID).Scan(&refused, &applied, &class)
		return class == installationban.FailureRetryable && applied < refused
	})
	flow.await("⑦ same revision applied after the backoff", 3*installationban.RetryBackoffBase+time.Minute, func() bool {
		var revision, applied int64
		var attempts int
		_ = flow.pool.QueryRow(flow.t.Context(), `SELECT revision, applied_revision, failed_attempts FROM installation_ban_node_state
			WHERE node_id=$1`, flow.nodeID).Scan(&revision, &applied, &attempts)
		return revision == refused && applied == refused && attempts == 0
	})
	flow.stopped("⑦", "banned", false)
	t.Logf("PASS ⑦ ban %s revision %d: node refused it twice (persistence_failed), control kept it retryable with a "+
		"backoff, delivered the same revision again and recorded it applied; node 503", banID, refused)

	// ⑧ deposit loss → automatic ban (small-1035f F1): lift ⑦'s ban, then the market reports an executed seller
	// default case for this installation; the license seller default ban worker bans it as the system.
	if status, raw := flow.operator(http.MethodPost, "/operator/v1/installation-bans/"+banID.String()+"/lift",
		map[string]string{"reason": "已处理"}, "license-ban-e2e-lift-3"); status != http.StatusOK {
		t.Fatalf("⑧ lift ⑦: %d %s", status, raw)
	}
	flow.unlocked("⑧ before")
	flow.serving("⑧ before")
	if err := os.WriteFile(filepath.Join(flow.directory, "seller-default"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	body = flow.locked("⑧", installationlock.ReasonBanned)
	flow.stopped("⑧", "banned", false)
	if _, err := os.Stat(filepath.Join(flow.directory, "seller-default-banned")); err != nil {
		t.Fatalf("⑧ market case not reported banned: %v", err)
	}
	status, raw := flow.operator(http.MethodGet, "/operator/v1/installations/"+flow.license.InstallationID+"/bans", nil, "")
	var bans struct {
		Items []struct {
			ID         uuid.UUID  `json:"id"`
			ReasonCode string     `json:"reason_code"`
			CreatedBy  *uuid.UUID `json:"created_by"`
			LiftedAt   *time.Time `json:"lifted_at"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &bans) != nil {
		t.Fatalf("⑧ list bans: %d %s", status, raw)
	}
	var system uuid.UUID
	for _, item := range bans.Items {
		if item.LiftedAt == nil {
			if item.ReasonCode != "seller_absconded" || item.CreatedBy != nil || system != uuid.Nil {
				t.Fatalf("⑧ active bans %s, want one system ban seller_absconded", raw)
			}
			system = item.ID
		}
	}
	if system == uuid.Nil || body["ban_id"] != system.String() {
		t.Fatalf("⑧ active bans %s, 423 body %v: want the system ban", raw, body)
	}
	t.Logf("PASS ⑧ seller default case reported by the market: system ban %s (seller_absconded, created_by null), "+
		"console 423, node 503 fixed page, case reported banned", system)
}
