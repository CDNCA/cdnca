package installationban

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testInstallation = "0190a000-0000-7000-8000-000000000001"
	testCustomer     = "0190a000-0000-7000-8000-000000000002"
	testBan          = "0190a000-0000-7000-8000-000000000003"
	testLicense      = "0190a000-0000-7000-8000-000000000004"
)

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func newSigner(label string) testSigner {
	seed := sha256.Sum256([]byte(label))
	return testSigner{id: "lease-" + label, private: ed25519.NewKeyFromSeed(seed[:])}
}

func (signer testSigner) keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{signer.id: signer.private.Public().(ed25519.PublicKey)}
}

var testNow = time.Unix(1_900_000_000, 0).UTC()

func testNotice(revision uint64, until *int64) BanNotice {
	return BanNotice{Schema: NoticeSchema, InstallationID: testInstallation, CustomerID: testCustomer, BanID: testBan,
		Revision: revision, State: StateBanned, ReasonCode: "market_seller_fault", ReasonText: "卖方违约，停止服务",
		StartsAt: testNow.Unix(), Until: until, IssuedAt: testNow.Unix()}
}

func testTicket(revision uint64) ServiceTicket {
	return ServiceTicket{Schema: TicketSchema, InstallationID: testInstallation, CustomerID: testCustomer,
		LicenseID: testLicense, Revision: revision, IssuedAt: testNow.Unix(),
		NotAfter: testNow.Add(DefaultNodeOfflineTolerance).Unix()}
}

func options(signer testSigner, now time.Time) VerifyOptions {
	return VerifyOptions{Now: now, ExpectedInstallationID: testInstallation, Keys: signer.keys()}
}

func TestNoticeAndTicketRoundTrip(t *testing.T) {
	signer := newSigner("a")
	until := testNow.Add(48 * time.Hour).Unix()
	for _, notice := range []BanNotice{testNotice(3, &until), testNotice(4, nil)} {
		encoded, err := SignNotice(t.Context(), notice, signer)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyNotice(encoded, options(signer, testNow))
		if err != nil || verified.Revision != notice.Revision || verified.ReasonText != notice.ReasonText ||
			(verified.Until == nil) != (notice.Until == nil) {
			t.Fatalf("VerifyNotice = (%#v,%v)", verified, err)
		}
		if !verified.InEffect(testNow) {
			t.Fatal("banned notice not in effect")
		}
	}
	permanent := testNotice(1, nil)
	if !permanent.InEffect(testNow.Add(100 * 365 * 24 * time.Hour)) {
		t.Fatal("permanent ban expired")
	}
	timed := testNotice(1, &until)
	if !timed.InEffect(time.Unix(until-1, 0)) || timed.InEffect(time.Unix(until, 0)) {
		t.Fatal("timed ban boundary wrong: until is exclusive")
	}
	lifted := testNotice(5, nil)
	lifted.State = StateLifted
	if lifted.InEffect(testNow) {
		t.Fatal("lifted notice in effect")
	}

	encoded, err := SignTicket(t.Context(), testTicket(6), signer)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := VerifyTicket(encoded, options(signer, testNow.Add(DefaultNodeOfflineTolerance-time.Second)))
	if err != nil || ticket.Revision != 6 {
		t.Fatalf("VerifyTicket = (%#v,%v)", ticket, err)
	}
	if _, err := VerifyTicket(encoded, options(signer, testNow.Add(DefaultNodeOfflineTolerance))); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("expired ticket error = %v", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	signer := newSigner("a")
	notice, _ := SignNotice(t.Context(), testNotice(1, nil), signer)
	ticket, _ := SignTicket(t.Context(), testTicket(1), signer)
	if _, err := VerifyTicket(notice, options(signer, testNow)); err == nil {
		t.Fatal("notice accepted as ticket")
	}
	if _, err := VerifyNotice(ticket, options(signer, testNow)); err == nil {
		t.Fatal("ticket accepted as notice")
	}
	// A ticket signature re-wrapped around a notice body must not verify.
	var signedTicket SignedTicket
	_ = json.Unmarshal(ticket, &signedTicket)
	var signedNotice SignedNotice
	_ = json.Unmarshal(notice, &signedNotice)
	signedNotice.Signature = signedTicket.Signature
	rewrapped, _ := json.Marshal(signedNotice)
	if _, err := VerifyNotice(rewrapped, options(signer, testNow)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("rewrapped signature error = %v", err)
	}
}

func TestTamperAndTrustRejected(t *testing.T) {
	signer := newSigner("a")
	encoded, err := SignNotice(t.Context(), testNotice(2, nil), signer)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"reason":     bytes.Replace(encoded, []byte("market_seller_fault"), []byte("market_seller_fauls"), 1),
		"state":      bytes.Replace(encoded, []byte(`"state":"banned"`), []byte(`"state":"lifted"`), 1),
		"revision":   bytes.Replace(encoded, []byte(`"revision":2`), []byte(`"revision":9`), 1),
		"permanent":  bytes.Replace(encoded, []byte(`"until":null`), []byte(`"until":1900000001`), 1),
		"unknown":    bytes.Replace(encoded, []byte(`{"algorithm"`), []byte(`{"extra":1,"algorithm"`), 1),
		"whitespace": append(append([]byte{}, encoded...), ' '),
		"truncated":  encoded[:len(encoded)-2],
	}
	for name, mutated := range cases {
		if _, err := VerifyNotice(mutated, options(signer, testNow)); err == nil {
			t.Errorf("%s: tampered notice accepted", name)
		}
	}
	other := newSigner("b")
	if _, err := VerifyNotice(encoded, options(other, testNow)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unknown key error = %v", err)
	}
	sameID := testSigner{id: signer.id, private: other.private}
	if _, err := VerifyNotice(encoded, options(sameID, testNow)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("wrong key under same id error = %v", err)
	}
	wrongInstallation := options(signer, testNow)
	wrongInstallation.ExpectedInstallationID = testCustomer
	if _, err := VerifyNotice(encoded, wrongInstallation); !errors.Is(err, ErrInstallationMatch) {
		t.Fatalf("installation mismatch error = %v", err)
	}
	if _, err := VerifyNotice(encoded, VerifyOptions{ExpectedInstallationID: testInstallation, Keys: signer.keys()}); err == nil {
		t.Fatal("zero Now accepted")
	}
	if _, err := VerifyNotice(encoded, options(signer, testNow.Add(-MaxClockSkew-time.Second))); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("future notice error = %v", err)
	}
	if _, err := VerifyNotice(encoded, options(signer, testNow.Add(-MaxClockSkew))); err != nil {
		t.Fatalf("notice within skew error = %v", err)
	}
}

func TestValidation(t *testing.T) {
	signer := newSigner("a")
	past := testNow.Add(-time.Second).Unix()
	bad := map[string]func(*BanNotice){
		"schema":         func(n *BanNotice) { n.Schema = "cdnca.installation-ban/v0" },
		"state":          func(n *BanNotice) { n.State = "suspended" },
		"revision":       func(n *BanNotice) { n.Revision = 0 },
		"reason code":    func(n *BanNotice) { n.ReasonCode = "Abuse" },
		"reason empty":   func(n *BanNotice) { n.ReasonText = "" },
		"reason spaces":  func(n *BanNotice) { n.ReasonText = " 违约" },
		"reason long":    func(n *BanNotice) { n.ReasonText = strings.Repeat("界", MaxReasonTextRune+1) },
		"until <= start": func(n *BanNotice) { n.Until = &past },
		"uuid":           func(n *BanNotice) { n.BanID = strings.ToUpper(testBan) },
	}
	for name, mutate := range bad {
		notice := testNotice(1, nil)
		mutate(&notice)
		if _, err := SignNotice(t.Context(), notice, signer); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: SignNotice error = %v", name, err)
		}
	}
	long := testTicket(1)
	long.NotAfter = long.IssuedAt + int64(MaxTicketValidity/time.Second) + 1
	if _, err := SignTicket(t.Context(), long, signer); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("over-long ticket error = %v", err)
	}
	if _, err := SignTicket(t.Context(), testTicket(1), testSigner{id: "bad id!", private: signer.private}); !errors.Is(err, ErrInvalidSigner) {
		t.Fatalf("bad signer id error = %v", err)
	}
}

func TestRevisionRule(t *testing.T) {
	signer := newSigner("a")
	first, _ := SignNotice(t.Context(), testNotice(4, nil), signer)
	lifted := testNotice(3, nil)
	lifted.State = StateLifted
	older, _ := SignNotice(t.Context(), lifted, signer)
	other := testNotice(4, nil)
	other.ReasonText = "另一原因"
	conflict, _ := SignNotice(t.Context(), other, signer)
	accepted, digest := uint64(4), Digest(first)
	if err := CheckRevision(accepted, digest, 4, Digest(first)); err != nil {
		t.Fatalf("redelivery error = %v", err)
	}
	if err := CheckRevision(accepted, digest, 3, Digest(older)); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("older lifted notice error = %v", err)
	}
	if err := CheckRevision(accepted, digest, 4, Digest(conflict)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same revision other bytes error = %v", err)
	}
	if err := CheckRevision(accepted, digest, 5, [32]byte{}); err != nil {
		t.Fatalf("newer revision error = %v", err)
	}
	if err := CheckRevision(0, [32]byte{}, 1, Digest(first)); err != nil {
		t.Fatalf("first document error = %v", err)
	}
}

func TestTicketClockRollbackDoesNotExtend(t *testing.T) {
	ticket := testTicket(1)
	notAfter := time.Unix(ticket.NotAfter, 0)
	if err := CheckTicketClock(ticket, notAfter.Add(-time.Second), time.Time{}); err != nil {
		t.Fatalf("valid ticket error = %v", err)
	}
	if err := CheckTicketClock(ticket, notAfter, time.Time{}); !errors.Is(err, ErrTicketExpired) {
		t.Fatal("ticket valid at not_after")
	}
	// Node clock set back past issued_at by more than the skew: expired.
	if err := CheckTicketClock(ticket, testNow.Add(-MaxClockSkew-time.Second), time.Time{}); !errors.Is(err, ErrTicketExpired) {
		t.Fatal("clock behind issued_at accepted")
	}
	if err := CheckTicketClock(ticket, testNow.Add(-MaxClockSkew), time.Time{}); err != nil {
		t.Fatalf("clock within skew error = %v", err)
	}
	// After the node saw time past not_after, moving the clock back stays expired.
	highWater := notAfter.Add(time.Hour)
	if err := CheckTicketClock(ticket, notAfter.Add(-24*time.Hour), highWater); !errors.Is(err, ErrTicketExpired) {
		t.Fatal("clock rollback below high-water extended the ticket")
	}
	if err := CheckTicketClock(ticket, testNow.Add(time.Hour), testNow.Add(time.Hour+MaxClockSkew)); err != nil {
		t.Fatalf("small backwards step within skew error = %v", err)
	}
}

func TestEvaluate(t *testing.T) {
	until := testNow.Add(time.Hour).Unix()
	ban := testNotice(5, &until)
	oldTicket, newTicket := testTicket(4), testTicket(6)
	lifted := testNotice(7, nil)
	lifted.State = StateLifted
	cases := []struct {
		name   string
		notice *BanNotice
		ticket *ServiceTicket
		now    time.Time
		want   Status
	}{
		{"no documents", nil, nil, testNow, StatusNoTicket},
		{"ticket", nil, &oldTicket, testNow, StatusServing},
		{"ban beats older ticket", &ban, &oldTicket, testNow, StatusBanned},
		{"newer ticket after ban", &ban, &newTicket, testNow, StatusServing},
		{"ban over, old ticket valid", &ban, &oldTicket, time.Unix(until, 0), StatusServing},
		{"lifted, no ticket", &lifted, nil, testNow, StatusNoTicket},
		{"ticket expired", nil, &oldTicket, testNow.Add(DefaultNodeOfflineTolerance), StatusTicketExpired},
	}
	for _, item := range cases {
		if got := Evaluate(item.notice, item.ticket, item.now, time.Time{}); got != item.want {
			t.Errorf("%s: Evaluate = %s, want %s", item.name, got, item.want)
		}
	}
}

// 只有合法签名、生效中的 BanNotice 停流量（首票前不开放保留）；
// 票据过期（商业到期/授权中心不可达/主控失联）只冻结新增、扩容与升级，已有流量继续服务。
// 票据有效期跟主控 30 天宽限走。
func TestStopPolicy(t *testing.T) {
	if DefaultNodeOfflineTolerance != 30*24*time.Hour {
		t.Fatalf("default ticket validity = %s, want the controller's 30-day grace", DefaultNodeOfflineTolerance)
	}
	if DefaultNodeOfflineTolerance > MaxTicketValidity {
		t.Fatal("default ticket validity exceeds MaxTicketValidity")
	}
	cases := []struct {
		status        Status
		stops, frozen bool
	}{
		{StatusServing, false, false},
		{StatusBanned, true, true},
		{StatusNoTicket, true, true},
		{StatusTicketExpired, false, true},
	}
	for _, item := range cases {
		if got := StopsServing(item.status); got != item.stops {
			t.Errorf("StopsServing(%s) = %v, want %v", item.status, got, item.stops)
		}
		if got := Frozen(item.status); got != item.frozen {
			t.Errorf("Frozen(%s) = %v, want %v", item.status, got, item.frozen)
		}
	}
	if StopsServing("unknown") || !Frozen("unknown") {
		t.Error("an unknown status must not stop traffic and must freeze changes")
	}
}

func TestStateFetchProof(t *testing.T) {
	seed := sha256.Sum256([]byte("installation"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	proof, err := SignStateFetchProof(StateFetchProof{InstallationID: testInstallation, RequestID: "state-1",
		RequestedAt: testNow.Unix()}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStateFetchProof(proof, public, testNow.Add(StateFetchClockSkew)); err != nil {
		t.Fatalf("valid proof error = %v", err)
	}
	if err := VerifyStateFetchProof(proof, public, testNow.Add(StateFetchClockSkew+time.Second)); !errors.Is(err, ErrFetchExpired) {
		t.Fatalf("stale proof error = %v", err)
	}
	for name, mutate := range map[string]func(*StateFetchProof){
		"installation": func(p *StateFetchProof) { p.InstallationID = testCustomer },
		"request":      func(p *StateFetchProof) { p.RequestID = "state-2" },
		"time":         func(p *StateFetchProof) { p.RequestedAt++ },
		"signature":    func(p *StateFetchProof) { p.Signature = p.Signature[:10] },
	} {
		mutated := proof
		mutate(&mutated)
		if err := VerifyStateFetchProof(mutated, public, testNow); !errors.Is(err, ErrInvalidFetchProof) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	other := sha256.Sum256([]byte("other"))
	if err := VerifyStateFetchProof(proof, ed25519.NewKeyFromSeed(other[:]).Public().(ed25519.PublicKey), testNow); !errors.Is(err, ErrInvalidFetchProof) {
		t.Fatalf("other key error = %v", err)
	}
}

func TestDecodeStateResponse(t *testing.T) {
	signer := newSigner("a")
	notice, _ := SignNotice(t.Context(), testNotice(1, nil), signer)
	body, _ := json.Marshal(StateResponse{Schema: StateSchema, InstallationID: testInstallation, Status: "banned",
		BanNotice: encodeRaw(notice)})
	response, rawNotice, rawTicket, err := DecodeStateResponse(body)
	if err != nil || response.Status != "banned" || !bytes.Equal(rawNotice, notice) || rawTicket != nil {
		t.Fatalf("DecodeStateResponse = (%#v,%v)", response, err)
	}
	if _, _, _, err := DecodeStateResponse(bytes.Replace(body, []byte(`"schema"`), []byte(`"x":1,"schema"`), 1)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, _, _, err := DecodeStateResponse(bytes.Replace(body, []byte(`"service_ticket":""`), []byte(`"service_ticket":"a+b"`), 1)); err == nil {
		t.Fatal("non-base64url ticket accepted")
	}
}

func encodeRaw(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
