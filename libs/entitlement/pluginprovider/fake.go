package pluginprovider

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FakePlugin is the reference implementation of the plugin side of
// cdnca.provider/v1 (all three kinds), holding state in memory. Tests serve
// it with httptest.NewTLSServer; developers can read it as the server
// contract: request signature, timestamp and nonce checks, idempotency,
// signed responses, sandbox behavior.
//
// The Misbehave switches turn it into a broken or malicious plugin for the
// contract runner's negative cases.
type FakePlugin struct {
	PluginID string
	// InstallationKey verifies request signatures (the control plane's
	// installation public key, given to the developer at install time).
	InstallationKey ed25519.PublicKey
	// ResponseKey signs responses (its public half is provider_response_key).
	ResponseKey ed25519.PrivateKey
	// Zone is the zone served outside sandbox mode (sandbox: SandboxZone).
	Zone string
	Now  func() time.Time

	Misbehave Misbehavior

	mu          sync.Mutex
	records     map[string][]DNSRecord // zone -> records
	nonces      map[string]bool
	idempotency map[string]json.RawMessage
	next        int
	// Calls counts requests per "kind/action"; Sent records SMS sends,
	// Mailed mail sends.
	Calls  map[string]int
	Sent   []SMSSendRequest
	Mailed []MailSendRequest

	// Payment: Merchant is served outside sandbox mode (sandbox:
	// SandboxMerchant); GatewayKey signs the simulated gateway
	// notifications (random when nil).
	Merchant   string
	GatewayKey []byte
	payments   map[string]*fakePayment
}

// Misbehavior flags.
type Misbehavior struct {
	// AcceptBadSignature: skip request signature, timestamp and nonce checks.
	AcceptBadSignature bool
	// WrongResponseKey: sign responses with another key.
	WrongResponseKey bool
	// NoIdempotency: a repeated idempotency key applies the write again.
	NoIdempotency bool
	// IgnoreDelete: delete_record answers ok but keeps the record.
	IgnoreDelete bool
	// WrongICP: answer filed for every domain.
	WrongICP bool
	// Unreachable: answer 503 to everything.
	Unreachable bool
	// AcceptBadMailbox: mail send takes any recipient string.
	AcceptBadMailbox bool
	// Payment (PA-23): ForgeCallbackPaid reports any callback bytes as a
	// succeeded payment without checking the gateway signature;
	// QueryAlwaysPaid answers query_payment "succeeded" for unpaid orders;
	// WrongAmount reports every fact one minor unit off.
	ForgeCallbackPaid bool
	QueryAlwaysPaid   bool
	WrongAmount       bool
}

func (fake *FakePlugin) now() time.Time {
	if fake.Now != nil {
		return fake.Now()
	}
	return time.Now()
}

// Records returns a copy of the zone's records.
func (fake *FakePlugin) Records(zone string) []DNSRecord {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]DNSRecord(nil), fake.records[zone]...)
}

func (fake *FakePlugin) reply(writer http.ResponseWriter, kind, action, nonce string, status int, code string, data any) {
	envelope := map[string]any{"protocol": Protocol, "ok": code == ""}
	if code != "" {
		envelope["error"] = map[string]string{"code": code, "message": "fake plugin"}
	}
	if data != nil {
		envelope["data"] = data
	}
	body, _ := json.Marshal(envelope)
	key := fake.ResponseKey
	if fake.Misbehave.WrongResponseKey {
		_, key, _ = ed25519.GenerateKey(nil)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set(HeaderResponseSignature, EncodeSignature(ed25519.Sign(key,
		ResponseMessage(fake.PluginID, kind, action, nonce, body))))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func (fake *FakePlugin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// The plugin may live under a base path: everything after PathPrefix.
	index := strings.Index(request.URL.Path, PathPrefix)
	ok := index >= 0
	kind, action, _ := strings.Cut(request.URL.Path[max(index, 0)+len(PathPrefix):], "/")
	nonce := request.Header.Get(HeaderNonce)
	if !ok || request.Method != http.MethodPost || !ValidAction(kind, action) {
		fake.reply(writer, kind, action, nonce, http.StatusNotFound, "unsupported", nil)
		return
	}
	if fake.Misbehave.Unreachable {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		fake.reply(writer, kind, action, nonce, http.StatusOK, "invalid_request", nil)
		return
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.nonces == nil {
		fake.nonces, fake.idempotency, fake.records, fake.Calls = map[string]bool{}, map[string]json.RawMessage{},
			map[string][]DNSRecord{}, map[string]int{}
	}
	if !fake.Misbehave.AcceptBadSignature {
		timestamp := request.Header.Get(HeaderTimestamp)
		unix, err := strconv.ParseInt(timestamp, 10, 64)
		signature, signatureOK := DecodeSignature(request.Header.Get(HeaderSignature))
		skew := fake.now().Unix() - unix
		if err != nil || !signatureOK || len(nonce) != 32 || skew > MaxClockSkewSeconds || -skew > MaxClockSkewSeconds ||
			fake.nonces[nonce] || !ed25519.Verify(fake.InstallationKey, RequestMessage(
			request.Header.Get(HeaderInstallation), fake.PluginID, kind, action, timestamp, nonce, body), signature) {
			fake.reply(writer, kind, action, nonce, http.StatusUnauthorized, "unauthorized", nil)
			return
		}
		fake.nonces[nonce] = true
	}
	fake.Calls[kind+"/"+action]++
	var header RequestHeader
	if json.Unmarshal(body, &header) != nil || header.Protocol != Protocol {
		fake.reply(writer, kind, action, nonce, http.StatusOK, "invalid_request", nil)
		return
	}
	if action == "verify" || action == "health" {
		fake.reply(writer, kind, action, nonce, http.StatusOK, "", map[string]any{})
		return
	}
	var code string
	var data any
	switch kind {
	case KindDNS:
		code, data = fake.dns(action, header.Sandbox, body)
	case KindSMS:
		code, data = fake.sms(body)
	case KindMail:
		code, data = fake.mail(body)
	case KindICP:
		code, data = fake.icp(header.Sandbox, body)
	case KindPayment:
		code, data = fake.payment(action, header.Sandbox, body)
	}
	fake.reply(writer, kind, action, nonce, http.StatusOK, code, data)
}

// idempotent replays the stored answer of key, or stores what apply returns.
func (fake *FakePlugin) idempotent(key string, apply func() (string, any)) (string, any) {
	if key == "" || len(key) > 128 {
		return "invalid_request", nil
	}
	if stored, ok := fake.idempotency[key]; ok && !fake.Misbehave.NoIdempotency {
		return "", stored
	}
	code, data := apply()
	if code == "" {
		encoded, _ := json.Marshal(data)
		fake.idempotency[key] = encoded
	}
	return code, data
}

func (fake *FakePlugin) zone(sandbox bool, zone string) bool {
	return sandbox && zone == SandboxZone || !sandbox && fake.Zone != "" && zone == fake.Zone
}

func (fake *FakePlugin) dns(action string, sandbox bool, body []byte) (string, any) {
	switch action {
	case "list_records":
		var input DNSListRequest
		if json.Unmarshal(body, &input) != nil {
			return "invalid_request", nil
		}
		if !fake.zone(sandbox, input.Zone) {
			return "zone_not_found", nil
		}
		records := []DNSRecord{}
		for _, record := range fake.records[input.Zone] {
			if input.Name == "" || strings.EqualFold(record.Name, strings.TrimSuffix(input.Name, ".")) {
				records = append(records, record)
			}
		}
		return "", DNSListResponse{Records: records}
	case "create_record", "update_record":
		var input DNSWriteRequest
		if json.Unmarshal(body, &input) != nil || input.Record.Name == "" || input.Record.Type == "" || input.Record.TTL == 0 {
			return "invalid_request", nil
		}
		if !fake.zone(sandbox, input.Zone) {
			return "zone_not_found", nil
		}
		return fake.idempotent(input.IdempotencyKey, func() (string, any) {
			records := fake.records[input.Zone]
			if action == "create_record" {
				fake.next++
				input.Record.ID = "r" + strconv.Itoa(fake.next)
				fake.records[input.Zone] = append(records, input.Record)
				return "", DNSCreateResponse{ID: input.Record.ID}
			}
			for index := range records {
				if records[index].ID == input.Record.ID {
					records[index] = input.Record
					return "", map[string]any{}
				}
			}
			return "not_found", nil
		})
	case "delete_record":
		var input DNSDeleteRequest
		if json.Unmarshal(body, &input) != nil || input.ID == "" {
			return "invalid_request", nil
		}
		if !fake.zone(sandbox, input.Zone) {
			return "zone_not_found", nil
		}
		return fake.idempotent(input.IdempotencyKey, func() (string, any) {
			records := fake.records[input.Zone]
			for index := range records {
				if records[index].ID == input.ID {
					if !fake.Misbehave.IgnoreDelete {
						fake.records[input.Zone] = append(records[:index:index], records[index+1:]...)
					}
					return "", map[string]any{}
				}
			}
			return "not_found", nil
		})
	}
	return "unsupported", nil
}

func (fake *FakePlugin) sms(body []byte) (string, any) {
	var input SMSSendRequest
	if json.Unmarshal(body, &input) != nil || !strings.HasPrefix(input.To, "+") || len(input.To) < 8 || input.Body == "" {
		return "invalid_request", nil
	}
	return fake.idempotent(input.IdempotencyKey, func() (string, any) {
		fake.next++
		fake.Sent = append(fake.Sent, input)
		return "", SMSSendResponse{DeliveryID: "sms-" + strconv.Itoa(fake.next)}
	})
}

func (fake *FakePlugin) mail(body []byte) (string, any) {
	var input MailSendRequest
	if json.Unmarshal(body, &input) != nil || input.Subject == "" || input.Text == "" {
		return "invalid_request", nil
	}
	if at := strings.LastIndexByte(input.To, '@'); !fake.Misbehave.AcceptBadMailbox && (at < 1 || at == len(input.To)-1 ||
		strings.ContainsAny(input.To, " <>\r\n")) {
		return "invalid_request", nil
	}
	return fake.idempotent(input.IdempotencyKey, func() (string, any) {
		fake.next++
		fake.Mailed = append(fake.Mailed, input)
		return "", MailSendResponse{MessageID: "mail-" + strconv.Itoa(fake.next)}
	})
}

func (fake *FakePlugin) icp(sandbox bool, body []byte) (string, any) {
	var input ICPQueryRequest
	if json.Unmarshal(body, &input) != nil || input.Domain == "" {
		return "invalid_request", nil
	}
	if fake.Misbehave.WrongICP || input.Domain == SandboxFiledDomain || !sandbox && strings.HasSuffix(input.Domain, ".cn") {
		return "", ICPQueryResponse{Status: ICPFiled, Licence: "京ICP备00000000号", Subject: "沙箱主体"}
	}
	return "", ICPQueryResponse{Status: ICPUnfiled}
}
