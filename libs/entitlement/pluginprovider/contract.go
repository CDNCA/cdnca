package pluginprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ContractVersion identifies the case set; a result recorded under another
// version is stale and the contract runs again.
const ContractVersion = "cdnca.provider-contract/v1"

// CaseResult is one contract case outcome. Code is a stable reason
// ("" when passed).
type CaseResult struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
	Code   string `json:"code,omitempty"`
}

// ContractReport is the result of one run over every declared kind.
type ContractReport struct {
	Version  string       `json:"version"`
	Passed   bool         `json:"passed"`
	Cases    []CaseResult `json:"cases"`
	Duration int64        `json:"duration_ms"`
}

// RunContract runs the installation contract against the plugin's sandbox
// (sandbox=true in every request): reachability and signatures, then the
// kind's functional cases. The runner never stops at the first failure so
// the administrator sees every broken case.
func RunContract(ctx context.Context, client *Client) ContractReport {
	started := time.Now()
	report := ContractReport{Version: ContractVersion, Passed: true}
	add := func(kind, id string, err error) {
		result := CaseResult{Kind: kind, ID: id, Passed: err == nil}
		if err != nil {
			result.Code = CodeOf(err)
			if result.Code == "" {
				result.Code = err.Error()
			}
			report.Passed = false
		}
		report.Cases = append(report.Cases, result)
	}
	for _, kind := range client.declaration.Kinds {
		run := contractRun{ctx: ctx, client: client, kind: kind, prefix: randomKey("contract")}
		add(kind, "verify", run.call("verify", run.header(), nil))
		add(kind, "rejects_bad_signature", run.rejectsTampered(func(request *http.Request, body []byte, _ string) []byte {
			request.Header.Set(HeaderSignature, EncodeSignature(make([]byte, 64)))
			return body
		}))
		add(kind, "rejects_tampered_body", run.rejectsTampered(func(_ *http.Request, body []byte, _ string) []byte {
			return append([]byte(strings.TrimSuffix(string(body), "}")), []byte(`,"x":1}`)...)
		}))
		add(kind, "rejects_stale_timestamp", run.rejectsTampered(func(request *http.Request, body []byte, _ string) []byte {
			request.Header.Set(HeaderTimestamp, "1000000000")
			return body
		}))
		add(kind, "rejects_replayed_nonce", run.rejectsReplay())
		switch kind {
		case KindDNS:
			run.dns(add)
		case KindSMS:
			run.sms(add)
		case KindICP:
			run.icp(add)
		case KindMail:
			run.mail(add)
		case KindPayment:
			run.payment(add)
		}
	}
	report.Duration = time.Since(started).Milliseconds()
	return report
}

type contractRun struct {
	ctx    context.Context
	client *Client
	kind   string
	prefix string
	seq    int
}

func randomKey(prefix string) string {
	var value [8]byte
	_, _ = rand.Read(value[:])
	return prefix + "-" + hex.EncodeToString(value[:])
}

func (run *contractRun) key() string {
	run.seq++
	return run.prefix + "-" + string(rune('a'+run.seq))
}

func (run *contractRun) header() RequestHeader {
	return RequestHeader{Protocol: Protocol, Sandbox: true}
}

func (run *contractRun) call(action string, request any, result any) error {
	return run.client.Call(run.ctx, run.kind, action, request, result)
}

// contractError is a case failure that is not a transport error.
type contractError string

func (e contractError) Error() string { return string(e) }

func (run *contractRun) rejectsTampered(alter tamper) error {
	status, err := run.client.call(run.ctx, run.kind, "verify", run.header(), nil, alter, nil)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil
	case err == nil:
		return contractError("accepted_forged_request")
	default:
		return contractError("forged_request_not_401")
	}
}

func (run *contractRun) rejectsReplay() error {
	var replayNonce string
	if _, err := run.client.call(run.ctx, run.kind, "verify", run.header(), nil,
		func(request *http.Request, body []byte, nonce string) []byte {
			replayNonce = nonce
			return body
		}, nil); err != nil {
		return err
	}
	// Same nonce, freshly signed: only the nonce memory can refuse it.
	return run.rejectsTampered(func(request *http.Request, body []byte, _ string) []byte {
		timestamp := request.Header.Get(HeaderTimestamp)
		request.Header.Set(HeaderNonce, replayNonce)
		request.Header.Set(HeaderSignature, EncodeSignature(signWith(run.client, run.kind, "verify", timestamp,
			replayNonce, body)))
		return body
	})
}

func (run *contractRun) dns(add func(kind, id string, err error)) {
	zone := SandboxZone
	owner := run.prefix + "." + zone
	list := func(name string) ([]DNSRecord, error) {
		var response DNSListResponse
		err := run.call("list_records", DNSListRequest{RequestHeader: run.header(), Zone: zone, Name: name}, &response)
		return response.Records, err
	}
	find := func(records []DNSRecord, id string) (DNSRecord, bool) {
		for _, record := range records {
			if record.ID == id {
				return record, true
			}
		}
		return DNSRecord{}, false
	}
	create := func(record DNSRecord, key string) (string, error) {
		var response DNSCreateResponse
		err := run.call("create_record", DNSWriteRequest{RequestHeader: run.header(), Zone: zone, Record: record,
			IdempotencyKey: key}, &response)
		if err == nil && (response.ID == "" || len(response.ID) > 256) {
			err = contractError("missing_record_id")
		}
		return response.ID, err
	}
	// Create, read back, idempotent repeat.
	a := DNSRecord{Name: owner, Type: "A", Value: "203.0.113.10", TTL: 600, Line: "默认"}
	key := run.key()
	id, err := create(a, key)
	add(KindDNS, "create_a", err)
	if err == nil {
		records, err := list(owner)
		if got, ok := find(records, id); err == nil && (!ok || got.Value != a.Value || got.Type != "A") {
			err = contractError("created_record_not_listed")
		}
		add(KindDNS, "list_created", err)
		again, err := create(a, key)
		if err == nil && again != id {
			err = contractError("idempotency_key_created_twice")
		}
		if err == nil {
			if records, listErr := list(owner); listErr == nil && len(records) != 1 {
				err = contractError("idempotency_key_created_twice")
			}
		}
		add(KindDNS, "create_idempotent", err)
		updated := a
		updated.ID, updated.Value = id, "203.0.113.11"
		err = run.call("update_record", DNSWriteRequest{RequestHeader: run.header(), Zone: zone, Record: updated,
			IdempotencyKey: run.key()}, nil)
		if err == nil {
			records, listErr := list(owner)
			if got, ok := find(records, id); listErr != nil || !ok || got.Value != updated.Value {
				err = contractError("update_not_applied")
			}
		}
		add(KindDNS, "update_a", err)
		err = run.call("delete_record", DNSDeleteRequest{RequestHeader: run.header(), Zone: zone, ID: id,
			IdempotencyKey: run.key()}, nil)
		if err == nil {
			records, listErr := list(owner)
			if _, ok := find(records, id); listErr != nil || ok {
				err = contractError("delete_not_applied")
			}
		}
		add(KindDNS, "delete_a", err)
		err = run.call("delete_record", DNSDeleteRequest{RequestHeader: run.header(), Zone: zone, ID: id,
			IdempotencyKey: run.key()}, nil)
		if err == nil {
			err = contractError("delete_missing_not_not_found")
		} else if CodeOf(err) == "not_found" {
			err = nil
		}
		add(KindDNS, "delete_missing_not_found", err)
	}
	// Line and TXT: the record keeps its unified line and exact TXT value.
	txt := DNSRecord{Name: "_acme-challenge." + owner, Type: "TXT", Value: "contract-" + run.prefix, TTL: 600, Line: "电信"}
	txtID, err := create(txt, run.key())
	if err == nil {
		records, listErr := list(txt.Name)
		if got, ok := find(records, txtID); listErr != nil || !ok || got.Value != txt.Value || got.Line != "电信" {
			err = contractError("txt_or_line_not_kept")
		}
		_ = run.call("delete_record", DNSDeleteRequest{RequestHeader: run.header(), Zone: zone, ID: txtID,
			IdempotencyKey: run.key()}, nil)
	}
	add(KindDNS, "txt_line", err)
	// An unknown zone is refused, never created.
	err = run.call("list_records", DNSListRequest{RequestHeader: run.header(), Zone: "unknown-" + zone}, &DNSListResponse{})
	if err == nil {
		err = contractError("unknown_zone_accepted")
	} else if code := CodeOf(err); code == "zone_not_found" || code == "not_found" {
		err = nil
	}
	add(KindDNS, "unknown_zone", err)
}

func (run *contractRun) sms(add func(kind, id string, err error)) {
	key := run.key()
	request := SMSSendRequest{RequestHeader: run.header(), To: SandboxPhone, TemplateID: "verify_code",
		Params: map[string]string{"code": "123456"}, Body: "【cdnca】验证码 123456（契约测试）", IdempotencyKey: key}
	var first, second SMSSendResponse
	err := run.call("send", request, &first)
	if err == nil && (first.DeliveryID == "" || len(first.DeliveryID) > 256) {
		err = contractError("missing_delivery_id")
	}
	add(KindSMS, "send", err)
	if err == nil {
		err = run.call("send", request, &second)
		if err == nil && second.DeliveryID != first.DeliveryID {
			err = contractError("idempotency_key_sent_twice")
		}
		add(KindSMS, "send_idempotent", err)
	}
	bad := request
	bad.To, bad.IdempotencyKey = "13800000000", run.key()
	err = run.call("send", bad, &SMSSendResponse{})
	if err == nil {
		err = contractError("invalid_number_accepted")
	} else if CodeOf(err) == "invalid_request" {
		err = nil
	}
	add(KindSMS, "invalid_number", err)
}

// mail: health, a sandbox send with HTML and reply-to, the idempotent
// repeat, and a malformed recipient refused as invalid_request.
func (run *contractRun) mail(add func(kind, id string, err error)) {
	add(KindMail, "health", run.call("health", run.header(), nil))
	key := run.key()
	request := MailSendRequest{RequestHeader: run.header(), To: SandboxMailbox, Subject: "cdnca 契约测试",
		Text: "验证码 123456（契约测试）", HTML: "<p>验证码 <b>123456</b>（契约测试）</p>",
		ReplyTo: "noreply@cdnca-sandbox.test", IdempotencyKey: key}
	var first, second MailSendResponse
	err := run.call("send", request, &first)
	if err == nil && (first.MessageID == "" || len(first.MessageID) > 256) {
		err = contractError("missing_message_id")
	}
	add(KindMail, "send", err)
	if err == nil {
		err = run.call("send", request, &second)
		if err == nil && second.MessageID != first.MessageID {
			err = contractError("idempotency_key_sent_twice")
		}
		add(KindMail, "send_idempotent", err)
	}
	bad := request
	bad.To, bad.IdempotencyKey = "not-an-address", run.key()
	err = run.call("send", bad, &MailSendResponse{})
	if err == nil {
		err = contractError("invalid_recipient_accepted")
	} else if CodeOf(err) == "invalid_request" {
		err = nil
	}
	add(KindMail, "invalid_recipient", err)
}

func (run *contractRun) icp(add func(kind, id string, err error)) {
	query := func(domain string) (ICPQueryResponse, error) {
		var response ICPQueryResponse
		err := run.call("query", ICPQueryRequest{RequestHeader: run.header(), Domain: domain}, &response)
		return response, err
	}
	filed, err := query(SandboxFiledDomain)
	if err == nil && (filed.Status != ICPFiled || filed.Licence == "") {
		err = contractError("filed_domain_wrong")
	}
	add(KindICP, "filed", err)
	unfiled, err := query(SandboxUnfiledDomain)
	if err == nil && unfiled.Status != ICPUnfiled {
		err = contractError("unfiled_domain_wrong")
	}
	add(KindICP, "unfiled", err)
	err = run.call("query", ICPQueryRequest{RequestHeader: run.header(), Domain: ""}, &ICPQueryResponse{})
	if err == nil {
		err = contractError("empty_domain_accepted")
	} else if CodeOf(err) == "invalid_request" {
		err = nil
	}
	add(KindICP, "invalid_domain", err)
}

// payment runs the collection channel cases against the sandbox merchant:
// checkout, an unpaid order is not reported paid, a sandbox settlement is
// reported paid by query and by the signed gateway notification with the
// same amount, a tampered notification is refused, refund is idempotent
// and bounded, the day statement lists the payment, unknown orders are
// not found.
func (run *contractRun) payment(add func(kind, id string, err error)) {
	orderRef := run.prefix
	const amount = int64(1234)
	checkout := PaymentCheckoutRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant, OrderRef: orderRef,
		AmountMinor: amount, Currency: "CNY", Method: "alipay", Subject: "cdnca contract",
		NotifyURL: "https://control.cdnca-sandbox.test/payments/v1/notify/contract", ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		IdempotencyKey: run.key()}
	var created PaymentCheckoutResponse
	err := run.call("create_checkout", checkout, &created)
	if err == nil && (created.OrderRef != orderRef || created.MerchantID != SandboxMerchant || created.AmountMinor != amount ||
		created.Currency != "CNY" || !validCheckoutAction(created)) {
		err = contractError("checkout_not_bound")
	}
	add(KindPayment, "create_checkout", err)
	if err != nil {
		return
	}
	query := func() (PaymentFact, error) {
		var fact PaymentFact
		err := run.call("query_payment", PaymentQueryRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
			OrderRef: orderRef}, &fact)
		return fact, err
	}
	fact, err := query()
	if err == nil && fact.Status == PaymentSucceeded {
		err = contractError("unpaid_reported_paid")
	}
	add(KindPayment, "query_unpaid", err)

	var settled PaymentSettleResponse
	err = run.call("sandbox_settle", PaymentSettleRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
		OrderRef: orderRef}, &settled)
	add(KindPayment, "sandbox_settle", err)
	if err != nil {
		return
	}
	fact, err = query()
	if err == nil && !paidAs(fact, orderRef, amount) {
		err = contractError("paid_query_mismatch")
	}
	add(KindPayment, "query_paid", err)
	tradeNo := fact.ExternalPaymentID

	var notified PaymentFact
	err = run.call("verify_callback", PaymentCallbackRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
		Callback: settled.Callback}, &notified)
	if err == nil && (!paidAs(notified, orderRef, amount) || notified.ExternalPaymentID != tradeNo) {
		err = contractError("callback_fact_mismatch")
	}
	add(KindPayment, "verify_callback", err)
	tampered := settled.Callback
	tampered.Body = tamperAmount(tampered.Body)
	err = run.call("verify_callback", PaymentCallbackRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
		Callback: tampered}, &PaymentFact{})
	if err == nil {
		err = contractError("tampered_callback_accepted")
	} else if code := CodeOf(err); code == "invalid_signature" || code == "invalid_request" {
		err = nil
	}
	add(KindPayment, "rejects_tampered_callback", err)

	refund := PaymentRefundRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant, OrderRef: orderRef,
		ExternalPaymentID: tradeNo, RefundRef: orderRef + "-r1", AmountMinor: 234, Currency: "CNY", IdempotencyKey: run.key()}
	var first, second PaymentRefundResponse
	err = run.call("refund", refund, &first)
	if err == nil && (first.RefundRef != refund.RefundRef || first.ExternalRefundID == "" || first.AmountMinor != 234 ||
		first.Status == PaymentFailed) {
		err = contractError("refund_not_bound")
	}
	if err == nil {
		if err = run.call("refund", refund, &second); err == nil && second.ExternalRefundID != first.ExternalRefundID {
			err = contractError("idempotency_key_refunded_twice")
		}
	}
	add(KindPayment, "refund_idempotent", err)
	over := refund
	over.RefundRef, over.AmountMinor, over.IdempotencyKey = orderRef+"-r2", amount, run.key()
	err = run.call("refund", over, &PaymentRefundResponse{})
	if err == nil {
		err = contractError("over_refund_accepted")
	} else if CodeOf(err) == "invalid_request" {
		err = nil
	}
	add(KindPayment, "refund_over_limit", err)

	var statement PaymentStatement
	err = run.call("reconcile", PaymentReconcileRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
		Date: time.Now().UTC().Format("2006-01-02")}, &statement)
	if err == nil {
		found := false
		for _, entry := range statement.Entries {
			found = found || entry.OrderRef == orderRef && paidAs(entry, orderRef, amount) && entry.ExternalPaymentID == tradeNo
		}
		if !found {
			err = contractError("statement_missing_payment")
		}
	}
	add(KindPayment, "reconcile", err)

	err = run.call("query_payment", PaymentQueryRequest{RequestHeader: run.header(), MerchantID: SandboxMerchant,
		OrderRef: orderRef + "-unknown"}, &PaymentFact{})
	if err == nil {
		err = contractError("unknown_order_reported")
	} else if CodeOf(err) == "not_found" {
		err = nil
	}
	add(KindPayment, "unknown_order", err)
}

func paidAs(fact PaymentFact, orderRef string, amount int64) bool {
	return fact.Status == PaymentSucceeded && fact.OrderRef == orderRef && fact.MerchantID == SandboxMerchant &&
		fact.AmountMinor == amount && fact.Currency == "CNY" && fact.ExternalPaymentID != ""
}

func validCheckoutAction(response PaymentCheckoutResponse) bool {
	switch response.Action {
	case PaymentActionRedirect:
		_, ok := checkoutURL(response.URL)
		return ok
	case PaymentActionQRCode:
		return response.QRContent != "" && len(response.QRContent) <= 2048
	}
	return false
}

// checkoutURL accepts an https URL a payer can open.
func checkoutURL(value string) (string, bool) {
	if len(value) > 2048 || !strings.HasPrefix(value, "https://") {
		return "", false
	}
	return value, true
}

// tamperAmount changes the notification so its signature no longer holds
// (a JSON amount_minor is bumped when present, otherwise a byte is flipped).
func tamperAmount(body []byte) []byte {
	var document map[string]any
	if json.Unmarshal(body, &document) == nil {
		if amount, ok := document["amount_minor"].(float64); ok {
			document["amount_minor"] = amount + 1
			if changed, err := json.Marshal(document); err == nil {
				return changed
			}
		}
	}
	changed := append([]byte(nil), body...)
	if len(changed) == 0 {
		return []byte("x")
	}
	changed[len(changed)/2] ^= 0x01
	return changed
}
