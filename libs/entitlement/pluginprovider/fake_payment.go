package pluginprovider

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

// fakePayment is one order the fake gateway knows.
type fakePayment struct {
	merchant, orderRef, tradeNo, currency, method string
	amount, refunded                              int64
	status                                        string
	paidAt                                        int64
}

// FakeGatewayNotice is the notification body the fake gateway posts to the
// notify URL (signed with GatewayKey, field sign).
type FakeGatewayNotice struct {
	MerchantID  string `json:"merchant_id"`
	OrderRef    string `json:"order_ref"`
	TradeNo     string `json:"trade_no"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	Status      string `json:"status"`
	PaidAt      int64  `json:"paid_at"`
	Sign        string `json:"sign"`
}

func (notice FakeGatewayNotice) canonical() string {
	return notice.MerchantID + "|" + notice.OrderRef + "|" + notice.TradeNo + "|" +
		strconv.FormatInt(notice.AmountMinor, 10) + "|" + notice.Currency + "|" + notice.Status + "|" +
		strconv.FormatInt(notice.PaidAt, 10)
}

func (fake *FakePlugin) gatewayKey() []byte {
	if len(fake.GatewayKey) == 0 {
		fake.GatewayKey = make([]byte, 32)
		_, _ = rand.Read(fake.GatewayKey)
	}
	return fake.GatewayKey
}

func (fake *FakePlugin) signNotice(notice FakeGatewayNotice) FakeGatewayNotice {
	mac := hmac.New(sha256.New, fake.gatewayKey())
	mac.Write([]byte(notice.canonical()))
	notice.Sign = hex.EncodeToString(mac.Sum(nil))
	return notice
}

func paymentKey(sandbox bool, merchant, orderRef string) string {
	return strconv.FormatBool(sandbox) + "/" + merchant + "/" + orderRef
}

func (fake *FakePlugin) merchant(sandbox bool, merchant string) bool {
	return sandbox && merchant == SandboxMerchant || !sandbox && fake.Merchant != "" && merchant == fake.Merchant
}

func (fake *FakePlugin) fact(record *fakePayment) PaymentFact {
	fact := PaymentFact{MerchantID: record.merchant, OrderRef: record.orderRef, Status: record.status,
		AmountMinor: record.amount, Currency: record.currency, PaidAt: record.paidAt}
	if record.status == PaymentSucceeded {
		fact.ExternalPaymentID = record.tradeNo
	}
	if fake.Misbehave.WrongAmount {
		fact.AmountMinor++
	}
	return fact
}

// settle marks an order paid and returns the gateway notification.
func (fake *FakePlugin) settle(record *fakePayment) PaymentCallback {
	if record.status != PaymentSucceeded {
		fake.next++
		record.status, record.tradeNo, record.paidAt = PaymentSucceeded, "T"+strconv.Itoa(fake.next), fake.now().Unix()
	}
	notice := fake.signNotice(FakeGatewayNotice{MerchantID: record.merchant, OrderRef: record.orderRef,
		TradeNo: record.tradeNo, AmountMinor: record.amount, Currency: record.currency, Status: PaymentSucceeded,
		PaidAt: record.paidAt})
	body, _ := json.Marshal(notice)
	return PaymentCallback{Method: "POST", ContentType: "application/json", Body: body}
}

// Pay simulates the payer completing a (non-sandbox) payment at the
// gateway and returns the notification the gateway sends; ok is false for
// an unknown order.
func (fake *FakePlugin) Pay(orderRef string) (PaymentCallback, bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	record, ok := fake.payments[paymentKey(false, fake.Merchant, orderRef)]
	if !ok {
		return PaymentCallback{}, false
	}
	return fake.settle(record), true
}

// SignedNotice signs an arbitrary notice with the gateway key (tests build
// "valid" notices about orders the gateway never saw paid).
func (fake *FakePlugin) SignedNotice(notice FakeGatewayNotice) PaymentCallback {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	body, _ := json.Marshal(fake.signNotice(notice))
	return PaymentCallback{Method: "POST", ContentType: "application/json", Body: body}
}

func validCurrency(currency string) bool { return currency == "CNY" }

func (fake *FakePlugin) payment(action string, sandbox bool, body []byte) (string, any) {
	if fake.payments == nil {
		fake.payments = map[string]*fakePayment{}
	}
	switch action {
	case "create_checkout":
		var input PaymentCheckoutRequest
		if json.Unmarshal(body, &input) != nil || input.OrderRef == "" || len(input.OrderRef) > 64 ||
			input.AmountMinor <= 0 || !validCurrency(input.Currency) || input.NotifyURL == "" {
			return "invalid_request", nil
		}
		if !fake.merchant(sandbox, input.MerchantID) {
			return "not_found", nil
		}
		return fake.idempotent(input.IdempotencyKey, func() (string, any) {
			key := paymentKey(sandbox, input.MerchantID, input.OrderRef)
			record, exists := fake.payments[key]
			if exists && (record.amount != input.AmountMinor || record.currency != input.Currency) {
				return "conflict", nil
			}
			if !exists {
				record = &fakePayment{merchant: input.MerchantID, orderRef: input.OrderRef, amount: input.AmountMinor,
					currency: input.Currency, method: input.Method, status: PaymentPending}
				fake.payments[key] = record
			}
			response := PaymentCheckoutResponse{MerchantID: record.merchant, OrderRef: record.orderRef,
				AmountMinor: record.amount, Currency: record.currency, Action: PaymentActionRedirect,
				URL: "https://pay.provider.example/cashier/" + record.orderRef}
			if fake.Misbehave.WrongAmount {
				response.AmountMinor++
			}
			return "", response
		})
	case "query_payment":
		var input PaymentQueryRequest
		if json.Unmarshal(body, &input) != nil || input.OrderRef == "" {
			return "invalid_request", nil
		}
		if !fake.merchant(sandbox, input.MerchantID) {
			return "not_found", nil
		}
		record, ok := fake.payments[paymentKey(sandbox, input.MerchantID, input.OrderRef)]
		if !ok {
			return "not_found", nil
		}
		fact := fake.fact(record)
		if fake.Misbehave.QueryAlwaysPaid && fact.Status != PaymentSucceeded {
			fact.Status, fact.ExternalPaymentID, fact.PaidAt = PaymentSucceeded, "T-forged-"+record.orderRef, fake.now().Unix()
		}
		return "", fact
	case "verify_callback":
		var input PaymentCallbackRequest
		if json.Unmarshal(body, &input) != nil {
			return "invalid_request", nil
		}
		if !fake.merchant(sandbox, input.MerchantID) {
			return "not_found", nil
		}
		var notice FakeGatewayNotice
		if json.Unmarshal(input.Callback.Body, &notice) != nil {
			return "invalid_signature", nil
		}
		if fake.Misbehave.ForgeCallbackPaid {
			return "", PaymentFact{MerchantID: notice.MerchantID, OrderRef: notice.OrderRef,
				ExternalPaymentID: notice.TradeNo, Status: PaymentSucceeded, AmountMinor: notice.AmountMinor,
				Currency: notice.Currency, PaidAt: notice.PaidAt}
		}
		expected := fake.signNotice(notice)
		if !hmac.Equal([]byte(expected.Sign), []byte(notice.Sign)) || notice.MerchantID != input.MerchantID {
			return "invalid_signature", nil
		}
		return "", PaymentFact{MerchantID: notice.MerchantID, OrderRef: notice.OrderRef,
			ExternalPaymentID: notice.TradeNo, Status: notice.Status, AmountMinor: notice.AmountMinor,
			Currency: notice.Currency, PaidAt: notice.PaidAt}
	case "refund":
		var input PaymentRefundRequest
		if json.Unmarshal(body, &input) != nil || input.RefundRef == "" || input.AmountMinor <= 0 ||
			!validCurrency(input.Currency) {
			return "invalid_request", nil
		}
		if !fake.merchant(sandbox, input.MerchantID) {
			return "not_found", nil
		}
		return fake.idempotent(input.IdempotencyKey, func() (string, any) {
			record, ok := fake.payments[paymentKey(sandbox, input.MerchantID, input.OrderRef)]
			if !ok || record.status != PaymentSucceeded || record.tradeNo != input.ExternalPaymentID {
				return "not_found", nil
			}
			if input.AmountMinor > record.amount-record.refunded || input.Currency != record.currency {
				return "invalid_request", nil
			}
			record.refunded += input.AmountMinor
			fake.next++
			return "", PaymentRefundResponse{RefundRef: input.RefundRef, ExternalRefundID: "R" + strconv.Itoa(fake.next),
				Status: PaymentSucceeded, AmountMinor: input.AmountMinor, Currency: input.Currency}
		})
	case "reconcile":
		var input PaymentReconcileRequest
		if json.Unmarshal(body, &input) != nil {
			return "invalid_request", nil
		}
		day, err := time.Parse("2006-01-02", input.Date)
		if err != nil {
			return "invalid_request", nil
		}
		if !fake.merchant(sandbox, input.MerchantID) {
			return "not_found", nil
		}
		statement := PaymentStatement{Date: input.Date, Entries: []PaymentFact{}}
		for key, record := range fake.payments {
			paid := time.Unix(record.paidAt, 0).UTC()
			if record.status == PaymentSucceeded && record.merchant == input.MerchantID &&
				key == paymentKey(sandbox, record.merchant, record.orderRef) &&
				!paid.Before(day) && paid.Before(day.Add(24*time.Hour)) {
				statement.Entries = append(statement.Entries, fake.fact(record))
			}
		}
		return "", statement
	case "sandbox_settle":
		var input PaymentSettleRequest
		if json.Unmarshal(body, &input) != nil {
			return "invalid_request", nil
		}
		if !sandbox {
			return "unsupported", nil
		}
		record, ok := fake.payments[paymentKey(true, input.MerchantID, input.OrderRef)]
		if !ok || input.MerchantID != SandboxMerchant {
			return "not_found", nil
		}
		return "", PaymentSettleResponse{Callback: fake.settle(record)}
	}
	return "unsupported", nil
}
