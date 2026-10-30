package site

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// set_protocols needs protocols with at least one change;
// every other action rejects them. Invalid input never reaches the store.
func TestBatchActionSetProtocolsValidation(t *testing.T) {
	on := true
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	items := []BatchActionItem{{ID: uuid.New(), ExpectedRevision: 1}}
	service := NewService(nil)
	for name, request := range map[string]BatchActionRequest{
		"set_protocols without protocols": {Action: BatchActionSetProtocols, Items: items},
		"set_protocols without a change":  {Action: BatchActionSetProtocols, Items: items, Protocols: &BatchProtocols{}},
		"reset and explicit prefer": {Action: BatchActionSetProtocols, Items: items,
			Protocols: &BatchProtocols{TLSPreferServerCiphers: &on, TLSPreferServerCiphersReset: true}},
		"protocols on enable": {Action: BatchActionEnable, Items: items, Protocols: &BatchProtocols{HTTP2Enabled: &on}},
	} {
		request.IdempotencyKey, request.RequestID = "key", "request"
		if _, err := service.BatchAction(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: error = %v, want invalid input", name, err)
		}
	}
	for _, protocols := range []BatchProtocols{
		{HTTP2Enabled: &on}, {HTTP3Enabled: &on}, {TLSPreferServerCiphers: &on}, {TLSPreferServerCiphersReset: true},
	} {
		if !validBatchProtocols(protocols) {
			t.Errorf("valid protocols %+v rejected", protocols)
		}
	}
	if !validBatchAction(BatchActionSetProtocols) {
		t.Fatal("set_protocols is not a batch action")
	}
}

// The single-site TLS audit diff covers what set_protocols writes.
func TestBatchProtocolsTLSAuditChanges(t *testing.T) {
	on := true
	before := Site{HTTP2Enabled: true, HTTP3Enabled: true}
	after := Site{HTTP2Enabled: false, HTTP3Enabled: true, TLSPreferServerCiphers: &on}
	changes := siteTLSAuditOf(before).changes(siteTLSAuditOf(after))
	if len(changes) != 2 || changes["http2_enabled"] == nil || changes["tls_prefer_server_ciphers"] == nil {
		t.Fatalf("changes = %v", changes)
	}
}
