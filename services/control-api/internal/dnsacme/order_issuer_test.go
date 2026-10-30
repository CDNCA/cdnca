package dnsacme

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// CERT-04：未知签发机构、超长名称、带控制字符的备注在进存储前拒绝。
func TestCreateOrderRejectsInvalidIssuerNameAndRemark(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	for name, request := range map[string]CreateOrderRequest{
		"issuer": {Issuer: "buypass"},
		"name":   {Name: strings.Repeat("n", 129)},
		"remark": {Remark: "a\tb"},
		"long":   {Remark: strings.Repeat("备", 257)},
	} {
		t.Run(name, func(t *testing.T) {
			service := NewService(NewStore(nil), nil)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("reached nil store: %v", recovered)
				}
			}()
			request.Domains, request.ChallengeType = []string{"example.com"}, "http-01"
			request.IdempotencyKey, request.RequestID = "issuer-validation", "issuer-validation-request"
			if _, err := service.CreateOrder(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}
