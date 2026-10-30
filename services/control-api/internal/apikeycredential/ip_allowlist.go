package apikeycredential

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ReasonClientIPMissing    = "api_key.client_ip_missing"
	ReasonClientIPInvalid    = "api_key.client_ip_invalid"
	ReasonClientIPSpoofed    = "api_key.client_ip_spoofed"
	ReasonClientIPNotAllowed = "api_key.client_ip_not_allowed"
	ReasonIPAllowlistInvalid = "api_key.ip_allowlist_invalid"
)

type clientIPFact struct {
	address    netip.Addr
	requestID  string
	reasonCode string
}

type clientIPContextKey struct{}

func WithClientIP(ctx context.Context, address netip.Addr, requestID string) context.Context {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return WithClientIPFailure(ctx, requestID, ReasonClientIPInvalid)
	}
	return context.WithValue(ctx, clientIPContextKey{}, clientIPFact{
		address: address, requestID: strings.TrimSpace(requestID),
	})
}

func WithClientIPFailure(ctx context.Context, requestID, reasonCode string) context.Context {
	if reasonCode != ReasonClientIPMissing && reasonCode != ReasonClientIPInvalid &&
		reasonCode != ReasonClientIPSpoofed {
		reasonCode = ReasonClientIPInvalid
	}
	return context.WithValue(ctx, clientIPContextKey{}, clientIPFact{
		requestID: strings.TrimSpace(requestID), reasonCode: reasonCode,
	})
}

func clientIPFactFromContext(ctx context.Context) (clientIPFact, bool) {
	if ctx == nil {
		return clientIPFact{}, false
	}
	fact, ok := ctx.Value(clientIPContextKey{}).(clientIPFact)
	return fact, ok
}

// ClientIP is the source address the server middleware resolved for the
// request (trusted proxies honoured), or "" when it could not be resolved.
func ClientIP(ctx context.Context) string {
	fact, ok := clientIPFactFromContext(ctx)
	if !ok || fact.reasonCode != "" || !fact.address.IsValid() {
		return ""
	}
	return fact.address.String()
}

func ClientIPRequestID(ctx context.Context) string {
	fact, _ := clientIPFactFromContext(ctx)
	return fact.requestID
}

func EnforceIPAllowlist(ctx context.Context, values []string) (netip.Addr, string) {
	return enforceIPAllowlist(ctx, values)
}

func enforceIPAllowlist(ctx context.Context, values []string) (netip.Addr, string) {
	if len(values) == 0 {
		return netip.Addr{}, ""
	}
	fact, ok := clientIPFactFromContext(ctx)
	if !ok {
		return netip.Addr{}, ReasonClientIPMissing
	}
	if fact.reasonCode != "" {
		return netip.Addr{}, fact.reasonCode
	}
	if !fact.address.IsValid() {
		return netip.Addr{}, ReasonClientIPInvalid
	}
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.String() != raw || prefix.Addr().Is4In6() {
			return fact.address, ReasonIPAllowlistInvalid
		}
		if prefix.Contains(fact.address) {
			return fact.address, ""
		}
	}
	return fact.address, ReasonClientIPNotAllowed
}

type Denial struct {
	ScopeID     uuid.UUID
	ActorUserID uuid.UUID
	KeyID       uuid.UUID
	RequestID   string
	ClientIP    netip.Addr
	IPAllowlist []string
	ReasonCode  string
}

type DenialRecorder interface {
	Record(context.Context, Denial) error
}

type PostgresDenialRecorder struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
}

func NewPostgresDenialRecorder(pool *pgxpool.Pool, now func() time.Time) *PostgresDenialRecorder {
	if pool == nil {
		return nil
	}
	return &PostgresDenialRecorder{pool: pool, auditor: audit.NewWithClock(pool, now)}
}

func (recorder *PostgresDenialRecorder) Record(ctx context.Context, denial Denial) error {
	if recorder == nil || recorder.pool == nil || recorder.auditor == nil || denial.ScopeID == uuid.Nil ||
		denial.ActorUserID == uuid.Nil || denial.KeyID == uuid.Nil || !validIPReason(denial.ReasonCode) {
		return errors.New("invalid API key authentication denial")
	}
	requestID := strings.TrimSpace(denial.RequestID)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	payload := map[string]any{
		"reason_code":  denial.ReasonCode,
		"ip_allowlist": append([]string(nil), denial.IPAllowlist...),
	}
	if denial.ClientIP.IsValid() {
		payload["client_ip"] = denial.ClientIP.Unmap().String()
	}
	actorID := denial.ActorUserID
	return pgx.BeginFunc(ctx, recorder.pool, func(tx pgx.Tx) error {
		return recorder.auditor.Append(ctx, tx, audit.Event{
			ScopeID: denial.ScopeID, ActorUserID: &actorID,
			Action: "api_key.authentication.denied", ResourceType: "api_key",
			ResourceID: denial.KeyID.String(), RequestID: requestID, Result: "denied", Payload: payload,
		})
	})
}

func validIPReason(reason string) bool {
	return reason == ReasonClientIPMissing || reason == ReasonClientIPInvalid ||
		reason == ReasonClientIPSpoofed || reason == ReasonClientIPNotAllowed ||
		reason == ReasonIPAllowlistInvalid
}
