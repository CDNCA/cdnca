package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	accessIssuer   = "cdnca-control-api"
	accessAudience = "cdnca-control"
)

type AccessClaims struct {
	ScopeID   string `json:"scp"`
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewTokenManager(secret string, ttl time.Duration) (*TokenManager, error) {
	if len(secret) < 32 {
		return nil, errors.New("access token secret must contain at least 32 bytes")
	}
	if ttl <= 0 {
		return nil, errors.New("access token TTL must be positive")
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl, now: time.Now}, nil
}

// Configured reports whether NewTokenManager initialized the manager's in-memory dependencies.
// It does not check dependency health.
func (m *TokenManager) Configured() bool {
	return m != nil && len(m.secret) >= 32 && m.ttl > 0 && m.now != nil
}

func (m *TokenManager) Mint(userID, scopeID, sessionID uuid.UUID) (string, time.Time, error) {
	now := m.now().UTC()
	expires := now.Add(m.ttl)
	jti, err := uuid.NewV7()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate access token ID: %w", err)
	}
	claims := AccessClaims{
		ScopeID:   scopeID.String(),
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    accessIssuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{accessAudience},
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expires, nil
}

func (m *TokenManager) Parse(raw string) (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	claims := new(AccessClaims)
	token, err := jwt.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(accessIssuer),
		jwt.WithAudience(accessAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil || !token.Valid {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid access token")
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid access token subject")
	}
	scopeID, err := uuid.Parse(claims.ScopeID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid access token scope")
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, errors.New("invalid access token session")
	}
	return userID, scopeID, sessionID, nil
}
