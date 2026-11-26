package accountrecovery

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// scriptedRecoveryQuery answers the resolution queries by their table.
type scriptedRecoveryQuery struct {
	usernameTaken bool
	candidates    []uuid.UUID
	registration  *recoveryTarget
	proved        bool
	login         *loginScopeRow
	queries       []string
}

type scriptedRow struct {
	values []any
	err    error
}

func (row scriptedRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return fmt.Errorf("scan %d values into %d", len(row.values), len(dest))
	}
	for index, value := range row.values {
		switch target := dest[index].(type) {
		case *bool:
			*target = value.(bool)
		case *string:
			*target = value.(string)
		case *uuid.UUID:
			*target = value.(uuid.UUID)
		case **uuid.UUID:
			*target = value.(*uuid.UUID)
		case *[]uuid.UUID:
			*target = value.([]uuid.UUID)
		default:
			return fmt.Errorf("unexpected scan target %T", target)
		}
	}
	return nil
}

func (query *scriptedRecoveryQuery) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	query.queries = append(query.queries, sql)
	switch {
	case strings.Contains(sql, "lower(username)=$1"):
		return scriptedRow{values: []any{query.usernameTaken}}
	case strings.Contains(sql, "FROM users WHERE email=$1"):
		return scriptedRow{values: []any{query.candidates}}
	case strings.Contains(sql, "account_registration_requests_159"):
		if query.registration == nil {
			return scriptedRow{err: pgx.ErrNoRows}
		}
		return scriptedRow{values: []any{"registration-key", query.registration.TenantID, query.registration.ScopeID}}
	case strings.Contains(sql, "account_registration_proofs_162"):
		return scriptedRow{values: []any{query.proved}}
	case strings.Contains(sql, "ORDER BY CASE scope.kind"):
		if query.login == nil {
			return scriptedRow{err: pgx.ErrNoRows}
		}
		return scriptedRow{values: []any{query.login.kind, query.login.tenantID, query.login.scopeID, query.login.tenantActive}}
	}
	return scriptedRow{err: fmt.Errorf("unexpected query %q", sql)}
}

func TestResolveRecoveryTargetEmailIdentifier(t *testing.T) {
	keys := [][]byte{make([]byte, 32)}
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	otherTenant, otherScope, platformScope := uuid.New(), uuid.New(), uuid.New()
	registration := &recoveryTarget{TenantID: tenantID, ScopeID: scopeID}
	tenantHost := RequestInput{TenantID: tenantID, ScopeID: scopeID}
	platformHost := RequestInput{ScopeID: platformScope}
	tenantLogin := &loginScopeRow{kind: "tenant", tenantID: &tenantID, scopeID: scopeID, tenantActive: true}
	verified := func() *scriptedRecoveryQuery {
		return &scriptedRecoveryQuery{candidates: []uuid.UUID{userID}, registration: registration, proved: true, login: tenantLogin}
	}
	cases := []struct {
		name  string
		input RequestInput
		keys  [][]byte
		edit  func(*scriptedRecoveryQuery)
		want  recoveryTarget
	}{
		{"verified on its tenant host", tenantHost, keys, nil,
			recoveryTarget{TenantID: tenantID, ScopeID: scopeID, EmailUserID: userID}},
		{"verified on the platform host", platformHost, keys, nil,
			recoveryTarget{TenantID: tenantID, ScopeID: scopeID, EmailUserID: userID}},
		{"no proof keys: username lookup", tenantHost, nil, nil, recoveryTarget{TenantID: tenantID, ScopeID: scopeID}},
		{"a username spelled like the email wins", tenantHost, keys,
			func(query *scriptedRecoveryQuery) { query.usernameTaken = true }, recoveryTarget{TenantID: tenantID, ScopeID: scopeID}},
		{"unverified email", tenantHost, keys,
			func(query *scriptedRecoveryQuery) { query.proved = false }, recoveryTarget{TenantID: tenantID, ScopeID: scopeID}},
		{"not created by a registration", tenantHost, keys,
			func(query *scriptedRecoveryQuery) { query.registration = nil }, recoveryTarget{TenantID: tenantID, ScopeID: scopeID}},
		{"more than one account", tenantHost, keys,
			func(query *scriptedRecoveryQuery) { query.candidates = []uuid.UUID{userID, uuid.New()} },
			recoveryTarget{TenantID: tenantID, ScopeID: scopeID}},
		{"another tenant's host", RequestInput{TenantID: otherTenant, ScopeID: otherScope}, keys, nil,
			recoveryTarget{TenantID: otherTenant, ScopeID: otherScope}},
		{"platform host where sign-in picks the platform", platformHost, keys,
			func(query *scriptedRecoveryQuery) {
				query.login = &loginScopeRow{kind: "platform", scopeID: platformScope}
			},
			recoveryTarget{ScopeID: platformScope}},
		{"platform host where sign-in picks another tenant", platformHost, keys,
			func(query *scriptedRecoveryQuery) {
				query.login = &loginScopeRow{kind: "tenant", tenantID: &tenantID, scopeID: otherScope, tenantActive: true}
			}, recoveryTarget{ScopeID: platformScope}},
		{"platform host with a suspended tenant", platformHost, keys,
			func(query *scriptedRecoveryQuery) {
				query.login = &loginScopeRow{kind: "tenant", tenantID: &tenantID, scopeID: scopeID}
			}, recoveryTarget{ScopeID: platformScope}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			query := verified()
			if test.edit != nil {
				test.edit(query)
			}
			got, err := resolveRecoveryTarget(t.Context(), query, test.input, "dana@example.test", test.keys)
			if err != nil || got != test.want {
				t.Fatalf("target = %+v (%v), want %+v", got, err, test.want)
			}
		})
	}
}

// A miss runs the same proof queries as a hit (no early return that would
// make an unknown email answer faster).
func TestResolveRecoveryTargetEmailMissRunsTheSameQueries(t *testing.T) {
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	input := RequestInput{TenantID: tenantID, ScopeID: scopeID}
	hit := &scriptedRecoveryQuery{candidates: []uuid.UUID{userID},
		registration: &recoveryTarget{TenantID: tenantID, ScopeID: scopeID}, proved: true}
	miss := &scriptedRecoveryQuery{candidates: []uuid.UUID{}}
	keys := [][]byte{make([]byte, 32)}
	for _, query := range []*scriptedRecoveryQuery{hit, miss} {
		if _, err := resolveRecoveryTarget(t.Context(), query, input, "dana@example.test", keys); err != nil {
			t.Fatal(err)
		}
	}
	if len(hit.queries) != len(miss.queries) {
		t.Fatalf("hit ran %d queries, miss %d", len(hit.queries), len(miss.queries))
	}
}

func TestCloneProofKeysDropsShortKeysAndCopies(t *testing.T) {
	key := make([]byte, 32)
	cloned := cloneProofKeys([][]byte{key, make([]byte, 31), nil})
	key[0] = 1
	if len(cloned) != 1 || cloned[0][0] != 0 {
		t.Fatalf("cloned keys = %v", cloned)
	}
}
