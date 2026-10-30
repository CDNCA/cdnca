package acmeruntime

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AccountStore struct {
	pool          *pgxpool.Pool
	termsAccepted bool
}

var accountContactPattern = regexp.MustCompile(`^mailto:[^[:space:][:cntrl:]]+@[^[:space:][:cntrl:]]+$`)

func NewAccountStore(pool *pgxpool.Pool, termsAccepted bool) (*AccountStore, error) {
	if pool == nil || !termsAccepted {
		return nil, ErrInvalidInput
	}
	return &AccountStore{pool: pool, termsAccepted: true}, nil
}

func (s *AccountStore) LoadAccount(
	ctx context.Context,
	directoryURL, keyRef string,
) (acmeworker.AccountRegistration, bool, error) {
	if s == nil || s.pool == nil {
		return acmeworker.AccountRegistration{}, false, ErrInvalidInput
	}
	tenantID, purpose, _, err := parseKeyRef(keyRef)
	if err != nil || purpose != purposeAccount || !accountRefMatches(tenantID, directoryURL, keyRef) {
		return acmeworker.AccountRegistration{}, false, ErrInvalidInput
	}
	var account acmeworker.AccountRegistration
	err = s.pool.QueryRow(ctx, `SELECT registration.account_uri,registration.contacts
		FROM acme_account_registration_facts registration
		JOIN acme_tenant_key_facts key ON key.tenant_scope_id=registration.tenant_scope_id
		 AND key.id=registration.account_key_id AND key.purpose='account'
		 AND key.created_by_user_id=registration.created_by_user_id
		JOIN access_scopes scope ON scope.id=registration.tenant_scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN users actor ON actor.id=registration.created_by_user_id
		 AND acme_runtime_actor_is_active_048(registration.tenant_scope_id,registration.created_by_user_id)
		WHERE registration.tenant_scope_id=$1 AND registration.directory_url=$2
		 AND key.key_ref=$3`, tenantID, directoryURL, keyRef).Scan(&account.URI, &account.Contact)
	if errors.Is(err, pgx.ErrNoRows) {
		return acmeworker.AccountRegistration{}, false, nil
	}
	if err != nil {
		return acmeworker.AccountRegistration{}, false, err
	}
	return account, true, nil
}

func (s *AccountStore) SaveAccount(
	ctx context.Context,
	directoryURL, keyRef string,
	account acmeworker.AccountRegistration,
) error {
	if s == nil || s.pool == nil || !s.termsAccepted {
		return ErrInvalidInput
	}
	tenantID, purpose, _, err := parseKeyRef(keyRef)
	if err != nil || purpose != purposeAccount || !accountRefMatches(tenantID, directoryURL, keyRef) ||
		!validHTTPSURL(account.URI) || !validContacts(account.Contact) {
		return ErrInvalidInput
	}
	// 048 stores contacts NOT NULL: no contact is the empty array, not NULL.
	contacts := append([]string{}, account.Contact...)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			tenantID.String()+"/"+directoryURL+"/"+keyRef); err != nil {
			return err
		}
		var keyID, actorID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT key.id,key.created_by_user_id
			FROM acme_tenant_key_facts key
			JOIN users actor ON actor.id=key.created_by_user_id
			 AND acme_runtime_actor_is_active_048(key.tenant_scope_id,key.created_by_user_id)
			WHERE key.tenant_scope_id=$1 AND key.key_ref=$2 AND key.purpose='account'`,
			tenantID, keyRef).Scan(&keyID, &actorID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		var storedURI string
		var storedContacts []string
		var storedActorID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT account_uri,contacts,created_by_user_id
			FROM acme_account_registration_facts
			WHERE tenant_scope_id=$1 AND directory_url=$2 AND account_key_id=$3`,
			tenantID, directoryURL, keyID).Scan(&storedURI, &storedContacts, &storedActorID)
		if err == nil {
			if storedActorID == actorID && storedURI == account.URI && slices.Equal(storedContacts, contacts) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO acme_account_registration_facts(
			tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
			terms_agreed_at,registered_at,created_by_user_id
		) VALUES($1,$2,$3,$4,$5,$6,statement_timestamp(),statement_timestamp(),$7)`,
			tenantID, uuid.New(), keyID, directoryURL, account.URI, contacts, actorID)
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	})
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func accountRefMatches(tenantID uuid.UUID, directoryURL, keyRef string) bool {
	expected, err := AccountKeyRef(tenantID, directoryURL)
	return err == nil && expected == keyRef
}

func validHTTPSURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 4096 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}

func validContacts(contacts []string) bool {
	if len(contacts) > 20 {
		return false
	}
	seen := make(map[string]struct{}, len(contacts))
	for _, contact := range contacts {
		if contact == "" || contact != strings.TrimSpace(contact) || len(contact) > 512 ||
			!accountContactPattern.MatchString(contact) {
			return false
		}
		if _, exists := seen[contact]; exists {
			return false
		}
		seen[contact] = struct{}{}
	}
	return true
}
