package regioncatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	createOperation = "region_catalog.create"
	updateOperation = "region_catalog.update"
	deleteOperation = "region_catalog.delete"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type transactionBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

type Store struct {
	database queryer
}

func NewStore(database queryer) *Store {
	return &Store{database: database}
}

func (store *Store) List(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	if err := authorize(actor, false); err != nil {
		return Page{}, err
	}
	search := strings.TrimSpace(request.Search)
	if ctx == nil || request.Limit < 0 || request.Limit > 300 || utf8.RuneCountInString(search) > 128 ||
		strings.IndexFunc(search, unicode.IsControl) >= 0 || request.Paginated &&
		(request.Page < 1 || request.PageSize < 1 || request.PageSize > 300) || !request.Paginated &&
		(request.Page != 0 || request.PageSize != 0) {
		return Page{}, ErrInvalidInput
	}
	if store == nil || store.database == nil {
		return Page{}, ErrUnavailable
	}
	limit, offset := request.Limit, 0
	if request.Paginated {
		limit, offset = request.PageSize, (request.Page-1)*request.PageSize
	}
	escapedSearch := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search)
	rows, err := store.database.Query(ctx, `SELECT display_id::text,name,code,country_code,province_code,description,l2_check_port,
		sort_order,revision,created_at,updated_at,count(*) OVER()
		FROM region_catalog
		WHERE platform_scope_id=$1 AND ($2='' OR name ILIKE '%'||$2||'%' ESCAPE '\' OR
			description ILIKE '%'||$2||'%' ESCAPE '\')
		ORDER BY sort_order,region_catalog.display_id
		LIMIT NULLIF($3,0) OFFSET $4`, actor.ScopeID, escapedSearch, limit, offset)
	if err != nil {
		return Page{}, databaseError(ctx, err)
	}
	defer rows.Close()
	result := Page{Data: []Region{}}
	for rows.Next() {
		var item Region
		if err := rows.Scan(&item.ID, &item.Name, &item.Code, &item.CountryCode, &item.ProvinceCode, &item.Description, &item.L2CheckPort, &item.Sort,
			&item.Revision, &item.CreatedAt, &item.UpdatedAt, &result.Count); err != nil {
			return Page{}, ErrUnavailable
		}
		result.Data = append(result.Data, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, databaseError(ctx, err)
	}
	return result, nil
}

func (store *Store) Get(ctx context.Context, actor Actor, id string) (Region, error) {
	if err := authorize(actor, false); err != nil {
		return Region{}, err
	}
	displayID, ok := parseDisplayID(id)
	if ctx == nil || !ok {
		return Region{}, ErrInvalidInput
	}
	if store == nil || store.database == nil {
		return Region{}, ErrUnavailable
	}
	rows, err := store.database.Query(ctx, `SELECT display_id::text,name,code,country_code,province_code,description,l2_check_port,
		sort_order,revision,created_at,updated_at
		FROM region_catalog WHERE platform_scope_id=$1 AND display_id=$2`, actor.ScopeID, displayID)
	if err != nil {
		return Region{}, databaseError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Region{}, databaseError(ctx, err)
		}
		return Region{}, ErrNotFound
	}
	var result Region
	if err := rows.Scan(&result.ID, &result.Name, &result.Code, &result.CountryCode, &result.ProvinceCode, &result.Description, &result.L2CheckPort,
		&result.Sort, &result.Revision, &result.CreatedAt, &result.UpdatedAt); err != nil {
		return Region{}, ErrUnavailable
	}
	if rows.Next() {
		return Region{}, ErrUnavailable
	}
	return result, nil
}

func (store *Store) Create(ctx context.Context, actor Actor, request CreateRequest) (Region, bool, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	if err := authorize(actor, true); err != nil {
		return Region{}, false, err
	}
	if ctx == nil || !validRegionInput(request.Name, request.Description, request.L2CheckPort, request.Sort) ||
		!ValidGeo(request.CountryCode, request.ProvinceCode) ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Region{}, false, ErrInvalidInput
	}
	digest := requestDigest(struct {
		ScopeID     uuid.UUID `json:"scope_id"`
		Name        string    `json:"name"`
		Country     string    `json:"country_code"`
		Province    string    `json:"province_code"`
		Description string    `json:"description"`
		Port        int       `json:"l2_check_port"`
		Sort        int       `json:"sort"`
	}{actor.ScopeID, request.Name, request.CountryCode, request.ProvinceCode, request.Description, request.L2CheckPort, request.Sort})
	var result Region
	replayed, err := store.write(ctx, actor, createOperation, request.IdempotencyKey, digest, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO region_catalog(
			id,platform_scope_id,name,description,l2_check_port,sort_order,country_code,province_code,
			revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,clock_timestamp(),clock_timestamp())
			RETURNING display_id::text,name,code,country_code,province_code,description,l2_check_port,sort_order,revision,created_at,updated_at`,
			uuid.New(), actor.ScopeID, request.Name, request.Description, request.L2CheckPort, request.Sort,
			request.CountryCode, request.ProvinceCode).Scan(
			&result.ID, &result.Name, &result.Code, &result.CountryCode, &result.ProvinceCode, &result.Description, &result.L2CheckPort, &result.Sort,
			&result.Revision, &result.CreatedAt, &result.UpdatedAt); err != nil {
			return mapDatabaseError(err)
		}
		return appendAudit(ctx, tx, actor, request.RequestID, createOperation, result, nil)
	}, &result, 201)
	return result, replayed, err
}

func (store *Store) Update(ctx context.Context, actor Actor, request UpdateRequest) (Region, bool, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	displayID, validID := parseDisplayID(request.ID)
	if err := authorize(actor, true); err != nil {
		return Region{}, false, err
	}
	if ctx == nil || !validID || request.ExpectedRevision < 1 ||
		!validRegionInput(request.Name, request.Description, request.L2CheckPort, request.Sort) ||
		!ValidGeo(request.CountryCode, request.ProvinceCode) ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Region{}, false, ErrInvalidInput
	}
	digest := requestDigest(struct {
		ScopeID  uuid.UUID `json:"scope_id"`
		ID       int64     `json:"id"`
		Version  int64     `json:"version"`
		Name     string    `json:"name"`
		Country  string    `json:"country_code"`
		Province string    `json:"province_code"`
		Notes    string    `json:"description"`
		Port     int       `json:"l2_check_port"`
		Sort     int       `json:"sort"`
	}{actor.ScopeID, displayID, request.ExpectedRevision, request.Name, request.CountryCode, request.ProvinceCode,
		request.Description, request.L2CheckPort, request.Sort})
	var result Region
	replayed, err := store.write(ctx, actor, updateOperation, request.IdempotencyKey, digest, func(tx pgx.Tx) error {
		current, err := lockRegion(ctx, tx, actor.ScopeID, displayID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if err := tx.QueryRow(ctx, `UPDATE region_catalog SET name=$3,description=$4,l2_check_port=$5,
			sort_order=$6,country_code=$7,province_code=$8,revision=revision+1,updated_at=clock_timestamp()
			WHERE platform_scope_id=$1 AND display_id=$2
			RETURNING display_id::text,name,code,country_code,province_code,description,l2_check_port,sort_order,revision,created_at,updated_at`,
			actor.ScopeID, displayID, request.Name, request.Description, request.L2CheckPort, request.Sort,
			request.CountryCode, request.ProvinceCode).Scan(
			&result.ID, &result.Name, &result.Code, &result.CountryCode, &result.ProvinceCode, &result.Description, &result.L2CheckPort, &result.Sort,
			&result.Revision, &result.CreatedAt, &result.UpdatedAt); err != nil {
			return mapDatabaseError(err)
		}
		return appendAudit(ctx, tx, actor, request.RequestID, updateOperation, result, &current)
	}, &result, 200)
	return result, replayed, err
}

func (store *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest) (bool, error) {
	displayID, validID := parseDisplayID(request.ID)
	if err := authorize(actor, true); err != nil {
		return false, err
	}
	if ctx == nil || !validID || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return false, ErrInvalidInput
	}
	digest := requestDigest(struct {
		ScopeID uuid.UUID `json:"scope_id"`
		ID      int64     `json:"id"`
		Version int64     `json:"version"`
	}{actor.ScopeID, displayID, request.ExpectedRevision})
	response := struct {
		Deleted bool `json:"deleted"`
	}{Deleted: true}
	replayed, err := store.write(ctx, actor, deleteOperation, request.IdempotencyKey, digest, func(tx pgx.Tx) error {
		current, err := lockRegion(ctx, tx, actor.ScopeID, displayID)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM region_catalog WHERE platform_scope_id=$1 AND display_id=$2`,
			actor.ScopeID, displayID); err != nil {
			return mapDatabaseError(err)
		}
		return appendAudit(ctx, tx, actor, request.RequestID, deleteOperation, current, &current)
	}, &response, 204)
	return replayed, err
}

func (store *Store) write(
	ctx context.Context,
	actor Actor,
	operation, key string,
	digest [32]byte,
	apply func(pgx.Tx) error,
	response any,
	status int,
) (bool, error) {
	if store == nil || store.database == nil {
		return false, ErrUnavailable
	}
	beginner, ok := store.database.(transactionBeginner)
	if !ok {
		return false, ErrUnavailable
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return false, databaseError(ctx, err)
	}
	defer tx.Rollback(context.Background())

	body, replayed, err := claimWrite(ctx, tx, actor, operation, key, digest)
	if err != nil {
		return false, err
	}
	if replayed {
		if err := json.Unmarshal(body, response); err != nil {
			return false, ErrUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return false, databaseError(ctx, err)
		}
		return true, nil
	}
	if err := apply(tx); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return false, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE region_catalog_write_requests
		SET response_status=$4,response_body=$5,completed_at=clock_timestamp()
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		actor.UserID, operation, key, status, encoded); err != nil {
		return false, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return false, databaseError(ctx, err)
	}
	return false, nil
}

func claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	digest [32]byte,
) ([]byte, bool, error) {
	var existingDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body
		FROM region_catalog_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
		actor.UserID, operation, key).Scan(&existingDigest, &body)
	if err == nil {
		if !bytes.Equal(existingDigest, digest[:]) {
			return nil, false, ErrIdempotencyConflict
		}
		if len(body) == 0 {
			return nil, false, ErrUnavailable
		}
		return body, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrUnavailable
	}
	command, err := tx.Exec(ctx, `INSERT INTO region_catalog_write_requests(
		id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,clock_timestamp())
		ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`,
		uuid.New(), actor.UserID, actor.ScopeID, operation, key, digest[:])
	if err != nil {
		return nil, false, ErrUnavailable
	}
	if command.RowsAffected() == 1 {
		return nil, false, nil
	}
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body
		FROM region_catalog_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
		actor.UserID, operation, key).Scan(&existingDigest, &body); err != nil {
		return nil, false, ErrUnavailable
	}
	if !bytes.Equal(existingDigest, digest[:]) {
		return nil, false, ErrIdempotencyConflict
	}
	if len(body) == 0 {
		return nil, false, ErrUnavailable
	}
	return body, true, nil
}

func lockRegion(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, displayID int64) (Region, error) {
	var result Region
	err := tx.QueryRow(ctx, `SELECT display_id::text,name,code,country_code,province_code,description,l2_check_port,sort_order,
		revision,created_at,updated_at FROM region_catalog
		WHERE platform_scope_id=$1 AND display_id=$2 FOR UPDATE`, scopeID, displayID).Scan(
		&result.ID, &result.Name, &result.Code, &result.CountryCode, &result.ProvinceCode, &result.Description, &result.L2CheckPort, &result.Sort,
		&result.Revision, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Region{}, ErrNotFound
	}
	if err != nil {
		return Region{}, ErrUnavailable
	}
	return result, nil
}

func appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	requestID, operation string,
	current Region,
	previous *Region,
) error {
	payload := map[string]any{
		"display_id":    current.ID,
		"name":          current.Name,
		"country_code":  current.CountryCode,
		"province_code": current.ProvinceCode,
		"revision":      current.Revision,
	}
	if previous != nil {
		payload["previous_name"] = previous.Name
		payload["previous_country_code"] = previous.CountryCode
		payload["previous_province_code"] = previous.ProvinceCode
		payload["previous_revision"] = previous.Revision
	}
	if err := audit.New(nil).Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "region_catalog", ResourceID: current.ID,
		RequestID: requestID, Result: "success", Payload: payload,
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func authorize(actor Actor, manage bool) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return ErrUnauthenticated
	}
	permission := PermissionRead
	if manage {
		permission = PermissionManage
	}
	if actor.ScopeKind != "platform" ||
		!slices.Contains(actor.Permissions, permission) && !slices.Contains(actor.Permissions, "platform.admin") {
		return ErrPermissionDenied
	}
	return nil
}

func validRegionInput(name, description string, port, sort int) bool {
	return utf8.RuneCountInString(name) >= 1 && utf8.RuneCountInString(name) <= 128 &&
		strings.IndexFunc(name, unicode.IsControl) < 0 && utf8.RuneCountInString(description) <= 1024 &&
		strings.IndexFunc(description, unicode.IsControl) < 0 && port >= 1 && port <= 65535 &&
		sort >= 0 && sort <= 999999
}

func validMetadata(value string) bool {
	return metadataPattern.MatchString(value)
}

func parseDisplayID(value string) (int64, bool) {
	if value == "" || value[0] == '0' || len(value) > 19 {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil && parsed > 0 && strconv.FormatInt(parsed, 10) == value
}

func requestDigest(value any) [32]byte {
	payload, _ := json.Marshal(value)
	return sha256.Sum256(payload)
}

func mapDatabaseError(err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch {
		case databaseError.Code == "23505" && databaseError.ConstraintName == "region_catalog_scope_name_unique":
			return ErrNameConflict
		case databaseError.Code == "P2351":
			return ErrRevisionConflict
		case databaseError.Code == "P2352":
			return ErrInUse
		}
	}
	return ErrUnavailable
}

func databaseError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return mapDatabaseError(err)
}
