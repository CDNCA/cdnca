package errorpagecontrol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	SlotBlacklist          = "blacklist"
	SlotHTTP400            = "http_400"
	SlotHTTP403            = "http_403"
	SlotWAFBlock           = "waf_block"
	SlotHTTP502            = "http_502"
	SlotHTTP504            = "http_504"
	SlotTrafficExceeded    = "traffic_exceeded"
	SlotPackageExpired     = "package_expired"
	SlotSiteLocked         = "site_locked"
	SlotDomainUnconfigured = "domain_unconfigured"
	SlotNodeIPAccess       = "node_ip_access"
	SlotConnectionLimit    = "connection_limit"

	operationSlotBind   = "error_page.slot.bind"
	operationSlotUnbind = "error_page.slot.unbind"
)

var ErrorPageSlotKeys = [...]string{
	SlotBlacklist,
	SlotHTTP400,
	SlotHTTP403,
	SlotWAFBlock,
	SlotHTTP502,
	SlotHTTP504,
	SlotTrafficExceeded,
	SlotPackageExpired,
	SlotSiteLocked,
	SlotDomainUnconfigured,
	SlotNodeIPAccess,
	SlotConnectionLimit,
}

type SlotBinding struct {
	Key       string     `json:"key"`
	AssetID   *uuid.UUID `json:"asset_id,omitempty"`
	Revision  int64      `json:"revision"`
	MIMEType  string     `json:"mime_type,omitempty"`
	SizeBytes int64      `json:"size_bytes,omitempty"`
	SHA256    string     `json:"sha256,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Publication: set on a bind/unbind response that changed a slot a node
	// page reads (errpage-content).
	Publication *SlotPublication `json:"publication,omitempty"`
}

// SlotPublication is the publication a slot change made: the error page
// publication revision pinning it and how many tenant scopes were queued for
// node republication (errpage-content).
type SlotPublication struct {
	Revision     int64 `json:"revision"`
	QueuedScopes int   `json:"queued_scopes"`
}

type SlotPage struct {
	Items []SlotBinding `json:"items"`
}

type SlotDocument struct {
	Binding SlotBinding `json:"binding"`
	Content string      `json:"content"`
	// Source: "override" (the bound asset) or "builtin" (the page in effect
	// while unbound, errpage-content).
	Source string `json:"source"`
	// Delivery: what a node answers for the slot while it is unbound
	// (SlotDelivery*); "none" also says a bound slot is only stored.
	Delivery string `json:"delivery"`
}

type BindSlotRequest struct {
	Key              string
	AssetID          uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type UnbindSlotRequest struct {
	Key              string
	ExpectedRevision int64
	WriteMetadata
}

type slotRecord struct {
	ID      uuid.UUID
	Binding SlotBinding
	Asset   *Asset
}

func validSlotKey(value string) bool {
	for _, key := range ErrorPageSlotKeys {
		if value == key {
			return true
		}
	}
	return false
}

func (s *Service) ListSlots(ctx context.Context, actor Actor) (SlotPage, error) {
	if validateActor(actor) != nil {
		return SlotPage{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return SlotPage{}, ErrPermissionDenied
	}
	records := make(map[string]SlotBinding, len(ErrorPageSlotKeys))
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, slotRecordsQuery+` WHERE identity.scope_id=$1`, actor.ScopeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanSlotRecord(rows)
			if err != nil {
				return err
			}
			if !validSlotKey(record.Binding.Key) {
				return ErrConflict
			}
			records[record.Binding.Key] = record.Binding
		}
		return rows.Err()
	})
	if err != nil {
		return SlotPage{}, fmt.Errorf("list error page slots: %w", normalizeDatabaseError(err))
	}
	page := SlotPage{Items: make([]SlotBinding, 0, len(ErrorPageSlotKeys))}
	for _, key := range ErrorPageSlotKeys {
		binding, found := records[key]
		if !found {
			binding = SlotBinding{Key: key}
		}
		page.Items = append(page.Items, binding)
	}
	return page, nil
}

func (s *Service) GetSlot(ctx context.Context, actor Actor, key string) (SlotDocument, error) {
	if validateActor(actor) != nil || !validSlotKey(key) {
		return SlotDocument{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return SlotDocument{}, ErrPermissionDenied
	}
	record := slotRecord{Binding: SlotBinding{Key: key}}
	var builtin []byte
	var delivery string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		var err error
		if builtin, delivery, err = builtinSlotContent(ctx, tx, key); err != nil {
			return err
		}
		loaded, found, err := loadSlotRecord(ctx, tx, actor.ScopeID, key, false)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		record = loaded
		if record.Binding.AssetID == nil {
			return nil
		}
		asset, err := loadAssetForActor(ctx, tx, actor, *record.Binding.AssetID, false)
		if err != nil {
			return err
		}
		if asset.ScopeID != actor.ScopeID || asset.Status != StatusReady || asset.objectState != "final" {
			return ErrConflict
		}
		record.Asset = &asset
		return nil
	})
	if err != nil {
		return SlotDocument{}, fmt.Errorf("get error page slot: %w", normalizeDatabaseError(err))
	}
	if !SlotReachesNodes(key) {
		delivery = SlotDeliveryNone
	}
	result := SlotDocument{Binding: record.Binding, Content: string(builtin), Source: "builtin", Delivery: delivery}
	if record.Asset == nil {
		return result, nil
	}
	result.Source = "override"
	body, err := s.readReadySlotContent(ctx, *record.Asset)
	if err != nil {
		return SlotDocument{}, err
	}
	result.Content = string(body)
	return result, nil
}

func (s *Service) BindSlot(ctx context.Context, actor Actor, request BindSlotRequest) (WriteResult[SlotBinding], error) {
	if request.AssetID == uuid.Nil {
		return WriteResult[SlotBinding]{}, ErrInvalidInput
	}
	assetID := request.AssetID
	return s.changeSlot(ctx, actor, request.Key, &assetID, request.ExpectedRevision,
		request.WriteMetadata, operationSlotBind)
}

func (s *Service) UnbindSlot(ctx context.Context, actor Actor, request UnbindSlotRequest) (WriteResult[SlotBinding], error) {
	return s.changeSlot(ctx, actor, request.Key, nil, request.ExpectedRevision,
		request.WriteMetadata, operationSlotUnbind)
}

func (s *Service) changeSlot(
	ctx context.Context,
	actor Actor,
	key string,
	assetID *uuid.UUID,
	expectedRevision int64,
	metadata WriteMetadata,
	operation string,
) (WriteResult[SlotBinding], error) {
	if validateActor(actor) != nil || !validSlotKey(key) ||
		expectedRevision < 0 || validateWriteMetadata(metadata) != nil ||
		(operation != operationSlotBind && operation != operationSlotUnbind) {
		return WriteResult[SlotBinding]{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult[SlotBinding]{}, ErrPermissionDenied
	}
	digest, err := digestRequest(struct {
		Key              string     `json:"key"`
		AssetID          *uuid.UUID `json:"asset_id"`
		ExpectedRevision int64      `json:"expected_revision"`
	}{Key: key, AssetID: assetID, ExpectedRevision: expectedRevision})
	if err != nil {
		return WriteResult[SlotBinding]{}, ErrInvalidInput
	}
	var result SlotBinding
	var replayed bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, actor.ScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[SlotBinding](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}

		record, found, err := loadSlotRecord(ctx, tx, actor.ScopeID, key, true)
		if err != nil {
			return err
		}
		if !found {
			if expectedRevision != 0 {
				return ErrRevisionConflict
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			now := storeTime(s.now())
			if _, err := tx.Exec(ctx, `INSERT INTO error_page_slots (
				id,scope_id,slot_key,created_by_user_id,created_by_scope_id,created_at
			) VALUES($1,$2,$3,$4,$5,$6)`, id, actor.ScopeID, key, actor.UserID, actor.ScopeID, now); err != nil {
				if sqlState(err) == "23505" {
					return ErrRevisionConflict
				}
				return err
			}
			record = slotRecord{ID: id, Binding: SlotBinding{Key: key}}
		}
		if record.Binding.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if assetID != nil {
			asset, err := loadAssetForActor(ctx, tx, actor, *assetID, false)
			if err != nil {
				return err
			}
			if asset.ScopeID != actor.ScopeID || asset.Status != StatusReady || asset.objectState != "final" ||
				asset.DeletedAt != nil {
				return ErrConflict
			}
		}
		unchanged := sameOptionalUUID(record.Binding.AssetID, assetID) && record.Binding.Revision > 0
		if !unchanged {
			now := storeTime(s.now())
			if _, err := tx.Exec(ctx, `INSERT INTO error_page_slot_revisions (
				slot_id,revision,asset_id,created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.ID, expectedRevision+1, assetID,
				actor.UserID, actor.ScopeID, metadata.RequestID, metadata.TraceID, now); err != nil {
				return err
			}
		}
		record, found, err = loadSlotRecord(ctx, tx, actor.ScopeID, key, false)
		if err != nil || !found {
			if err == nil {
				err = ErrConflict
			}
			return err
		}
		result = record.Binding
		// A slot a node page reads goes out with a new publication revision
		// (it pins the slots) and the system republication of every tenant
		// scope on the platform theme; queued before the publication lock.
		if SlotReachesNodes(key) && !unchanged {
			if result.Publication, err = s.publishSlotsTx(ctx, tx, actor, metadata); err != nil {
				return err
			}
		}
		if err := s.appendAudit(ctx, tx, &actor, actor.ScopeID, operation, "error_page_slot",
			record.ID.String(), metadata, "success", map[string]any{
				"slot_key": key, "from_revision": expectedRevision, "to_revision": result.Revision,
				"asset_id": assetID, "unchanged": unchanged, "publication": result.Publication,
			}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operation, metadata, record.ID, 200, result)
	})
	if err != nil {
		return WriteResult[SlotBinding]{}, fmt.Errorf("%s: %w", operation, normalizeDatabaseError(err))
	}
	return WriteResult[SlotBinding]{Value: result, Replayed: replayed}, nil
}

// publishSlotsTx appends the error page publication revision that pins the
// platform's slots (and their region / node overrides) and queues the system
// republication of every tenant scope; queued before the publication lock.
func (s *Service) publishSlotsTx(ctx context.Context, tx pgx.Tx, actor Actor, metadata WriteMetadata) (*SlotPublication, error) {
	publication := &SlotPublication{}
	if s.slotRepublisher != nil {
		var err error
		if publication.QueuedScopes, err = s.slotRepublisher.QueueSlotRepublicationTx(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := lockPublication(ctx, tx); err != nil {
		return nil, err
	}
	snapshot, err := insertPublication(ctx, tx, actor.UserID, actor.ScopeID, metadata, uuid.Nil, nil, storeTime(s.now()))
	if err != nil {
		return nil, err
	}
	publication.Revision = snapshot.Policy.Revision
	return publication, nil
}

func (s *Service) authorizeSlotActor(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	if err := s.authorizeActor(ctx, tx, actor, actor.ScopeID, permission); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).
		Scan(&kind, &tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	return nil
}

func loadSlotRecord(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	key string,
	lock bool,
) (slotRecord, bool, error) {
	query := slotRecordsQuery + ` WHERE identity.scope_id=$1 AND identity.slot_key=$2`
	if lock {
		query += ` FOR UPDATE OF identity`
	}
	record, err := scanSlotRecord(tx.QueryRow(ctx, query, scopeID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return slotRecord{}, false, nil
	}
	return record, err == nil, err
}

const slotRecordsQuery = `SELECT identity.id,identity.slot_key,current.revision,current.asset_id,
	asset.mime_type,asset.size_bytes,asset.sha256,current.created_at
	FROM error_page_slots identity
	JOIN LATERAL (
		SELECT revision.revision,revision.asset_id,revision.created_at
		FROM error_page_slot_revisions revision
		WHERE revision.slot_id=identity.id ORDER BY revision.revision DESC LIMIT 1
	) current ON true
	LEFT JOIN error_page_assets asset ON asset.id=current.asset_id`

func scanSlotRecord(row rowScanner) (slotRecord, error) {
	var record slotRecord
	var digest []byte
	var mimeType *string
	var sizeBytes *int64
	var updatedAt time.Time
	err := row.Scan(&record.ID, &record.Binding.Key, &record.Binding.Revision, &record.Binding.AssetID,
		&mimeType, &sizeBytes, &digest, &updatedAt)
	if err != nil {
		return slotRecord{}, err
	}
	record.Binding.UpdatedAt = &updatedAt
	if record.Binding.AssetID == nil {
		if mimeType != nil || sizeBytes != nil || len(digest) != 0 {
			return slotRecord{}, ErrConflict
		}
		return record, nil
	}
	if mimeType == nil || sizeBytes == nil || *sizeBytes < 1 || len(digest) != 32 {
		return slotRecord{}, ErrConflict
	}
	record.Binding.MIMEType = *mimeType
	record.Binding.SizeBytes = *sizeBytes
	record.Binding.SHA256 = hex.EncodeToString(digest)
	return record, nil
}

func (s *Service) readReadySlotContent(ctx context.Context, asset Asset) ([]byte, error) {
	if asset.Status != StatusReady || asset.objectState != "final" || asset.DeletedAt != nil ||
		asset.SizeBytes < 1 || asset.SizeBytes > MaxEdgeResourceBytes ||
		asset.storageObjectKey != "error-pages/objects/"+asset.ScopeID.String()+"/"+asset.SHA256 {
		return nil, fmt.Errorf("error page slot asset metadata: %w", ErrConflict)
	}
	ref := assetObjectRef(asset, asset.storageObjectKey)
	info, err := s.content.Stat(ctx, ref)
	if err != nil {
		return nil, wrapUnavailable("stat error page slot asset", err)
	}
	if validateObjectInfo(asset, info) != nil {
		return nil, fmt.Errorf("error page slot asset object metadata: %w", ErrConflict)
	}
	reader, err := s.content.Open(ctx, ref, info.ImmutableToken)
	if err != nil {
		return nil, wrapUnavailable("open error page slot asset", err)
	}
	defer reader.Close()
	body, err := readBounded(reader, asset.SizeBytes)
	if err != nil || int64(len(body)) != asset.SizeBytes || digestBytes(body) != asset.SHA256 {
		return nil, fmt.Errorf("error page slot asset body integrity: %w", ErrConflict)
	}
	if err := validateStaticBody(asset.MIMEType, body); err != nil {
		return nil, err
	}
	return body, nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
