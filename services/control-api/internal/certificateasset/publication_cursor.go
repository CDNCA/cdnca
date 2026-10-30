package certificateasset

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	publicationCursorVersion       = 1
	publicationCursorAudience      = "certificate-publication-status-list"
	publicationCursorSort          = "occurred_at_desc,site_id_asc,binding_revision_desc"
	publicationCursorMACDomain     = "cdnca.certificate-publication-status.cursor.v1\x00"
	minPublicationCursorKeyBytes   = 32
	maxPublicationCursorKeyBytes   = 64
	maxPublicationCursorKeyringLen = 2
	maxPublicationCursorKIDBytes   = 64
	maxPublicationCursorTokenBytes = 4096
)

var (
	ErrInvalidPublicationCursor       = errors.New("invalid certificate publication cursor")
	ErrInvalidPublicationCursorConfig = errors.New("invalid certificate publication cursor configuration")
)

type PublicationCursorKeyring struct {
	ActiveKID string
	Keys      map[string][]byte
}

type PublicationCursorCodec struct {
	activeKID string
	keys      map[string][]byte
}

type publicationCursorPayload struct {
	Version             int       `json:"v"`
	KID                 string    `json:"kid"`
	Audience            string    `json:"audience"`
	Sort                string    `json:"sort"`
	ActorScopeKind      string    `json:"actor_scope_kind"`
	ActorScopeID        uuid.UUID `json:"actor_scope_id"`
	ActorUserID         uuid.UUID `json:"actor_user_id"`
	TenantScopeID       uuid.UUID `json:"tenant_scope_id"`
	FilterState         string    `json:"filter_state"`
	FilterOperation     string    `json:"filter_operation"`
	FilterSiteID        uuid.UUID `json:"filter_site_id"`
	SnapshotAt          string    `json:"snapshot_at"`
	LastOccurredAt      string    `json:"last_occurred_at"`
	LastSiteID          uuid.UUID `json:"last_site_id"`
	LastBindingRevision int64     `json:"last_binding_revision"`
}

func NewPublicationCursorCodec(keyring PublicationCursorKeyring) (*PublicationCursorCodec, error) {
	if !validPublicationCursorKID(keyring.ActiveKID) || len(keyring.Keys) < 1 ||
		len(keyring.Keys) > maxPublicationCursorKeyringLen {
		return nil, ErrInvalidPublicationCursorConfig
	}
	keys := make(map[string][]byte, len(keyring.Keys))
	for kid, key := range keyring.Keys {
		if !validPublicationCursorKID(kid) || len(key) < minPublicationCursorKeyBytes ||
			len(key) > maxPublicationCursorKeyBytes {
			return nil, ErrInvalidPublicationCursorConfig
		}
		keys[kid] = bytes.Clone(key)
	}
	if _, ok := keys[keyring.ActiveKID]; !ok {
		return nil, ErrInvalidPublicationCursorConfig
	}
	return &PublicationCursorCodec{activeKID: keyring.ActiveKID, keys: keys}, nil
}

func (codec *PublicationCursorCodec) Encode(
	actor Actor,
	tenantScopeID uuid.UUID,
	filter PublicationStatusFilter,
	cursor PublicationStatusCursor,
) (string, error) {
	if codec == nil || !validPublicationCursorBinding(actor, tenantScopeID, filter) ||
		!validPublicationStatusCursor(cursor) {
		return "", ErrInvalidPublicationCursor
	}
	snapshotAt, ok := formatPublicationCursorTime(cursor.SnapshotAt)
	if !ok {
		return "", ErrInvalidPublicationCursor
	}
	lastOccurredAt, ok := formatPublicationCursorTime(cursor.LastOccurredAt)
	if !ok {
		return "", ErrInvalidPublicationCursor
	}
	payload, err := json.Marshal(publicationCursorPayload{
		Version: publicationCursorVersion, KID: codec.activeKID,
		Audience: publicationCursorAudience, Sort: publicationCursorSort,
		ActorScopeKind: actor.ScopeKind, ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID,
		TenantScopeID: tenantScopeID, FilterState: filter.State,
		FilterOperation: filter.Operation, FilterSiteID: filter.SiteID,
		SnapshotAt: snapshotAt, LastOccurredAt: lastOccurredAt,
		LastSiteID: cursor.LastSiteID, LastBindingRevision: cursor.LastBindingRevision,
	})
	if err != nil {
		return "", ErrInvalidPublicationCursor
	}
	packet := append(append([]byte(nil), payload...), publicationCursorMAC(codec.keys[codec.activeKID], payload)...)
	encoded := base64.RawURLEncoding.EncodeToString(packet)
	if len(encoded) > maxPublicationCursorTokenBytes {
		return "", ErrInvalidPublicationCursor
	}
	return encoded, nil
}

func (codec *PublicationCursorCodec) Decode(
	encoded string,
	actor Actor,
	tenantScopeID uuid.UUID,
	filter PublicationStatusFilter,
) (PublicationStatusCursor, error) {
	if codec == nil || encoded == "" || len(encoded) > maxPublicationCursorTokenBytes ||
		!validPublicationCursorBinding(actor, tenantScopeID, filter) {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	packet, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(packet) <= sha256.Size {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	payload, tag := packet[:len(packet)-sha256.Size], packet[len(packet)-sha256.Size:]
	if len(payload) == 0 || !utf8.Valid(payload) || rejectPublicationCursorDuplicateKeys(payload) != nil {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	var value publicationCursorPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	key, ok := codec.keys[value.KID]
	if !ok || !hmac.Equal(tag, publicationCursorMAC(key, payload)) {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) ||
		value.Version != publicationCursorVersion || value.Audience != publicationCursorAudience ||
		value.Sort != publicationCursorSort || value.ActorScopeKind != actor.ScopeKind ||
		value.ActorScopeID != actor.ScopeID || value.ActorUserID != actor.UserID ||
		value.TenantScopeID != tenantScopeID || value.FilterState != filter.State ||
		value.FilterOperation != filter.Operation || value.FilterSiteID != filter.SiteID {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	snapshotAt, ok := parsePublicationCursorTime(value.SnapshotAt)
	if !ok {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	lastOccurredAt, ok := parsePublicationCursorTime(value.LastOccurredAt)
	if !ok {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	cursor := PublicationStatusCursor{
		SnapshotAt: snapshotAt, LastOccurredAt: lastOccurredAt,
		LastSiteID: value.LastSiteID, LastBindingRevision: value.LastBindingRevision,
	}
	if !validPublicationStatusCursor(cursor) {
		return PublicationStatusCursor{}, ErrInvalidPublicationCursor
	}
	return cursor, nil
}

func validPublicationCursorBinding(
	actor Actor,
	tenantScopeID uuid.UUID,
	filter PublicationStatusFilter,
) bool {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || tenantScopeID == uuid.Nil ||
		!validPublicationStatusFilter(filter) {
		return false
	}
	switch actor.ScopeKind {
	case ScopeTenant:
		return actor.ScopeID == tenantScopeID
	case ScopePlatform:
		return true
	default:
		return false
	}
}

func validPublicationCursorKID(value string) bool {
	if value == "" || len(value) > maxPublicationCursorKIDBytes {
		return false
	}
	for index, character := range []byte(value) {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !alphaNumeric && character != '.' && character != '_' && character != '-' || index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func formatPublicationCursorTime(value time.Time) (string, bool) {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Microsecond) != 0 {
		return "", false
	}
	return value.Format(time.RFC3339Nano), true
}

func parsePublicationCursorTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond()%int(time.Microsecond) != 0 ||
		parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func publicationCursorMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(publicationCursorMACDomain))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func rejectPublicationCursorDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidPublicationCursor
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidPublicationCursor
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidPublicationCursor
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidPublicationCursor
	}
	return nil
}
