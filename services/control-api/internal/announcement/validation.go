package announcement

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

const (
	FormatContent = "content"
	FormatLink    = "link"
)

// fix-fielderr-be4: refusals name the editor's body field (title, body,
// sort_order, link_url, format, the audience fields, withdrawal_visibility)
// and still unwrap to ErrInvalidContent / ErrInvalidInput / ErrInvalidAudience.

func ValidateContent(content Content) error {
	if err := validateTitle(content.Title); err != nil {
		return err
	}
	if err := validateBodyText(content.Body); err != nil {
		return err
	}
	lower := strings.ToLower(content.Body)
	for _, forbidden := range []string{
		"<", ">", "![", "](", "] (", "][", "//", "://", "www.",
		"http:", "https:", "ftp:", "ftps:", "ws:", "wss:",
		"javascript:", "vbscript:", "data:", "file:", "mailto:",
	} {
		if strings.Contains(lower, forbidden) {
			return fielderr.New(ErrInvalidContent, "body", fielderr.Invalid)
		}
	}
	return nil
}

func validateTitle(title string) error {
	switch {
	case title != strings.TrimSpace(title) && strings.TrimSpace(title) != "":
		return fielderr.New(ErrInvalidContent, "title", fielderr.Invalid)
	case title == "" || strings.TrimSpace(title) == "":
		return fielderr.New(ErrInvalidContent, "title", fielderr.Required)
	case utf8.RuneCountInString(title) > MaxTitleRunes:
		return fielderr.New(ErrInvalidContent, "title", fielderr.TooLong)
	case hasForbiddenControl(title, false):
		return fielderr.New(ErrInvalidContent, "title", fielderr.Invalid)
	}
	return nil
}

// validateBodyText checks the body text, not its link/markup rules.
func validateBodyText(body string) error {
	switch {
	case strings.TrimSpace(body) == "":
		return fielderr.New(ErrInvalidContent, "body", fielderr.Required)
	case len(body) > MaxBodyBytes:
		return fielderr.New(ErrInvalidContent, "body", fielderr.TooLong)
	case body != strings.TrimSpace(body) || !utf8.ValidString(body) || hasForbiddenControl(body, true):
		return fielderr.New(ErrInvalidContent, "body", fielderr.Invalid)
	}
	return nil
}

func NormalizePresentation(value Presentation) Presentation {
	if value.Format == "" {
		value.Format = FormatContent
		value.SortOrder = 100
		value.Visible = true
	}
	return value
}

func ValidatePresentation(value Presentation, content Content) error {
	value = NormalizePresentation(value)
	if value.SortOrder < 0 || value.SortOrder > 999999 {
		return fielderr.New(ErrInvalidInput, "sort_order", fielderr.OutOfRange)
	}
	if value.LinkURL != strings.TrimSpace(value.LinkURL) {
		return fielderr.New(ErrInvalidInput, "link_url", fielderr.InvalidFormat)
	}
	switch value.Format {
	case FormatContent:
		if value.LinkURL != "" {
			return fielderr.New(ErrInvalidInput, "link_url", fielderr.Invalid)
		}
		return ValidateContent(content)
	case FormatLink:
		if content.Body != "" {
			return fielderr.New(ErrInvalidInput, "body", fielderr.Invalid)
		}
		if value.LinkURL == "" {
			return fielderr.New(ErrInvalidInput, "link_url", fielderr.Required)
		}
		parsed, err := url.Parse(value.LinkURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return fielderr.New(ErrInvalidInput, "link_url", fielderr.Invalid)
		}
		return nil
	default:
		return fielderr.New(ErrInvalidInput, "format", fielderr.Invalid)
	}
}

func hasForbiddenControl(value string, allowLayout bool) bool {
	for _, r := range value {
		if allowLayout && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func ValidateAudience(audience Audience) error {
	if audience.All {
		if len(audience.UserIDs) != 0 || len(audience.GroupIDs) != 0 {
			return fielderr.New(ErrInvalidAudience, "all", fielderr.Invalid)
		}
		return nil
	}
	if len(audience.UserIDs)+len(audience.GroupIDs) == 0 {
		return fielderr.New(ErrInvalidAudience, "user_ids", fielderr.Required)
	}
	if len(audience.UserIDs)+len(audience.GroupIDs) > MaxAudienceTargets {
		return fielderr.New(ErrInvalidAudience, "user_ids", fielderr.OutOfRange)
	}
	for field, ids := range map[string][]uuid.UUID{"user_ids": audience.UserIDs, "group_ids": audience.GroupIDs} {
		if slices.Contains(ids, uuid.Nil) {
			return fielderr.New(ErrInvalidAudience, field, fielderr.Invalid)
		}
	}
	return nil
}

func ValidateGlobalAudience(audience GlobalAudience) error {
	total := len(audience.TenantScopeIDs) + len(audience.RoleTargets) + len(audience.UserTargets)
	if audience.AllTenants {
		if total != 0 {
			return fielderr.New(ErrInvalidAudience, "all_tenants", fielderr.Invalid)
		}
		return nil
	}
	if total == 0 {
		return fielderr.New(ErrInvalidAudience, "tenant_scope_ids", fielderr.Required)
	}
	if total > MaxAudienceTargets {
		return fielderr.New(ErrInvalidAudience, "tenant_scope_ids", fielderr.OutOfRange)
	}
	if slices.Contains(audience.TenantScopeIDs, uuid.Nil) {
		return fielderr.New(ErrInvalidAudience, "tenant_scope_ids", fielderr.Invalid)
	}
	for _, target := range audience.RoleTargets {
		if target.ScopeID == uuid.Nil || target.RoleID == uuid.Nil {
			return fielderr.New(ErrInvalidAudience, "role_targets", fielderr.Invalid)
		}
	}
	for _, target := range audience.UserTargets {
		if target.ScopeID == uuid.Nil || target.UserID == uuid.Nil {
			return fielderr.New(ErrInvalidAudience, "user_targets", fielderr.Invalid)
		}
	}
	return nil
}

func canonicalGlobalAudience(audience GlobalAudience) GlobalAudience {
	result := GlobalAudience{
		AllTenants: audience.AllTenants, TenantScopeIDs: canonicalIDs(audience.TenantScopeIDs),
		RoleTargets: make([]GlobalRoleTarget, 0), UserTargets: make([]GlobalUserTarget, 0),
	}
	if result.TenantScopeIDs == nil {
		result.TenantScopeIDs = make([]uuid.UUID, 0)
	}
	roles := make(map[string]GlobalRoleTarget, len(audience.RoleTargets))
	for _, target := range audience.RoleTargets {
		roles[target.ScopeID.String()+":"+target.RoleID.String()] = target
	}
	roleKeys := make([]string, 0, len(roles))
	for key := range roles {
		roleKeys = append(roleKeys, key)
	}
	sort.Strings(roleKeys)
	for _, key := range roleKeys {
		result.RoleTargets = append(result.RoleTargets, roles[key])
	}
	users := make(map[string]GlobalUserTarget, len(audience.UserTargets))
	for _, target := range audience.UserTargets {
		users[target.ScopeID.String()+":"+target.UserID.String()] = target
	}
	userKeys := make([]string, 0, len(users))
	for key := range users {
		userKeys = append(userKeys, key)
	}
	sort.Strings(userKeys)
	for _, key := range userKeys {
		result.UserTargets = append(result.UserTargets, users[key])
	}
	return result
}

func canonicalAudience(audience Audience) Audience {
	result := Audience{All: audience.All}
	result.UserIDs = canonicalIDs(audience.UserIDs)
	result.GroupIDs = canonicalIDs(audience.GroupIDs)
	return result
}

func canonicalIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	result := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return strings.Compare(result[i].String(), result[j].String()) < 0 })
	return result
}

func validMeta(key, requestID string) bool {
	if len(key) < 1 || len(key) > 128 || len(requestID) < 1 || len(requestID) > 128 {
		return false
	}
	for _, value := range []string{key, requestID} {
		for offset, r := range value {
			alphaNumeric := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !(alphaNumeric || r == '.' || r == '_' || r == ':' || r == '-') || (offset == 0 && !alphaNumeric) {
				return false
			}
		}
	}
	return true
}

type pageCursor struct {
	SortOrder   *int64
	ScopeID     uuid.UUID
	UserID      uuid.UUID
	Filter      string
	Watermark   int64
	PublishedAt time.Time
	ID          uuid.UUID
}

type announcementCursor struct {
	ScopeID   uuid.UUID
	UserID    uuid.UUID
	Filter    string
	Watermark int64
	CreatedAt time.Time
	ID        uuid.UUID
}

type cursorPayload struct {
	SortOrder *int64    `json:"o,omitempty"`
	Version   int       `json:"v"`
	KID       string    `json:"k"`
	UserID    uuid.UUID `json:"u"`
	ScopeID   uuid.UUID `json:"s"`
	Domain    string    `json:"d"`
	Filter    string    `json:"f"`
	Watermark int64     `json:"w"`
	Position  int64     `json:"p"`
	ID        uuid.UUID `json:"i"`
}

const (
	cursorSchemaVersion = 3
	cursorDomainAdmin   = "admin"
	cursorDomainInbox   = "inbox"
)

type CursorKeyring struct {
	ActiveKID string
	Keys      map[string][]byte
}

func validatedCursorKeyring(keyring CursorKeyring) (CursorKeyring, bool) {
	if !validCursorKID(keyring.ActiveKID) || len(keyring.Keys) == 0 {
		return CursorKeyring{}, false
	}
	result := CursorKeyring{ActiveKID: keyring.ActiveKID, Keys: make(map[string][]byte, len(keyring.Keys))}
	for kid, key := range keyring.Keys {
		if !validCursorKID(kid) || len(key) < 32 || len(key) > 64 {
			return CursorKeyring{}, false
		}
		result.Keys[kid] = append([]byte(nil), key...)
	}
	if _, ok := result.Keys[result.ActiveKID]; !ok {
		return CursorKeyring{}, false
	}
	return result, true
}

func validCursorKID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index, r := range value {
		alphaNumeric := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !(alphaNumeric || r == '.' || r == '_' || r == '-') || index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func encodeCursor(keyring CursorKeyring, cursor pageCursor) string {
	return encodeCursorPayload(keyring, cursorPayload{
		SortOrder: cursor.SortOrder,
		Version:   cursorSchemaVersion, KID: keyring.ActiveKID, UserID: cursor.UserID, ScopeID: cursor.ScopeID,
		Domain: cursorDomainInbox, Filter: cursor.Filter, Watermark: cursor.Watermark,
		Position: cursor.PublishedAt.UTC().UnixMicro(), ID: cursor.ID,
	})
}

func decodeCursor(keyring CursorKeyring, encoded string) (pageCursor, error) {
	payload, err := decodeCursorPayload(keyring, encoded)
	if err != nil {
		return pageCursor{}, err
	}
	var value cursorPayload
	if err := json.Unmarshal(payload, &value); err != nil || value.Version != cursorSchemaVersion ||
		value.Domain != cursorDomainInbox || value.UserID == uuid.Nil || value.ScopeID == uuid.Nil ||
		value.Watermark < 0 || value.ID == uuid.Nil || value.Filter != normalizeReadFilter(value.Filter) {
		return pageCursor{}, ErrInvalidCursor
	}
	return pageCursor{ScopeID: value.ScopeID, UserID: value.UserID, Filter: value.Filter, Watermark: value.Watermark,
		PublishedAt: time.UnixMicro(value.Position).UTC(), ID: value.ID, SortOrder: value.SortOrder}, nil
}

func encodeAnnouncementCursor(keyring CursorKeyring, cursor announcementCursor) string {
	return encodeCursorPayload(keyring, cursorPayload{
		Version: cursorSchemaVersion, KID: keyring.ActiveKID, UserID: cursor.UserID, ScopeID: cursor.ScopeID,
		Domain: cursorDomainAdmin, Filter: cursor.Filter, Watermark: cursor.Watermark,
		Position: cursor.CreatedAt.UTC().UnixMicro(), ID: cursor.ID,
	})
}

func decodeAnnouncementCursor(keyring CursorKeyring, encoded string) (announcementCursor, error) {
	payload, err := decodeCursorPayload(keyring, encoded)
	if err != nil {
		return announcementCursor{}, err
	}
	var value cursorPayload
	if err := json.Unmarshal(payload, &value); err != nil || value.Version != cursorSchemaVersion ||
		value.Domain != cursorDomainAdmin || value.UserID == uuid.Nil || value.ScopeID == uuid.Nil ||
		value.Watermark < 0 || value.ID == uuid.Nil || value.Filter != normalizeStatusFilter(value.Filter) {
		return announcementCursor{}, ErrInvalidCursor
	}
	return announcementCursor{ScopeID: value.ScopeID, UserID: value.UserID, Filter: value.Filter, Watermark: value.Watermark,
		CreatedAt: time.UnixMicro(value.Position).UTC(), ID: value.ID}, nil
}

func encodeCursorPayload(keyring CursorKeyring, value cursorPayload) string {
	payload, _ := json.Marshal(value)
	key := keyring.Keys[value.KID]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cdnca-announcement-cursor/v3\x00"))
	_, _ = mac.Write(payload)
	tag := mac.Sum(nil)
	packet := append(append([]byte(nil), payload...), tag...)
	return base64.RawURLEncoding.EncodeToString(packet)
}

func decodeCursorPayload(keyring CursorKeyring, encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) <= sha256.Size {
		return nil, ErrInvalidCursor
	}
	payload, tag := raw[:len(raw)-sha256.Size], raw[len(raw)-sha256.Size:]
	var keyReference struct {
		KID string `json:"k"`
	}
	if err := json.Unmarshal(payload, &keyReference); err != nil || !validCursorKID(keyReference.KID) {
		return nil, ErrInvalidCursor
	}
	key, ok := keyring.Keys[keyReference.KID]
	if !ok {
		return nil, ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cdnca-announcement-cursor/v3\x00"))
	_, _ = mac.Write(payload)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, ErrInvalidCursor
	}
	return payload, nil
}

func normalizeStatusFilter(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeReadFilter(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
