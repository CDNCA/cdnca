package errorpagecontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/google/uuid"
)

var (
	writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hexDigestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validateActor(actor Actor) error {
	if actor.UserID == uuidNil || actor.ScopeID == uuidNil ||
		(actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") ||
		(actor.Credential.Kind != CredentialKindSession && actor.Credential.Kind != CredentialKindAPIKey) ||
		actor.Credential.ID == uuidNil {
		return ErrInvalidInput
	}
	return nil
}

func validateWriteMetadata(metadata WriteMetadata) error {
	if !writeMetadataPattern.MatchString(metadata.IdempotencyKey) ||
		!writeMetadataPattern.MatchString(metadata.RequestID) ||
		!writeMetadataPattern.MatchString(metadata.TraceID) {
		return ErrInvalidInput
	}
	return nil
}

func validateAssetMetadata(mime string, size int64, digest string, maxBytes int64) error {
	if !validMIME(mime) || size < 1 || size > maxBytes || size > MaxEdgeResourceBytes ||
		!hexDigestPattern.MatchString(digest) {
		return ErrInvalidInput
	}
	return nil
}

func validMIME(value string) bool {
	return value == "text/html" || value == "text/plain" || value == "application/json"
}

func validateStaticBody(mime string, body []byte) error {
	if !validMIME(mime) || len(body) == 0 || len(body) > int(MaxEdgeResourceBytes) ||
		!utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return ErrUnsafeContent
	}
	for _, marker := range themepack.TemplateMarkers {
		if bytes.Contains(body, marker) {
			return ErrUnsafeContent
		}
	}
	if mime == "application/json" && !json.Valid(body) {
		return ErrUnsafeContent
	}
	// HTML is attribute-free static HTML, or a theme-shaped page (ADR 0007
	// §7.2): its one <style> in the errorpagestyle grammar (only text the
	// control plane renders from tokens; no url(), @import or functions) and
	// class attributes naming only classes that style declares. An admin
	// edits the built-in theme page and saves it back (errpage-2); the edge
	// agent accepts the same shape (errorpage validateStaticHTML).
	if mime == "text/html" && themepack.ValidateStaticHTML(body) != nil && themepack.ValidateThemedHTML(body) != nil {
		return ErrUnsafeContent
	}
	return nil
}

// ValidateThemedHTML validates a theme-rendered page (ADR 0007 §7.2) with
// the shared themepack rule. Uploaded assets keep validateStaticBody.
func ValidateThemedHTML(body []byte) error {
	if themepack.ValidateThemedHTML(body) != nil {
		return ErrUnsafeContent
	}
	return nil
}

func validateRuleTarget(target RuleTarget) error {
	if target.ScopeID == uuidNil || (target.Kind != ScopeGlobal && target.Kind != ScopeSite) {
		return ErrInvalidInput
	}
	if target.Kind == ScopeGlobal && target.SiteID != nil {
		return ErrInvalidInput
	}
	if target.Kind == ScopeSite && (target.SiteID == nil || *target.SiteID == uuidNil) {
		return ErrInvalidInput
	}
	return nil
}

func normalizeRuleFields(target RuleTarget, fields RuleFields) (RuleFields, error) {
	if fields.AssetID == uuidNil || !validCategory(fields.Category) ||
		(fields.Match.Kind != MatchExact && fields.Match.Kind != MatchRange) {
		return RuleFields{}, ErrInvalidInput
	}
	if fields.Match.Kind == MatchExact {
		fields.Match.To = fields.Match.From
	}
	if fields.Match.From > fields.Match.To || !categoryAllowsRange(fields.Category, fields.Match.From, fields.Match.To) ||
		(target.Kind == ScopeSite && (fields.Category == CategoryNoHost || fields.Category == CategoryUnknownSite)) {
		return RuleFields{}, ErrInvalidInput
	}
	return fields, nil
}

func validCategory(category string) bool {
	switch category {
	case CategoryOriginResponse, CategoryEdgeRoute, CategoryEdgeConnect, CategoryNoHost, CategoryUnknownSite:
		return true
	default:
		return false
	}
}

func categoryAllowsRange(category string, from, to int) bool {
	switch category {
	case CategoryOriginResponse, CategoryEdgeRoute:
		return from >= 400 && to <= 599
	case CategoryEdgeConnect:
		return from >= 502 && to <= 504
	case CategoryNoHost:
		return from == 400 && to == 400
	case CategoryUnknownSite:
		// The domain mismatch page answers with one status.
		return from == to && (from == 403 || from == 404 || from == 410 || from == 421)
	default:
		return false
	}
}

func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode request digest: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

var uuidNil = uuid.Nil

// ValidAssetName: an error page asset name is empty (unnamed) or 1..128
// characters without control characters or surrounding blanks (migration 509).
func ValidAssetName(name string) bool {
	if name == "" {
		return true
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 128 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
