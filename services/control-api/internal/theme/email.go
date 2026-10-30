package theme

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailLayout wraps notification email in the active platform theme's email
// template (ADR 0007 §7.2; no tenant themes in the community edition). The plain-text body
// stays authoritative; the HTML part is an alternative and is skipped on any
// failure.
type EmailLayout struct {
	pool  *pgxpool.Pool
	mu    sync.Mutex
	cache map[string]Rendered
}

func NewEmailLayout(pool *pgxpool.Pool) *EmailLayout {
	return &EmailLayout{pool: pool, cache: make(map[string]Rendered)}
}

// Render returns the themed HTML for subject and a plain-text body, or false.
// recipientScopeID is the recipient's access scope (uuid.Nil: platform theme).
func (layout *EmailLayout) Render(ctx context.Context, recipientScopeID uuid.UUID, subject, body string) ([]byte, bool) {
	if layout == nil || layout.pool == nil {
		return nil, false
	}
	rendered, ok := layout.active(ctx, recipientScopeID)
	if !ok {
		return nil, false
	}
	lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n"), "\n")
	page, err := rendered.RenderEmail(subject, lines)
	if err != nil {
		return nil, false
	}
	return page, true
}

func (layout *EmailLayout) active(ctx context.Context, _ uuid.UUID) (Rendered, bool) {
	var digest, raw []byte
	var err error
	err = layout.pool.QueryRow(ctx, `SELECT package.package_sha256,package.package_body FROM theme_activations activation
		JOIN theme_packages package ON package.package_sha256=activation.package_sha256
		WHERE activation.slot IN ('admin','all') ORDER BY activation.revision DESC LIMIT 1`).Scan(&digest, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultRendered(), true
	}
	if err != nil {
		return Rendered{}, false
	}
	key := hex.EncodeToString(digest)
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if rendered, ok := layout.cache[key]; ok {
		return rendered, true
	}
	rendered, err := Render(raw)
	if err != nil || rendered.PackageSHA256 != key {
		return Rendered{}, false
	}
	if len(layout.cache) >= 8 {
		layout.cache = make(map[string]Rendered)
	}
	layout.cache[key] = rendered
	return rendered, true
}
