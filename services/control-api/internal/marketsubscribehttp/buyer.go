package marketsubscribehttp

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Plugin security advisories this controller keeps itself (migration 296):
// what the license service delivered to this installation, with each access
// scope's acknowledgement. Buyer selection limits live on the market
// subscription (forwarded, member.go).

var (
	ErrStoreInvalid  = errors.New("market buyer store: invalid")
	ErrStoreNotFound = errors.New("market buyer store: not found")
)

type Advisory struct {
	ID               uuid.UUID        `json:"id"`
	PluginID         string           `json:"plugin_id"`
	AffectedVersions string           `json:"affected_versions"`
	FixedVersion     string           `json:"fixed_version"`
	Severity         string           `json:"severity"`
	Action           string           `json:"action"`
	Title            string           `json:"title"`
	Body             string           `json:"body"`
	PublishedAt      time.Time        `json:"published_at"`
	Acknowledgement  *Acknowledgement `json:"acknowledgement"`
}

type Acknowledgement struct {
	Disposition    string    `json:"disposition"`
	Note           string    `json:"note"`
	AcknowledgedBy uuid.UUID `json:"acknowledged_by"`
	AcknowledgedAt time.Time `json:"acknowledged_at"`
}

type BuyerStore interface {
	Advisories(ctx context.Context, scope uuid.UUID, pluginID string) ([]Advisory, error)
	Acknowledge(ctx context.Context, scope, advisory, user uuid.UUID, disposition, note string) (Acknowledgement, error)
}

// AdvisoryReporter forwards a platform acknowledgement to the license service
// right away; failures are retried by AdvisorySync. Nil when the plugin
// runtime is not configured.
type AdvisoryReporter interface {
	Report(ctx context.Context) error
}

var buyerPatterns = []string{
	"GET /v1/admin/market/advisories",
	"POST /v1/admin/market/advisories/{id}/acknowledge",
	libraryPattern,
}

// PA-27: what this controller already holds of each market plugin, so the
// embedded store can show 购买 → 下载 → 启用 and 授权失效 without the market.
const libraryPattern = "GET /v1/admin/market/plugin-library"

// LibraryItem is one plugin's local state. Installed: an installation head
// exists (any tenant); Enabled: one is enabled. Withdrawn: a materialized
// artifact (data pack, ui_page, provider) was withdrawn by the platform, i.e.
// the licence moved to another controller or ended (ADR 0007 §9).
type LibraryItem struct {
	PluginID  string `json:"plugin_id"`
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Withdrawn bool   `json:"withdrawn"`
}

// LibraryStore is optional: a BuyerStore that also implements it serves the
// plugin library route.
type LibraryStore interface {
	Library(ctx context.Context) ([]LibraryItem, error)
}

var pluginIDPattern = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)+$`)

var dispositions = map[string]bool{"disabled": true, "upgraded": true, "uninstalled": true, "accepted_risk": true, "not_affected": true}

// WithBuyer also serves plugin security advisories from store.
func (h *Handler) WithBuyer(store BuyerStore, reporter AdvisoryReporter) *Handler {
	h.handle(buyerPatterns[0], accessAdvisoryRead, func(w http.ResponseWriter, r *http.Request, c Caller) {
		plugin := ""
		for key, values := range r.URL.Query() {
			if key != "plugin_id" || len(values) != 1 || len(values[0]) > 128 || !pluginIDPattern.MatchString(values[0]) {
				writeError(w, http.StatusBadRequest, "invalid_query")
				return
			}
			plugin = values[0]
		}
		items, err := store.Advisories(r.Context(), c.ScopeID, plugin)
		if err != nil {
			storeFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	h.handle(buyerPatterns[1], accessAdvisoryAck, func(w http.ResponseWriter, r *http.Request, c Caller) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil || !segmentPattern.MatchString(r.PathValue("id")) {
			writeError(w, http.StatusBadRequest, "invalid_id")
			return
		}
		var body struct {
			Disposition string `json:"disposition"`
			Note        string `json:"note"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !dispositions[body.Disposition] || len([]rune(body.Note)) > 500 {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		ack, err := store.Acknowledge(r.Context(), c.ScopeID, id, c.UserID, body.Disposition, body.Note)
		if err != nil {
			storeFail(w, err)
			return
		}
		if reporter != nil && c.ScopeKind == "platform" {
			// Best effort: the background sync retries what did not get through.
			_ = reporter.Report(r.Context())
		}
		writeJSON(w, http.StatusOK, ack)
	})
	if library, ok := store.(LibraryStore); ok {
		h.handle(libraryPattern, accessBrowse, func(w http.ResponseWriter, r *http.Request, _ Caller) {
			if len(r.URL.Query()) > 0 {
				writeError(w, http.StatusBadRequest, "invalid_query")
				return
			}
			items, err := library.Library(r.Context())
			if err != nil {
				storeFail(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items})
		})
	}
	return h
}

func storeFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrStoreInvalid):
		writeError(w, http.StatusBadRequest, "invalid")
	case errors.Is(err, ErrStoreNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	default:
		writeError(w, http.StatusInternalServerError, "internal")
	}
}
