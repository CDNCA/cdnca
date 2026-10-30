package marketsubscribehttp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync"

	"github.com/cdnca/cdnca/libs/sitetheme"
)

// GET /v1/admin/market/plugins/{id}/preview (site theme C): the theme card's
// preview of a market theme plugin not installed yet, served same-origin so
// the console never loads a third-party URL and its CSP stays as it is.
//
// The member relay carries JSON only (Forwarder returns status and body, no
// headers), so this route does not pass the market's response through: it
// checks the body itself (png/jpeg/webp sniffed from the bytes, at most
// 512 KiB, libs/sitetheme.PreviewType), takes the media type from that sniff,
// keeps the image by sha256 and answers it with its own headers. Anything else
// from the market is a 404; the card then falls back to its colors.
const marketPreviewPattern = "GET /v1/admin/market/plugins/{id}/preview"

// previewCacheLimit bounds the images kept (at most 512 KiB each).
const previewCacheLimit = 64

type previewEntry struct {
	sha, mime string
	body      []byte
}

// previewCache maps a plugin row id to its last relayed preview. A plugin's
// preview changes only with a new published version; the entry is refreshed
// on every miss of the browser cache, which revalidates by ETag.
type previewCache struct {
	mu      sync.Mutex
	entries map[string]previewEntry
}

func (c *previewCache) put(id string, entry previewEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= previewCacheLimit {
		c.entries = map[string]previewEntry{}
	}
	c.entries[id] = entry
}

func (c *previewCache) get(id string) (previewEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	return entry, ok
}

// withPluginPreview serves the market theme preview through forwarder (WithMember mounts it).
func (h *Handler) withPluginPreview(forwarder Forwarder) *Handler {
	cache := &previewCache{}
	h.handle(marketPreviewPattern, accessPluginRead, func(w http.ResponseWriter, r *http.Request, _ Caller) {
		id := r.PathValue("id")
		if !segmentPattern.MatchString(id) || r.URL.RawQuery != "" {
			writeError(w, http.StatusBadRequest, "invalid_id")
			return
		}
		status, body, err := forwarder.Forward(r.Context(), http.MethodGet, "/v1/plugins/"+id+"/preview", "", nil)
		if err != nil {
			// The market is unreachable: answer the copy kept, if any.
			if entry, ok := cache.get(id); ok {
				writeMarketPreview(w, r, entry)
				return
			}
			writeError(w, http.StatusBadGateway, "market_unavailable")
			return
		}
		mime := sitetheme.PreviewType(body)
		if status != http.StatusOK || mime == "" {
			writeError(w, http.StatusNotFound, "preview_not_found")
			return
		}
		sum := sha256.Sum256(body)
		entry := previewEntry{sha: hex.EncodeToString(sum[:]), mime: mime, body: body}
		cache.put(id, entry)
		writeMarketPreview(w, r, entry)
	})
	return h
}

func writeMarketPreview(w http.ResponseWriter, r *http.Request, entry previewEntry) {
	header := w.Header()
	etag := `"` + entry.sha + `"`
	header.Set("ETag", etag)
	// Private: the route is behind the admin session; revalidated by ETag
	// after a day since a new market version may change the image.
	header.Set("Cache-Control", "private, max-age=86400")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", entry.mime)
	header.Set("Content-Length", strconv.Itoa(len(entry.body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.body)
}
