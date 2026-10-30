package dyntelemetry

import (
	"container/list"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// ObjectSites resolves site objects from the worker-readable object directory
// the request path reads (dynroute contract §5.5, siteindex.ObjectDir):
// <root>/sha256/<2>/<2>/<64>, every object verified against its digest and
// decoded strictly (edgesite.Decode). Decoded sites are cached by digest
// (content addressed: an entry never goes stale).
type ObjectSites struct {
	Root  string
	Limit int // cached sites; 0 = 4096

	mu    sync.Mutex
	order *list.List
	cache map[string]*list.Element
}

type cachedSite struct {
	digest string
	site   edgesite.Site
}

func (sites *ObjectSites) Site(digest string) (edgesite.Site, error) {
	if !hexDigest(digest) {
		return edgesite.Site{}, fmt.Errorf("%w: digest %q", ErrInvalid, digest)
	}
	sites.mu.Lock()
	if sites.cache == nil {
		sites.cache, sites.order = map[string]*list.Element{}, list.New()
	}
	if element, ok := sites.cache[digest]; ok {
		sites.order.MoveToFront(element)
		site := element.Value.(cachedSite).site
		sites.mu.Unlock()
		return site, nil
	}
	sites.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(sites.Root, "sha256", digest[:2], digest[2:4], digest))
	if err != nil {
		return edgesite.Site{}, err
	}
	if edgesite.Digest(raw) != digest {
		return edgesite.Site{}, fmt.Errorf("%w: object %s does not match its digest", ErrInvalid, digest)
	}
	site, err := edgesite.Decode(raw)
	if err != nil {
		return edgesite.Site{}, fmt.Errorf("%w: object %s: %v", ErrInvalid, digest, err)
	}
	limit := sites.Limit
	if limit <= 0 {
		limit = 4096
	}
	sites.mu.Lock()
	defer sites.mu.Unlock()
	if _, ok := sites.cache[digest]; !ok {
		sites.cache[digest] = sites.order.PushFront(cachedSite{digest: digest, site: site})
		for sites.order.Len() > limit {
			oldest := sites.order.Back()
			sites.order.Remove(oldest)
			delete(sites.cache, oldest.Value.(cachedSite).digest)
		}
	}
	return site, nil
}
