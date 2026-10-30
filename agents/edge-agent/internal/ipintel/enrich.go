package ipintel

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

// Enricher fills the country and carrier of the node's access and security
// events from the installed IP intelligence library:
// ClickHouse gets the region dimension at ingestion, so
// grouping and filtering by country or carrier works without a lookup at
// query time. Values the node already set are kept. Without a library the
// events pass unchanged.
//
// Carrier is the lowest carrier:* tag of the address, the display rule the
// control plane's log view uses (analyticslog.IPInfo).
type Enricher struct {
	next   eventspool.BatchSink
	path   string
	now    func() time.Time
	check  time.Duration
	mu     sync.Mutex
	table  *format.Table
	stat   fileStamp
	looked time.Time
}

type fileStamp struct {
	size    int64
	modTime time.Time
}

// enrichRefresh: how often current.ipi is checked for a new library.
const enrichRefresh = 30 * time.Second

// NewEnricher wraps next; root is the library directory (Installer.Root).
func NewEnricher(next eventspool.BatchSink, root string, now func() time.Time) *Enricher {
	if next == nil || root == "" {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &Enricher{next: next, path: filepath.Join(root, CurrentFile), now: now, check: enrichRefresh}
}

func (enricher *Enricher) AppendBatch(ctx context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	if table := enricher.library(); table != nil {
		for index := range envelopes {
			envelope := &envelopes[index]
			if envelope.Type != eventspool.EventSecurity && envelope.Type != eventspool.EventAccess {
				continue
			}
			if envelope.CountryCode != "" && envelope.Carrier != "" {
				continue
			}
			address, err := netip.ParseAddr(envelope.ClientIP)
			if err != nil {
				continue
			}
			attrs, ok := table.Lookup(address.WithZone("").Unmap())
			if !ok {
				continue
			}
			if envelope.CountryCode == "" {
				envelope.CountryCode = attrs.Country
			}
			if envelope.Carrier == "" {
				envelope.Carrier = carrierName(attrs.Tags)
			}
		}
	}
	return enricher.next.AppendBatch(ctx, envelopes)
}

func carrierName(tags uint64) string {
	for _, definition := range format.TagDefinitions() {
		if bit := uint64(1) << definition.Bit; bit&format.CarrierMask != 0 && tags&bit != 0 {
			return definition.Name
		}
	}
	return ""
}

// library is the current table, reopened when current.ipi changed. A file
// that fails to open keeps the previous table.
func (enricher *Enricher) library() *format.Table {
	enricher.mu.Lock()
	defer enricher.mu.Unlock()
	now := enricher.now()
	if !enricher.looked.IsZero() && now.Sub(enricher.looked) < enricher.check {
		return enricher.table
	}
	enricher.looked = now
	info, err := os.Stat(enricher.path)
	if err != nil {
		enricher.table, enricher.stat = nil, fileStamp{}
		return nil
	}
	stamp := fileStamp{info.Size(), info.ModTime()}
	if enricher.table != nil && stamp == enricher.stat {
		return enricher.table
	}
	data, err := os.ReadFile(enricher.path)
	if err != nil {
		return enricher.table
	}
	table, err := format.Open(data)
	if err != nil {
		return enricher.table
	}
	enricher.table, enricher.stat = table, stamp
	return table
}
