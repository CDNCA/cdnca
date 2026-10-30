package analyticslog

import (
	"context"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IPInfo is what the control plane's IP intelligence library says about a
// log row's client address: looked up when the page is served,
// so nodes, telemetry and ClickHouse stay unchanged and every node's logs
// get it. Absent fields are unknown; the whole object is absent when the
// control plane has no library or the address is not in it.
type IPInfo struct {
	// Carrier is the lowest carrier:* tag (the format's display rule).
	Carrier string `json:"carrier,omitempty"`
	// IDC is idc:cn or idc:global.
	IDC          string `json:"idc,omitempty"`
	ASN          uint32 `json:"asn,omitempty"`
	Country      string `json:"country,omitempty"`
	Province     string `json:"province,omitempty"`
	ProvinceName string `json:"province_name,omitempty"`
	City         string `json:"city,omitempty"`
	CityName     string `json:"city_name,omitempty"`
	// Revision is the library revision the answer came from.
	Revision uint64 `json:"revision"`
}

// IPIntelLookup answers log rows' client addresses (nil: none).
type IPIntelLookup interface {
	Lookup(ctx context.Context, addresses []string) map[string]*IPInfo
}

// ipIntelTable is one opened library.
type ipIntelTable struct {
	revision uint64
	version  string
	table    *ipintel.Table
}

// lookup returns the answer for one address string (nil when unknown).
func (library *ipIntelTable) lookup(raw string) *IPInfo {
	if library == nil || library.table == nil {
		return nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return nil
	}
	attrs, ok := library.table.Lookup(addr.WithZone(""))
	if !ok {
		return nil
	}
	info := &IPInfo{ASN: attrs.ASN, Country: attrs.Country, Revision: library.revision}
	for _, definition := range ipintel.TagDefinitions() {
		bit := uint64(1) << definition.Bit
		if attrs.Tags&bit == 0 {
			continue
		}
		switch {
		case bit&ipintel.CarrierMask != 0 && info.Carrier == "":
			info.Carrier = definition.Name
		case bit == ipintel.TagIDCCN || bit == ipintel.TagIDCGlobal:
			if info.IDC == "" {
				info.IDC = definition.Name
			}
		}
	}
	regions := library.table.Metadata.Regions
	if attrs.Province != 0 {
		info.Province = strconv.FormatUint(uint64(attrs.Province), 10)
		info.ProvinceName = regions[info.Province]
	}
	if attrs.City != 0 {
		info.City = strconv.FormatUint(uint64(attrs.City), 10)
		info.CityName = regions[info.City]
	}
	if info.Carrier == "" && info.IDC == "" && info.ASN == 0 && info.Country == "" {
		return nil
	}
	return info
}

func (library *ipIntelTable) lookupAll(addresses []string) map[string]*IPInfo {
	result := make(map[string]*IPInfo, len(addresses))
	for _, address := range addresses {
		if _, done := result[address]; done {
			continue
		}
		result[address] = library.lookup(address)
	}
	return result
}

// PostgresIPIntelLookup reads the control plane's downloaded IP intelligence
// base library (artifact ipintel/base, kept by artifactsync). It checks the
// downloaded revision at most every refreshEvery and opens (and re-verifies)
// the bytes only when it changed; a failed reload keeps serving the previous
// table.
type PostgresIPIntelLookup struct {
	artifacts    *artifactsync.Store
	refreshEvery time.Duration
	now          func() time.Time
	logger       *slog.Logger

	mu        sync.Mutex
	current   *ipIntelTable
	checkedAt time.Time
}

func NewPostgresIPIntelLookup(pool *pgxpool.Pool, logger *slog.Logger) *PostgresIPIntelLookup {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresIPIntelLookup{artifacts: artifactsync.NewStore(pool, nil), refreshEvery: 30 * time.Second, now: time.Now, logger: logger}
}

func (lookup *PostgresIPIntelLookup) Lookup(ctx context.Context, addresses []string) map[string]*IPInfo {
	if lookup == nil || len(addresses) == 0 {
		return nil
	}
	return lookup.table(ctx).lookupAll(addresses)
}

// Library is the revision and version of the library answering (ok false:
// none loaded).
func (lookup *PostgresIPIntelLookup) Library(ctx context.Context) (revision uint64, version string, ok bool) {
	if lookup == nil {
		return 0, "", false
	}
	current := lookup.table(ctx)
	if current == nil || current.table == nil {
		return 0, "", false
	}
	return current.revision, current.version, true
}

func (lookup *PostgresIPIntelLookup) table(ctx context.Context) *ipIntelTable {
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	now := lookup.now()
	if lookup.current != nil && now.Sub(lookup.checkedAt) < lookup.refreshEvery {
		return lookup.current
	}
	lookup.checkedAt = now
	library, err := lookup.artifacts.Current(ctx, artifactcatalog.IPIntelBaseID)
	if err != nil {
		lookup.logger.WarnContext(ctx, "ip intel lookup revision check failed", "error", err)
		return lookup.current
	}
	if library == nil || lookup.current != nil && lookup.current.revision == library.Revision {
		return lookup.current
	}
	content, err := lookup.artifacts.Object(ctx, library.SHA256)
	if err != nil {
		lookup.logger.WarnContext(ctx, "ip intel lookup load failed", "error", err)
		return lookup.current
	}
	table, err := artifactcatalog.VerifyIPIntel(artifactcatalog.Entry{Kind: artifactcatalog.KindIPIntel,
		Version: library.Version, Revision: library.Revision, SHA256: library.SHA256, Size: library.Size,
		RequiresCapability: library.RequiresCapability}, content)
	if err != nil {
		lookup.logger.WarnContext(ctx, "ip intel lookup artifact invalid", "error", err)
		return lookup.current
	}
	lookup.current = &ipIntelTable{revision: library.Revision, version: library.Version, table: table}
	return lookup.current
}
