// Package sched302table computes and pushes every node's HTTP 302
// scheduling table (libs/edgeconfig/sched302): for each
// schedule302 site a node serves, the site's signing key and the candidate
// nodes of the site's line group with availability and load.
//
// Availability follows the DNS scheduling facts, so 302 and DNS scheduling
// agree: an endpoint is a candidate when its line group's current revision
// publishes it (node_line_endpoint_published: admin state, serving holds from
// availability monitoring, external probes and config sync, standby
// failover), its node is online (node_presence), and, for target=hostname,
// the node has a direct hostname. Load is the node's latest CPU percent
// (node_load_latest, fresh within two minutes).
//
// Delivery: the worker recomputes every second; a node gets a new table
// (revision + 1) when its content changed, and the same content again before
// half of sched302.HoldSeconds elapsed so the node's hold never expires while
// the control plane is reachable. Tables are signed with the configuration
// artifact key and published to JetStream (one newest message per node).
package sched302table

import (
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
)

// Site is one schedule302 site with the line group endpoints it may land on
// and the nodes serving it.
type Site struct {
	ID     uuid.UUID
	Hosts  []string
	Key    []byte
	Target string
	// HTTPPorts are the site's plain HTTP ports, ascending.
	HTTPPorts []int
	Endpoints []Endpoint
}

// Endpoint is one published line-group endpoint of the site's line group.
type Endpoint struct {
	NodeID   uuid.UUID
	Address  netip.Addr
	Region   string
	Carrier  string
	Weight   int
	Online   bool
	Hostname string
	// Load is 0..100; -1 unknown.
	Load int
}

// Tables builds the table of every node serving at least one site (a node
// serves a site when it is one of the site's endpoints). generatedAt is Unix
// seconds; revisions are filled in by the caller.
func Tables(sites []Site, generatedAt int64) map[uuid.UUID]sched302.Table {
	tables := map[uuid.UUID]sched302.Table{}
	for _, site := range sites {
		if len(site.HTTPPorts) == 0 || len(site.Key) != sched302.KeyBytes {
			continue
		}
		entry := sched302.TableSite{SiteID: site.ID.String(), Hosts: append([]string(nil), site.Hosts...),
			Key: base64.RawURLEncoding.EncodeToString(site.Key), Candidates: candidates(site)}
		served := map[uuid.UUID]bool{}
		for _, endpoint := range site.Endpoints {
			if endpoint.NodeID == uuid.Nil || served[endpoint.NodeID] {
				continue
			}
			served[endpoint.NodeID] = true
			table := tables[endpoint.NodeID]
			table.Schema, table.NodeID, table.GeneratedAt = sched302.TableSchema, endpoint.NodeID.String(), generatedAt
			table.Sites = append(table.Sites, entry)
			tables[endpoint.NodeID] = table
		}
	}
	for nodeID, table := range tables {
		sort.Slice(table.Sites, func(i, j int) bool { return table.Sites[i].SiteID < table.Sites[j].SiteID })
		tables[nodeID] = table
	}
	return tables
}

// candidates is one candidate per node (its first IPv4 endpoint, else its
// first IPv6 one: a client follows the redirect over the family it has, and
// IPv4 reaches everyone), sorted by node ID.
func candidates(site Site) []sched302.Candidate {
	type pick struct {
		endpoint Endpoint
		set      bool
	}
	byNode := map[uuid.UUID]pick{}
	for _, endpoint := range site.Endpoints {
		if endpoint.NodeID == uuid.Nil || !endpoint.Address.IsValid() {
			continue
		}
		current := byNode[endpoint.NodeID]
		if !current.set || endpoint.Address.Is4() && !current.endpoint.Address.Is4() {
			byNode[endpoint.NodeID] = pick{endpoint: endpoint, set: true}
		}
	}
	result := make([]sched302.Candidate, 0, len(byNode))
	for nodeID, value := range byNode {
		endpoint := value.endpoint
		host := endpoint.Address.Unmap().String()
		if site.Target == sched302.TargetHostname {
			if !sched302.ValidHostname(endpoint.Hostname) {
				continue
			}
			host = endpoint.Hostname
		}
		carrier, _ := marketprobe.Carrier(endpoint.Carrier)
		country, province := Region(endpoint.Region)
		load := endpoint.Load
		if load < 0 {
			load = 0
		}
		weight := min(max(endpoint.Weight, 1), 100)
		result = append(result, sched302.Candidate{NodeID: nodeID.String(), Host: host, HTTPPort: site.HTTPPorts[0],
			Carrier: carrier, Country: country, Province: province, Weight: weight, Available: endpoint.Online,
			Load: min(load, 100)})
		if len(result) == sched302.MaxCandidates {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NodeID < result[j].NodeID })
	return result
}

// Digest identifies a table's content (everything but revision and
// generated_at).
func Digest(table sched302.Table) [sha256.Size]byte {
	table.Revision, table.GeneratedAt = 1, 1
	encoded, err := sched302.Encode(table)
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(encoded)
}

// Region maps an endpoint's free-text region to an upper-case ISO country
// and, on the mainland, a GB/T 2260 province code (0 when not a province).
func Region(raw string) (string, uint32) {
	code, ok := marketprobe.Region(raw)
	if !ok {
		return "", 0
	}
	country := strings.ToUpper(code)
	if code != "cn" {
		return country, 0
	}
	value := strings.TrimPrefix(strings.TrimSpace(raw), "中国")
	for _, province := range provinceCodes {
		if strings.HasPrefix(value, province.name) {
			return country, province.code
		}
	}
	return country, 0
}

// provinceCodes are the mainland provinces (GB/T 2260 province codes), the
// names marketprobe recognizes.
var provinceCodes = []struct {
	name string
	code uint32
}{
	{"北京", 110000}, {"天津", 120000}, {"河北", 130000}, {"山西", 140000}, {"内蒙古", 150000},
	{"辽宁", 210000}, {"吉林", 220000}, {"黑龙江", 230000}, {"上海", 310000}, {"江苏", 320000},
	{"浙江", 330000}, {"安徽", 340000}, {"福建", 350000}, {"江西", 360000}, {"山东", 370000},
	{"河南", 410000}, {"湖北", 420000}, {"湖南", 430000}, {"广东", 440000}, {"广西", 450000},
	{"海南", 460000}, {"重庆", 500000}, {"四川", 510000}, {"贵州", 520000}, {"云南", 530000},
	{"西藏", 540000}, {"陕西", 610000}, {"甘肃", 620000}, {"青海", 630000}, {"宁夏", 640000},
	{"新疆", 650000},
}
