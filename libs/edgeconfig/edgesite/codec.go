package edgesite

import (
	"bytes"
	"crypto/md5" //nolint:gosec // index key, collisions are re-checked against Hosts (ADR 0009 PoC §1)
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

var ErrInvalid = errors.New("edge site object: invalid")

// Encode validates site and returns its object encoding.
func Encode(site Site) ([]byte, error) {
	if err := Validate(site); err != nil {
		return nil, err
	}
	raw, err := siteobject.Encode(site)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(raw) > MaxObjectBytes {
		return nil, fmt.Errorf("%w: %d bytes exceed %d", ErrInvalid, len(raw), MaxObjectBytes)
	}
	return raw, nil
}

// Digest is the object address: hex SHA-256 of the encoding.
func Digest(raw []byte) string { return siteobject.Digest(raw) }

// Decode accepts exactly one encoding per site: bounded size, no unknown
// fields at any depth, no trailing data, re-encoding equal to raw, and a
// valid site.
func Decode(raw []byte) (Site, error) {
	if len(raw) == 0 || len(raw) > MaxObjectBytes {
		return Site{}, fmt.Errorf("%w: size", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var site Site
	if err := decoder.Decode(&site); err != nil {
		return Site{}, fmt.Errorf("%w: JSON: %v", ErrInvalid, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Site{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	encoded, err := Encode(site)
	if err != nil {
		return Site{}, err
	}
	if !bytes.Equal(encoded, raw) {
		return Site{}, fmt.Errorf("%w: not in object encoding", ErrInvalid)
	}
	return site, nil
}

// IndexKey is the node site index key of (public port, name): md5 of
// "<port>\0<name>", 16 bytes (ADR 0009 PoC §1: a 16-byte key and a 32-byte
// site digest fit one 128-byte shared dictionary slot). A lookup re-checks
// the found site's Hosts, so an md5 collision cannot route to another site.
func IndexKey(port int, name string) [md5.Size]byte {
	return md5.Sum([]byte(strconv.Itoa(port) + "\x00" + name)) //nolint:gosec
}

// DefaultSiteName is the index name of the default site: a Host is never
// empty, so the key is only ever looked up as the fallback.
const DefaultSiteName = ""

// IndexEntry is one key of the node site index.
type IndexEntry struct {
	Port int
	Name string
	Key  [md5.Size]byte
}

// IndexEntries is every (port, name) the site answers: each listener port
// with the primary name and every alias, sorted by port then name.
func (site Site) IndexEntries() []IndexEntry {
	names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
	sortStrings(names)
	entries := make([]IndexEntry, 0, len(site.Listeners)*len(names))
	for _, listener := range site.Listeners {
		for _, name := range names {
			entries = append(entries, IndexEntry{Port: listener.Port, Name: name, Key: IndexKey(listener.Port, name)})
		}
		if site.Default {
			// the default site (默认站点): the empty name, which no Host is,
			// answers what no site serves on the port (cdnca_site.find_site)
			entries = append(entries, IndexEntry{Port: listener.Port, Name: DefaultSiteName, Key: IndexKey(listener.Port, DefaultSiteName)})
		}
	}
	return entries
}

// CacheKeyPrefix is the stable cache identity of a site: it does not change
// with publications (v7 keyed caches by config version) or site edits.
func CacheKeyPrefix(tenantID, siteID string) string {
	sum := sha256.Sum256([]byte("cdnca-edge-cache-key-v2\x00" + tenantID + "\x00" + siteID))
	return hex.EncodeToString(sum[:16])
}

// CacheGeneration is the site's cache generation (edgeconfig.CacheGeneration,
// ge-cache): a new generation is a new key space; old entries age out of the
// shared zone. The error is kept for callers; the definition cannot fail.
func CacheGeneration(cache Cache) (string, error) {
	return edgeconfig.CacheGeneration(cache.Domain, cache.KeyByHost, cache.Policy), nil
}

// ReferencedDigests lists the object store digests the site references
// (every Ref with a digest: CC policies, HTTP policy, firewall action, error
// page assets, client CA, origin trust CA sets), sorted and unique. A node keeps them as long as
// the site object itself (siteindex.Activator); kinds held by identity
// (challenge policy, origin auth secret) carry no digest and are not listed.
// The CRS profile is a node-level rule pack, not a site object reference.
func (site Site) ReferencedDigests() []string {
	var refs []Ref
	if site.HTTP != nil {
		refs = append(refs, *site.HTTP)
	}
	for _, binding := range site.Security.CC {
		refs = append(refs, binding.Policy)
	}
	if site.Security.FirewallAction != nil {
		refs = append(refs, *site.Security.FirewallAction)
	}
	if site.Security.Challenge != nil {
		refs = append(refs, *site.Security.Challenge)
	}
	for _, page := range site.Errors {
		refs = append(refs, page.Asset)
	}
	for _, variant := range site.ErrorVariants {
		refs = append(refs, variant.Asset)
	}
	for _, auth := range site.Origin.Auth {
		refs = append(refs, auth.Secret)
	}
	for _, listener := range site.Listeners {
		if listener.TLS != nil && listener.TLS.ClientCA != nil {
			refs = append(refs, *listener.TLS.ClientCA)
		}
	}
	digests := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.SHA256 != "" {
			digests = append(digests, ref.SHA256)
		}
	}
	// origin trust CA sets (D5b): referenced by trust anchor digest
	digests = append(digests, site.TrustAnchors()...)
	sort.Strings(digests)
	return slices.Compact(digests)
}
