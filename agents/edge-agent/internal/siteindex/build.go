package siteindex

import (
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Object is one site object as the node holds it: its plaintext (the
// cdnca.edge.site/v2 encoding) and decoded form.
type Object struct {
	Digest Digest
	Raw    []byte
	Site   edgesite.Site
	// Referenced optionally holds, by digest, the objects the site reads at
	// request time (edgesite.Site.ReferencedDigests). Activate puts them into
	// the worker readable directory before the generation is staged; release
	// keeps them while a kept generation's site references them.
	Referenced map[string][]byte
}

// DecodeObject checks raw against its address and decodes it.
func DecodeObject(digest string, raw []byte) (Object, error) {
	parsed, err := ParseDigest(digest)
	if err != nil {
		return Object{}, err
	}
	if edgesite.Digest(raw) != digest {
		return Object{}, fmt.Errorf("%w: site object %s does not match its digest", ErrFormat, digest)
	}
	site, err := edgesite.Decode(raw)
	if err != nil {
		return Object{}, err
	}
	return Object{Digest: parsed, Raw: raw, Site: site}, nil
}

// Builder accumulates the node-wide index (all scopes together) one site at
// a time, so a million sites never have to be decoded at once. It refuses
// what the request path cannot decide, with the rules of
// edgesite.PortProfiles: a site twice, a (port, name) of two sites (or an
// md5 collision of two names: the same key either way), and a port whose
// sites disagree on TLS. HTTP/2 is per site (native patch 27): the port's
// server has it when any site does (PortProfiles), so it is not checked.
type Builder struct {
	generation uint64
	sites      map[string]bool
	// ports: per port, whether it is TLS
	ports   map[int]bool
	entries []Entry
	// defaults: the default sites' entries per port (默认站点). Only a port
	// with one keeps it: two meet only while the scopes republish one after
	// the other, and then neither is the fallback until the second lands.
	defaults map[int][]Entry
}

func NewBuilder(generation uint64, sizeHint int) *Builder {
	return &Builder{generation: generation, sites: make(map[string]bool, sizeHint),
		ports: map[int]bool{}, entries: make([]Entry, 0, sizeHint), defaults: map[int][]Entry{}}
}

// Add indexes one site object under digest.
func (b *Builder) Add(digest Digest, site edgesite.Site) error {
	if b.sites[site.SiteID] {
		return fmt.Errorf("%w: site %s appears twice", ErrFormat, site.SiteID)
	}
	b.sites[site.SiteID] = true
	for _, listener := range site.Listeners {
		tls := listener.TLS != nil
		if existing, ok := b.ports[listener.Port]; ok && existing != tls {
			return fmt.Errorf("%w: port %d: TLS must be the same for every site (site %s)", ErrFormat, listener.Port, site.SiteID)
		}
		b.ports[listener.Port] = tls
	}
	for _, entry := range site.IndexEntries() {
		if entry.Name == edgesite.DefaultSiteName {
			b.defaults[entry.Port] = append(b.defaults[entry.Port], Entry{Key: entry.Key, Digest: digest})
			continue
		}
		b.entries = append(b.entries, Entry{Key: entry.Key, Digest: digest})
	}
	return nil
}

// Index sorts and checks the entries. The Builder must not be used after.
func (b *Builder) Index() (Index, error) {
	for _, entries := range b.defaults {
		if len(entries) == 1 {
			b.entries = append(b.entries, entries[0])
		}
	}
	index := Index{Generation: b.generation, Ports: make([]uint16, 0, len(b.ports)), Entries: b.entries}
	for port := range b.ports {
		index.Ports = append(index.Ports, uint16(port))
	}
	sort.Slice(index.Ports, func(i, j int) bool { return index.Ports[i] < index.Ports[j] })
	sortEntries(index.Entries)
	for position := 1; position < len(index.Entries); position++ {
		if index.Entries[position-1].Key == index.Entries[position].Key {
			return Index{}, fmt.Errorf("%w: index key %s is served twice (same port and name, or an md5 collision)", ErrFormat, index.Entries[position].Key)
		}
	}
	if err := index.check(); err != nil {
		return Index{}, err
	}
	return index, nil
}

// Build is Builder over objects.
func Build(generation uint64, objects []Object) (Index, error) {
	builder := NewBuilder(generation, len(objects))
	for _, object := range objects {
		if err := builder.Add(object.Digest, object.Site); err != nil {
			return Index{}, err
		}
	}
	return builder.Index()
}

// Digests is every distinct site object digest the index routes to.
func (index Index) Digests() []string {
	seen := make(map[Digest]bool)
	result := make([]string, 0)
	for _, entry := range index.Entries {
		if !seen[entry.Digest] {
			seen[entry.Digest] = true
			result = append(result, entry.Digest.String())
		}
	}
	return result
}

// ChangeSets splits the change from active to next into change sets of at
// most limit entries (MaxChangeEntries when limit <= 0), with consecutive
// generations starting at first (contract §4.4). Every change set carries
// next's port table except that ports are only removed in the last one, so a
// port stays ready while its remaining keys are still being changed. A
// change of nothing is one empty change set (it still moves the generation).
func ChangeSets(active Index, next Index, first uint64, limit int) ([]ChangeSet, error) {
	if limit <= 0 || limit > MaxChangeEntries {
		limit = MaxChangeEntries
	}
	if first == 0 || first <= active.Generation {
		return nil, fmt.Errorf("%w: first generation %d after %d", ErrFormat, first, active.Generation)
	}
	changes := Diff(active.Entries, next.Entries)
	parts := (len(changes) + limit - 1) / limit
	if parts == 0 {
		parts = 1
	}
	union := unionPorts(active.Ports, next.Ports)
	sets := make([]ChangeSet, 0, parts)
	base := active.Generation
	for part := range parts {
		start, end := part*limit, min((part+1)*limit, len(changes))
		ports := union
		if part == parts-1 {
			ports = next.Ports
		}
		set := ChangeSet{Generation: first + uint64(part), Base: base, Ports: ports, Changes: changes[start:end]}
		if err := set.check(); err != nil {
			return nil, err
		}
		sets = append(sets, set)
		base = set.Generation
	}
	return sets, nil
}

func unionPorts(a, b []uint16) []uint16 {
	out := make([]uint16, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j == len(b) || i < len(a) && a[i] < b[j]:
			out = append(out, a[i])
			i++
		case i == len(a) || a[i] > b[j]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// Apply returns the entries after applying changes (sorted by key) to
// entries: the expected state of the node index after a change set.
func Apply(entries []Entry, changes []Change) []Entry {
	out := make([]Entry, 0, len(entries)+len(changes))
	i, j := 0, 0
	for i < len(entries) || j < len(changes) {
		switch {
		case j == len(changes) || i < len(entries) && compareKeys(entries[i].Key, changes[j].Key) < 0:
			out = append(out, entries[i])
			i++
		default:
			same := i < len(entries) && entries[i].Key == changes[j].Key
			if changes[j].Op == OpSet {
				out = append(out, Entry{Key: changes[j].Key, Digest: changes[j].Digest})
			}
			if same {
				i++
			}
			j++
		}
	}
	return out
}
