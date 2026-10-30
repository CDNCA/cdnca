// Package ipintel is the shared format of the signed IP intelligence library
// (carrier / ASN / country / IDC per address range). The license service
// builds and signs it; control-api and nodes verify and look it up. The
// on-disk layout is documented in docs/architecture/ip-intel-artifact.md and
// must stay byte-compatible with the node-side (Lua FFI) reader.
package ipintel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// Magic is the first 8 bytes of every artifact.
	Magic = "CDNIPI01"
	// FormatVersion is the binary layout version (header field and release field).
	// v2: attribute records carry GB/T 2260 province / city codes (24 bytes).
	FormatVersion = 2
	HeaderSize    = 64
	AttrSize      = 24
	// IPv4RecordSize: start[4] last[4] attr_index u32.
	IPv4RecordSize = 12
	// IPv6RecordSize: start[16] last[16] attr_index u32.
	IPv6RecordSize = 36

	// ArtifactSchema names the embedded metadata document.
	ArtifactSchema = "cdnca.ip-intel.artifact/v2"
	// Capability is the node capability gating tag rules (proto capability 35).
	Capability = "IP_INTEL"
	// CapabilityVersion is the node capability version this schema needs
	// (IP_INTEL v2 = format v2 reader).
	CapabilityVersion = 2

	// MaxArtifactBytes bounds what Open accepts (full world tables are ~20 MB).
	MaxArtifactBytes = 256 << 20
	maxMetadataBytes = 1 << 20
	maxNoticeBytes   = 64 << 10
	maxRanges        = 4_000_000
	maxFacts         = 16_000_000
	maxRegions       = 8192
	maxRegionName    = 64
	maxSourceRelease = 128
)

// Tag bits (frozen since schema v1; v2 added bit 6). Bits are frozen once released: new tags take an
// unused bit, a removed tag leaves its bit unused. Readers ignore unknown
// bits. Carrier lists are not mutually exclusive (a prefix announced by
// several origins can be in more than one list).
const (
	TagCNTelecom uint64 = 1 << 0 // carrier:cn-telecom 中国电信
	TagCNUnicom  uint64 = 1 << 1 // carrier:cn-unicom 中国联通
	TagCNMobile  uint64 = 1 << 2 // carrier:cn-mobile 中国移动
	TagCNCERNET  uint64 = 1 << 3 // carrier:cn-cernet 教育网
	TagCNCSTNET  uint64 = 1 << 4 // carrier:cn-cstnet 科技网
	TagCNDrPeng  uint64 = 1 << 5 // carrier:cn-drpeng 鹏博士
	TagCNCBN     uint64 = 1 << 6 // carrier:cn-cbn 中国广电
	// Bits 7..15 are reserved for further carriers.
	TagIDCCN     uint64 = 1 << 16 // idc:cn 国内 IDC / 云
	TagIDCGlobal uint64 = 1 << 17 // idc:global 境外 IDC / 云

	// TagIDCByCountry is a build input only (never stored): the range is an
	// IDC and Build resolves it to idc:cn when the final country is CN,
	// otherwise idc:global. Sources that know "IDC" but not the scope use it.
	TagIDCByCountry uint64 = 1 << 63

	// CarrierMask selects the carrier bits; TagMask every stored bit.
	CarrierMask uint64 = 0xFFFF
	TagMask            = TagCNTelecom | TagCNUnicom | TagCNMobile | TagCNCERNET | TagCNCSTNET | TagCNDrPeng | TagCNCBN |
		TagIDCCN | TagIDCGlobal
)

// TagDefinition describes one bit for consumers (rule names, labels).
type TagDefinition struct {
	Bit   uint8  `json:"bit"`
	Name  string `json:"name"`
	Label string `json:"label"`
}

var tagDefinitions = []TagDefinition{
	{0, "carrier:cn-telecom", "中国电信"},
	{1, "carrier:cn-unicom", "中国联通"},
	{2, "carrier:cn-mobile", "中国移动"},
	{3, "carrier:cn-cernet", "教育网"},
	{4, "carrier:cn-cstnet", "科技网"},
	{5, "carrier:cn-drpeng", "鹏博士"},
	{6, "carrier:cn-cbn", "中国广电"},
	{16, "idc:cn", "国内 IDC"},
	{17, "idc:global", "境外 IDC"},
}

// TagDefinitions returns the tag table in bit order.
func TagDefinitions() []TagDefinition { return append([]TagDefinition(nil), tagDefinitions...) }

// TagByName maps a rule tag name (carrier:cn-telecom, idc:cn ...) to its bit.
func TagByName(name string) (uint64, bool) {
	for _, definition := range tagDefinitions {
		if definition.Name == name {
			return 1 << definition.Bit, true
		}
	}
	return 0, false
}

// TagNames lists the names of the known bits set in tags, in bit order.
func TagNames(tags uint64) []string {
	names := []string{}
	for _, definition := range tagDefinitions {
		if tags&(1<<definition.Bit) != 0 {
			names = append(names, definition.Name)
		}
	}
	return names
}

var (
	ErrInvalidInput    = errors.New("ip intel build input invalid")
	ErrInvalidArtifact = errors.New("ip intel artifact invalid")

	buildIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Attrs is what a lookup returns. Country is ISO 3166-1 alpha-2 or "".
// Province / City are GB/T 2260 six digit codes (440000 / 440300) or 0;
// they are only set together with a country.
type Attrs struct {
	Tags     uint64
	ASN      uint32
	Country  string
	Province uint32
	City     uint32
}

// Fact is one input prefix. CountryRank orders geography claims (country,
// province and city travel together): a lower rank is more authoritative.
type Fact struct {
	Prefix      netip.Prefix
	Tags        uint64
	ASN         uint32
	Country     string
	Province    uint32
	City        uint32
	CountryRank uint8
}

// SourceFile is one fetched input file.
type SourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Source is one upstream dataset and its license (SPDX id). Files are the
// fetched inputs when the builder downloads them itself; a source served
// through an aggregating API may have none.
type Source struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	URL         string       `json:"url"`
	License     string       `json:"license"`
	Attribution string       `json:"attribution,omitempty"`
	Ref         string       `json:"ref"`
	Role        string       `json:"role"`
	Files       []SourceFile `json:"files,omitempty"`
}

// Counts are the section sizes.
type Counts struct {
	Attrs      uint32 `json:"attrs"`
	IPv4Ranges uint32 `json:"ipv4_ranges"`
	IPv6Ranges uint32 `json:"ipv6_ranges"`
}

// Metadata is the JSON document at the end of the artifact.
//
// Freshness: DataUpdatedAt is when the upstream data last changed,
// StaleAfter the moment after which consumers must treat the library as
// expired (it is also in the signed release). SourceRelease is the upstream
// snapshot id (dnspup release) the build came from.
type Metadata struct {
	Schema            string            `json:"schema"`
	FormatVersion     int               `json:"format_version"`
	Capability        string            `json:"capability"`
	CapabilityVersion int               `json:"capability_version"`
	Revision          uint64            `json:"revision"`
	BuildID           string            `json:"build_id"`
	GeneratedAt       string            `json:"generated_at"`
	DataUpdatedAt     string            `json:"data_updated_at"`
	StaleAfter        string            `json:"stale_after"`
	SourceRelease     string            `json:"source_release,omitempty"`
	DataSHA256        string            `json:"data_sha256"`
	Counts            Counts            `json:"counts"`
	Tags              []TagDefinition   `json:"tags"`
	Regions           map[string]string `json:"regions"`
	Sources           []Source          `json:"sources"`
	Notice            string            `json:"notice"`
}

// BuildInput is everything Build depends on: equal inputs give equal bytes.
// Regions names every province / city code the facts use (extra entries
// are dropped).
type BuildInput struct {
	Revision      uint64
	BuildID       string
	GeneratedAt   time.Time
	DataUpdatedAt time.Time
	StaleAfter    time.Time
	SourceRelease string
	Sources       []Source
	Regions       map[uint32]string
	Notice        string
	Facts         []Fact
}

// Artifact is a built library.
type Artifact struct {
	Bytes      []byte
	SHA256     string
	DataSHA256 string
	Metadata   Metadata
}

type rangeEntry struct {
	start, last netip.Addr
	attrs       mergedAttrs
}

type mergedAttrs struct {
	tags uint64
	asn  uint32
	geo  geoClaim
}

type geoClaim struct {
	country  string
	province uint32
	city     uint32
	rank     uint8
}

// public resolves build-only bits; it defines range equality and the
// dictionary.
func (attrs mergedAttrs) public() Attrs {
	tags := attrs.tags
	if tags&TagIDCByCountry != 0 {
		tags &^= TagIDCByCountry
		if attrs.geo.country == "CN" {
			tags |= TagIDCCN
		} else {
			tags |= TagIDCGlobal
		}
	}
	return Attrs{Tags: tags, ASN: attrs.asn, Country: attrs.geo.country, Province: attrs.geo.province, City: attrs.geo.city}
}

// better orders geography claims for one prefix: lower rank, then a
// deterministic tie break that prefers the more specific claim.
func (claim geoClaim) better(other geoClaim) bool {
	if other.country == "" {
		return claim.country != ""
	}
	if claim.country == "" || claim.rank != other.rank {
		return claim.country != "" && claim.rank < other.rank
	}
	if claim.country != other.country {
		return claim.country < other.country
	}
	if claim.province != other.province {
		return claim.province > other.province
	}
	return claim.city > other.city
}

// Build validates the facts, flattens nested prefixes into disjoint ranges
// and encodes the artifact.
func Build(input BuildInput) (Artifact, error) {
	if input.Revision == 0 || !buildIDPattern.MatchString(input.BuildID) || !wholeSecond(input.GeneratedAt) ||
		!wholeSecond(input.DataUpdatedAt) || !wholeSecond(input.StaleAfter) || input.DataUpdatedAt.After(input.GeneratedAt) ||
		!input.StaleAfter.After(input.GeneratedAt) || len(input.SourceRelease) > maxSourceRelease ||
		input.SourceRelease != "" && !buildIDPattern.MatchString(strings.ReplaceAll(input.SourceRelease, ":", "-")) ||
		len(input.Facts) == 0 || len(input.Facts) > maxFacts || len(input.Notice) > maxNoticeBytes {
		return Artifact{}, ErrInvalidInput
	}
	sources, err := canonicalSources(input.Sources)
	if err != nil {
		return Artifact{}, err
	}
	v4, v6, err := mergeFacts(input.Facts)
	if err != nil {
		return Artifact{}, err
	}
	if len(v4)+len(v6) > maxRanges {
		return Artifact{}, ErrInvalidInput
	}
	dictionary, index := attrDictionary(v4, v6)
	regions, err := usedRegions(dictionary, input.Regions)
	if err != nil {
		return Artifact{}, err
	}
	body := encodeBody(dictionary, index, v4, v6)
	dataDigest := sha256.Sum256(body)
	metadata := Metadata{
		Schema: ArtifactSchema, FormatVersion: FormatVersion, Capability: Capability, CapabilityVersion: CapabilityVersion,
		Revision: input.Revision, BuildID: input.BuildID, GeneratedAt: input.GeneratedAt.UTC().Format(time.RFC3339),
		DataUpdatedAt: input.DataUpdatedAt.UTC().Format(time.RFC3339), StaleAfter: input.StaleAfter.UTC().Format(time.RFC3339),
		SourceRelease: input.SourceRelease, DataSHA256: hex.EncodeToString(dataDigest[:]),
		Counts: Counts{Attrs: uint32(len(dictionary)), IPv4Ranges: uint32(len(v4)), IPv6Ranges: uint32(len(v6))},
		Tags:   TagDefinitions(), Regions: regions, Sources: sources, Notice: input.Notice,
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil || len(encodedMetadata) > maxMetadataBytes {
		return Artifact{}, ErrInvalidInput
	}
	attrOff := uint32(HeaderSize)
	v4Off := attrOff + uint32(len(dictionary))*AttrSize
	v6Off := v4Off + align8(uint32(len(v4))*IPv4RecordSize)
	metaOff := v6Off + align8(uint32(len(v6))*IPv6RecordSize)
	header := make([]byte, HeaderSize)
	copy(header[0:8], Magic)
	binary.LittleEndian.PutUint16(header[8:10], FormatVersion)
	binary.LittleEndian.PutUint16(header[10:12], HeaderSize)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(dictionary)))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(v4)))
	binary.LittleEndian.PutUint32(header[20:24], uint32(len(v6)))
	binary.LittleEndian.PutUint64(header[24:32], input.Revision)
	binary.LittleEndian.PutUint32(header[32:36], attrOff)
	binary.LittleEndian.PutUint32(header[36:40], v4Off)
	binary.LittleEndian.PutUint32(header[40:44], v6Off)
	binary.LittleEndian.PutUint32(header[44:48], metaOff)
	binary.LittleEndian.PutUint32(header[48:52], uint32(len(encodedMetadata)))
	output := make([]byte, 0, int(metaOff)+len(encodedMetadata))
	output = append(output, header...)
	output = append(output, body...)
	output = append(output, encodedMetadata...)
	if len(output) > MaxArtifactBytes {
		return Artifact{}, ErrInvalidInput
	}
	digest := sha256.Sum256(output)
	return Artifact{Bytes: output, SHA256: hex.EncodeToString(digest[:]), DataSHA256: metadata.DataSHA256,
		Metadata: metadata}, nil
}

func align8(value uint32) uint32 { return (value + 7) &^ 7 }

func wholeSecond(value time.Time) bool {
	return !value.IsZero() && value.Equal(value.Truncate(time.Second))
}

// validRegion checks a GB/T 2260 province / city pair.
func validRegion(country string, province, city uint32) bool {
	if province == 0 {
		return city == 0
	}
	if country == "" || province < 110000 || province > 999999 || province%10000 != 0 {
		return false
	}
	return city == 0 || city/10000*10000 == province && city != province
}

func usedRegions(dictionary []Attrs, names map[uint32]string) (map[string]string, error) {
	regions := map[string]string{}
	for _, attrs := range dictionary {
		for _, code := range []uint32{attrs.Province, attrs.City} {
			if code == 0 {
				continue
			}
			name := names[code]
			if name == "" || len(name) > maxRegionName || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\n\r") {
				return nil, ErrInvalidInput
			}
			regions[strconv.FormatUint(uint64(code), 10)] = name
		}
	}
	if len(regions) > maxRegions {
		return nil, ErrInvalidInput
	}
	return regions, nil
}

func canonicalSources(input []Source) ([]Source, error) {
	if len(input) == 0 || len(input) > 32 {
		return nil, ErrInvalidInput
	}
	sources := make([]Source, len(input))
	seen := map[string]bool{}
	for index, source := range input {
		if !sourceIDPattern.MatchString(source.ID) || seen[source.ID] || source.Name == "" || source.URL == "" ||
			source.License == "" || len(source.Files) > 4096 {
			return nil, ErrInvalidInput
		}
		seen[source.ID] = true
		files := append([]SourceFile(nil), source.Files...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for fileIndex, file := range files {
			if file.Path == "" || file.SHA256 == "" || file.Bytes < 0 ||
				fileIndex > 0 && files[fileIndex-1].Path == file.Path {
				return nil, ErrInvalidInput
			}
		}
		source.Files = files
		sources[index] = source
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	return sources, nil
}

func validCountry(value string) bool {
	return value == "" || len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

// combineSame merges two claims for the same prefix (order independent).
func combineSame(left, right mergedAttrs) mergedAttrs {
	result := mergedAttrs{tags: left.tags | right.tags, asn: left.asn, geo: left.geo}
	if result.asn == 0 || right.asn != 0 && right.asn < result.asn {
		result.asn = right.asn
	}
	if right.geo.better(result.geo) {
		result.geo = right.geo
	}
	return result
}

// inherit applies a more specific prefix (inner) on top of its covering one.
func inherit(outer, inner mergedAttrs) mergedAttrs {
	result := mergedAttrs{tags: outer.tags | inner.tags, asn: outer.asn, geo: outer.geo}
	if inner.asn != 0 {
		result.asn = inner.asn
	}
	if inner.geo.country != "" && (result.geo.country == "" || inner.geo.rank <= result.geo.rank) {
		result.geo = inner.geo
	}
	return result
}

type prefixNode struct {
	prefix netip.Prefix
	last   netip.Addr
	attrs  mergedAttrs
}

func mergeFacts(facts []Fact) ([]rangeEntry, []rangeEntry, error) {
	unique := make(map[netip.Prefix]mergedAttrs, len(facts))
	for _, item := range facts {
		prefix := item.Prefix
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
			!validCountry(item.Country) || !validRegion(item.Country, item.Province, item.City) ||
			item.Tags&^(TagMask|TagIDCByCountry) != 0 || item.Tags == 0 && item.ASN == 0 && item.Country == "" {
			return nil, nil, ErrInvalidInput
		}
		attrs := mergedAttrs{tags: item.Tags, asn: item.ASN,
			geo: geoClaim{country: item.Country, province: item.Province, city: item.City, rank: item.CountryRank}}
		if item.Country == "" {
			attrs.geo.rank = 0
		}
		if previous, found := unique[prefix]; found {
			attrs = combineSame(previous, attrs)
		}
		unique[prefix] = attrs
	}
	var v4Nodes, v6Nodes []prefixNode
	for prefix, attrs := range unique {
		node := prefixNode{prefix: prefix, last: lastAddr(prefix), attrs: attrs}
		if prefix.Addr().Is4() {
			v4Nodes = append(v4Nodes, node)
		} else {
			v6Nodes = append(v6Nodes, node)
		}
	}
	return sweep(v4Nodes), sweep(v6Nodes), nil
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	raw := prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(raw)*8; bit++ {
		raw[bit/8] |= 0x80 >> (bit % 8)
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr
}

type sweepFrame struct {
	last  netip.Addr
	attrs mergedAttrs
}

// sweep flattens a laminar family of prefixes (any two are nested or
// disjoint) into sorted, disjoint, maximal ranges.
func sweep(nodes []prefixNode) []rangeEntry {
	sort.Slice(nodes, func(i, j int) bool {
		if compared := nodes[i].prefix.Addr().Compare(nodes[j].prefix.Addr()); compared != 0 {
			return compared < 0
		}
		return nodes[i].prefix.Bits() < nodes[j].prefix.Bits()
	})
	var output []rangeEntry
	emit := func(start, last netip.Addr, attrs mergedAttrs) {
		if count := len(output); count > 0 && output[count-1].attrs.public() == attrs.public() &&
			output[count-1].last.Next() == start {
			output[count-1].last = last
			return
		}
		output = append(output, rangeEntry{start: start, last: last, attrs: attrs})
	}
	var stack []sweepFrame
	var cursor netip.Addr
	exhausted := false
	// pop emits the not yet emitted tail of the innermost open prefix.
	pop := func() {
		top := stack[len(stack)-1]
		if !exhausted && cursor.Compare(top.last) <= 0 {
			emit(cursor, top.last, top.attrs)
		}
		if next := top.last.Next(); next.IsValid() {
			if !exhausted && cursor.Compare(next) < 0 {
				cursor = next
			}
		} else {
			exhausted = true
		}
		stack = stack[:len(stack)-1]
	}
	for _, node := range nodes {
		start := node.prefix.Addr()
		for len(stack) > 0 && stack[len(stack)-1].last.Compare(start) < 0 {
			pop()
		}
		attrs := node.attrs
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			if cursor.Compare(start) < 0 {
				emit(cursor, start.Prev(), top.attrs)
			}
			attrs = inherit(top.attrs, node.attrs)
		}
		cursor, exhausted = start, false
		stack = append(stack, sweepFrame{last: node.last, attrs: attrs})
	}
	for len(stack) > 0 {
		pop()
	}
	return output
}

func attrDictionary(v4, v6 []rangeEntry) ([]Attrs, map[Attrs]uint32) {
	set := map[Attrs]struct{}{}
	for _, entries := range [][]rangeEntry{v4, v6} {
		for _, entry := range entries {
			set[entry.attrs.public()] = struct{}{}
		}
	}
	dictionary := make([]Attrs, 0, len(set))
	for attrs := range set {
		dictionary = append(dictionary, attrs)
	}
	sort.Slice(dictionary, func(i, j int) bool {
		left, right := dictionary[i], dictionary[j]
		if left.Tags != right.Tags {
			return left.Tags < right.Tags
		}
		if left.ASN != right.ASN {
			return left.ASN < right.ASN
		}
		if left.Country != right.Country {
			return left.Country < right.Country
		}
		if left.Province != right.Province {
			return left.Province < right.Province
		}
		return left.City < right.City
	})
	index := make(map[Attrs]uint32, len(dictionary))
	for position, attrs := range dictionary {
		index[attrs] = uint32(position)
	}
	return dictionary, index
}

func encodeBody(dictionary []Attrs, index map[Attrs]uint32, v4, v6 []rangeEntry) []byte {
	size := len(dictionary)*AttrSize + int(align8(uint32(len(v4))*IPv4RecordSize)) + int(align8(uint32(len(v6))*IPv6RecordSize))
	body := make([]byte, 0, size)
	record := make([]byte, IPv6RecordSize)
	for _, attrs := range dictionary {
		clear(record[:AttrSize])
		binary.LittleEndian.PutUint64(record[0:8], attrs.Tags)
		binary.LittleEndian.PutUint32(record[8:12], attrs.ASN)
		copy(record[12:14], attrs.Country)
		binary.LittleEndian.PutUint32(record[16:20], attrs.Province)
		binary.LittleEndian.PutUint32(record[20:24], attrs.City)
		body = append(body, record[:AttrSize]...)
	}
	for _, entry := range v4 {
		start, last := entry.start.As4(), entry.last.As4()
		copy(record[0:4], start[:])
		copy(record[4:8], last[:])
		binary.LittleEndian.PutUint32(record[8:12], index[entry.attrs.public()])
		body = append(body, record[:IPv4RecordSize]...)
	}
	body = append(body, make([]byte, int(align8(uint32(len(v4))*IPv4RecordSize))-len(v4)*IPv4RecordSize)...)
	for _, entry := range v6 {
		start, last := entry.start.As16(), entry.last.As16()
		copy(record[0:16], start[:])
		copy(record[16:32], last[:])
		binary.LittleEndian.PutUint32(record[32:36], index[entry.attrs.public()])
		body = append(body, record[:IPv6RecordSize]...)
	}
	return append(body, make([]byte, int(align8(uint32(len(v6))*IPv6RecordSize))-len(v6)*IPv6RecordSize)...)
}

// Table is an opened, fully validated artifact.
type Table struct {
	Metadata Metadata
	attrs    []Attrs
	v4       []byte
	v6       []byte
}

// Open validates the whole artifact (layout, ordering, data digest and
// metadata consistency). It does not check the signature: use VerifyArtifact
// with a verified Release for that.
func Open(data []byte) (*Table, error) { return open(data, true) }

func openUnchecked(data []byte) (*Table, error) { return open(data, false) }

func open(data []byte, verifyDigest bool) (*Table, error) {
	if len(data) < HeaderSize || len(data) > MaxArtifactBytes || string(data[0:8]) != Magic ||
		binary.LittleEndian.Uint16(data[8:10]) != FormatVersion || binary.LittleEndian.Uint16(data[10:12]) != HeaderSize ||
		!bytes.Equal(data[52:64], make([]byte, 12)) {
		return nil, ErrInvalidArtifact
	}
	attrCount := uint64(binary.LittleEndian.Uint32(data[12:16]))
	v4Count := uint64(binary.LittleEndian.Uint32(data[16:20]))
	v6Count := uint64(binary.LittleEndian.Uint32(data[20:24]))
	revision := binary.LittleEndian.Uint64(data[24:32])
	attrOff := uint64(binary.LittleEndian.Uint32(data[32:36]))
	v4Off := uint64(binary.LittleEndian.Uint32(data[36:40]))
	v6Off := uint64(binary.LittleEndian.Uint32(data[40:44]))
	metaOff := uint64(binary.LittleEndian.Uint32(data[44:48]))
	metaLen := uint64(binary.LittleEndian.Uint32(data[48:52]))
	align := func(value uint64) uint64 { return (value + 7) &^ 7 }
	if attrCount == 0 || attrCount > maxRanges || v4Count+v6Count == 0 || v4Count+v6Count > maxRanges ||
		attrOff != HeaderSize || v4Off != attrOff+attrCount*AttrSize || v6Off != v4Off+align(v4Count*IPv4RecordSize) ||
		metaOff != v6Off+align(v6Count*IPv6RecordSize) || metaLen == 0 || metaLen > maxMetadataBytes ||
		metaOff+metaLen != uint64(len(data)) {
		return nil, ErrInvalidArtifact
	}
	table := &Table{attrs: make([]Attrs, attrCount), v4: data[v4Off : v4Off+v4Count*IPv4RecordSize],
		v6: data[v6Off : v6Off+v6Count*IPv6RecordSize]}
	if !allZero(data[v4Off+v4Count*IPv4RecordSize:v6Off]) || !allZero(data[v6Off+v6Count*IPv6RecordSize:metaOff]) {
		return nil, ErrInvalidArtifact
	}
	for position := range table.attrs {
		record := data[attrOff+uint64(position)*AttrSize:]
		country := string(record[12:14])
		if country == "\x00\x00" {
			country = ""
		}
		attrs := Attrs{Tags: binary.LittleEndian.Uint64(record[0:8]), ASN: binary.LittleEndian.Uint32(record[8:12]), Country: country,
			Province: binary.LittleEndian.Uint32(record[16:20]), City: binary.LittleEndian.Uint32(record[20:24])}
		if !validCountry(country) || record[14] != 0 || record[15] != 0 || attrs.Tags == 0 && attrs.ASN == 0 && country == "" ||
			!validRegion(country, attrs.Province, attrs.City) {
			return nil, ErrInvalidArtifact
		}
		table.attrs[position] = attrs
	}
	if !validRanges(table.v4, IPv4RecordSize, 4, attrCount) || !validRanges(table.v6, IPv6RecordSize, 16, attrCount) {
		return nil, ErrInvalidArtifact
	}
	var metadata Metadata
	decoder := json.NewDecoder(bytes.NewReader(data[metaOff:]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil || decoder.More() {
		return nil, ErrInvalidArtifact
	}
	dataDigest := sha256.Sum256(data[HeaderSize:metaOff])
	if metadata.Schema != ArtifactSchema || metadata.FormatVersion != FormatVersion || metadata.Revision != revision ||
		metadata.Counts != (Counts{Attrs: uint32(attrCount), IPv4Ranges: uint32(v4Count), IPv6Ranges: uint32(v6Count)}) ||
		!buildIDPattern.MatchString(metadata.BuildID) ||
		verifyDigest && metadata.DataSHA256 != hex.EncodeToString(dataDigest[:]) {
		return nil, ErrInvalidArtifact
	}
	generatedAt, err := time.Parse(time.RFC3339, metadata.GeneratedAt)
	if err != nil {
		return nil, ErrInvalidArtifact
	}
	dataUpdatedAt, err := time.Parse(time.RFC3339, metadata.DataUpdatedAt)
	if err != nil || dataUpdatedAt.After(generatedAt) {
		return nil, ErrInvalidArtifact
	}
	if staleAfter, err := time.Parse(time.RFC3339, metadata.StaleAfter); err != nil || !staleAfter.After(generatedAt) {
		return nil, ErrInvalidArtifact
	}
	for _, attrs := range table.attrs {
		for _, code := range []uint32{attrs.Province, attrs.City} {
			if code != 0 && metadata.Regions[strconv.FormatUint(uint64(code), 10)] == "" {
				return nil, ErrInvalidArtifact
			}
		}
	}
	table.Metadata = metadata
	return table, nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func validRanges(section []byte, recordSize, addrSize int, attrCount uint64) bool {
	var previousLast []byte
	for offset := 0; offset < len(section); offset += recordSize {
		start := section[offset : offset+addrSize]
		last := section[offset+addrSize : offset+2*addrSize]
		attr := binary.LittleEndian.Uint32(section[offset+2*addrSize : offset+recordSize])
		if bytes.Compare(start, last) > 0 || uint64(attr) >= attrCount ||
			previousLast != nil && bytes.Compare(start, previousLast) <= 0 {
			return false
		}
		previousLast = last
	}
	return true
}

// Lookup returns the attributes of the range containing addr. IPv4-mapped
// IPv6 addresses are looked up in the IPv4 table.
func (table *Table) Lookup(addr netip.Addr) (Attrs, bool) {
	if table == nil || !addr.IsValid() {
		return Attrs{}, false
	}
	addr = addr.Unmap()
	section, recordSize, key := table.v6, IPv6RecordSize, addr.AsSlice()
	if addr.Is4() {
		section, recordSize = table.v4, IPv4RecordSize
	}
	addrSize := len(key)
	count := len(section) / recordSize
	// First record whose start is greater than addr; the candidate is the one before.
	position := sort.Search(count, func(index int) bool {
		offset := index * recordSize
		return bytes.Compare(section[offset:offset+addrSize], key) > 0
	})
	if position == 0 {
		return Attrs{}, false
	}
	offset := (position - 1) * recordSize
	if bytes.Compare(key, section[offset+addrSize:offset+2*addrSize]) > 0 {
		return Attrs{}, false
	}
	return table.attrs[binary.LittleEndian.Uint32(section[offset+2*addrSize:offset+recordSize])], true
}
