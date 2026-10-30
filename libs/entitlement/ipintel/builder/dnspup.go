package builder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

// FileSource reads an IP intelligence file exported on a dnspup server
// (dnspup backend/cmd/ipintel-export: dnspup-ipintel-<release>.ndjson.gz,
// gzip NDJSON, schema dnspup.ip-intel.export/v1) and uploaded by an
// operator. Every Collect re-reads and re-validates the file with
// ParseDnspupSnapshot; a bad file fails the build and the previous library
// keeps being served. Source refs are the dnspup release.
const (
	DnspupExportSchema = "dnspup.ip-intel.export/v1"
	dnspupMaxLineBytes = 4 << 20
	dnspupMaxRows      = 12_000_000
	// DefaultFileSourceMaxBytes bounds the compressed file.
	DefaultFileSourceMaxBytes = 512 << 20

	// Geography rank of the rows (one merged answer per prefix).
	dnspupGeoRank = 0
)

var (
	dnspupReleasePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	dnspupSourcePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	dnspupFileName       = regexp.MustCompile(`^dnspup-ipintel-(.+)\.ndjson\.gz$`)
)

// dnspupCarrierTags maps the export's carrier ids to tag bits. Unknown
// carriers are ignored (forward compatible).
var dnspupCarrierTags = map[string]uint64{
	"cn-telecom": format.TagCNTelecom, "cn-unicom": format.TagCNUnicom, "cn-mobile": format.TagCNMobile,
	"cn-cernet": format.TagCNCERNET, "cn-cstnet": format.TagCNCSTNET, "cn-drpeng": format.TagCNDrPeng,
	"cn-cbn": format.TagCNCBN,
}

// FileSource is a Source backed by one uploaded export file.
type FileSource struct {
	path     string
	maxBytes int64
}

// NewFileSource checks the file once (so a bad upload is rejected at
// once). maxBytes <= 0 means DefaultFileSourceMaxBytes. A file still named
// dnspup-ipintel-<release>.ndjson.gz must carry that release.
func NewFileSource(path string, maxBytes int64) (*FileSource, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultFileSourceMaxBytes
	}
	source := &FileSource{path: path, maxBytes: maxBytes}
	if _, err := source.Collect(context.Background()); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *FileSource) ID() string { return "dnspup-file" }

// Collect parses the file.
func (source *FileSource) Collect(ctx context.Context) (Collection, error) {
	if err := ctx.Err(); err != nil {
		return Collection{}, err
	}
	file, err := os.Open(source.path)
	if err != nil {
		return Collection{}, fmt.Errorf("%w: open ip intel file: %v", ErrSource, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Collection{}, fmt.Errorf("%w: ip intel file is not a regular file", ErrSource)
	}
	if info.Size() > source.maxBytes {
		return Collection{}, fmt.Errorf("%w: ip intel file larger than %d bytes", ErrSource, source.maxBytes)
	}
	collection, release, err := ParseDnspupSnapshot(io.LimitReader(file, source.maxBytes+1), source.maxBytes)
	if err != nil {
		return Collection{}, err
	}
	if match := dnspupFileName.FindStringSubmatch(filepath.Base(source.path)); match != nil && match[1] != release {
		return Collection{}, fmt.Errorf("%w: file name says release %q but the file holds %q", ErrSource, match[1], release)
	}
	return collection, nil
}

type dnspupMeta struct {
	Type           string            `json:"type"`
	Schema         string            `json:"schema"`
	Release        string            `json:"release"`
	LibraryRelease string            `json:"library_release"`
	DataUpdatedAt  string            `json:"data_updated_at"`
	Sources        []dnspupSource    `json:"sources"`
	Carriers       map[string]string `json:"carriers"`
	Provinces      map[string]string `json:"provinces"`
	Cities         map[string]string `json:"cities"`
}

type dnspupSource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	License     string `json:"license"`
	Attribution string `json:"attribution"`
	Notice      string `json:"notice"`
	Version     string `json:"version"`
	Records     int64  `json:"records"`
	UpdatedAt   string `json:"updated_at"`
	Role        string `json:"role"`
}

type dnspupRow struct {
	Type     string `json:"type"`
	Prefix   string `json:"prefix"`
	ASN      uint32 `json:"asn"`
	Country  string `json:"country"`
	Province uint32 `json:"province"`
	City     uint32 `json:"city"`
	Carrier  string `json:"carrier"`
	IDC      bool   `json:"idc"`
	// Tor marks a Tor exit (dnspup source tor-exitlist). Accepted but not
	// stored yet: the artifact has no Tor tag bit (format v2).
	Tor      bool   `json:"tor"`
	SourceID string `json:"source_id"`
	Release  string `json:"release"`
	Rows     int64  `json:"rows"`
}

// countingReader tracks the compressed size to enforce MaxBodyBytes.
type countingReader struct {
	reader io.Reader
	n      int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	n, err := reader.reader.Read(buffer)
	reader.n += int64(n)
	return n, err
}

// ParseDnspupSnapshot decodes one gzip NDJSON snapshot. Every source the
// snapshot names must pass CheckRedistributable, every row must reference
// a listed source, and the stream must end with a matching end line.
func ParseDnspupSnapshot(body io.Reader, maxBytes int64) (Collection, string, error) {
	counted := &countingReader{reader: body}
	compressed, err := gzip.NewReader(counted)
	if err != nil {
		return Collection{}, "", fmt.Errorf("%w: dnspup body is not gzip: %v", ErrSource, err)
	}
	defer compressed.Close()
	scanner := bufio.NewScanner(compressed)
	scanner.Buffer(make([]byte, 0, 1<<20), dnspupMaxLineBytes)
	fail := func(format string, args ...any) (Collection, string, error) {
		return Collection{}, "", fmt.Errorf("%w: dnspup snapshot: "+format, append([]any{ErrSource}, args...)...)
	}
	if !scanner.Scan() {
		return fail("empty body (%v)", scanner.Err())
	}
	var meta dnspupMeta
	if err := strictJSON(scanner.Bytes(), &meta); err != nil || meta.Type != "meta" || meta.Schema != DnspupExportSchema ||
		!dnspupReleasePattern.MatchString(meta.Release) {
		return fail("bad meta line: %v", err)
	}
	dataUpdatedAt, err := time.Parse(time.RFC3339, meta.DataUpdatedAt)
	if err != nil {
		return fail("bad data_updated_at")
	}
	collection := Collection{Regions: map[uint32]string{}, DataUpdatedAt: dataUpdatedAt.UTC(), SourceRelease: meta.Release}
	listed := map[string]bool{}
	var notice strings.Builder
	notice.WriteString("IP intelligence data from dnspup release " + meta.Release + ". Sources and licenses:\n")
	for _, item := range meta.Sources {
		if !dnspupSourcePattern.MatchString(item.ID) || listed[item.ID] || item.Name == "" || item.URL == "" ||
			item.Version == "" || len(item.Attribution) > 2048 || len(item.Notice) > 16<<10 {
			return fail("bad source %q", item.ID)
		}
		listed[item.ID] = true
		collection.Sources = append(collection.Sources, format.Source{ID: item.ID, Name: item.Name, URL: item.URL,
			License: item.License, Attribution: item.Attribution, Ref: item.Version, Role: item.Role})
		fmt.Fprintf(&notice, "- %s (%s, %s): %s\n", item.Name, item.License, item.Version, item.Attribution)
		if item.Notice != "" {
			notice.WriteString(item.Notice)
			if !strings.HasSuffix(item.Notice, "\n") {
				notice.WriteString("\n")
			}
		}
	}
	if err := CheckRedistributable(collection.Sources); err != nil {
		return Collection{}, "", err
	}
	collection.Notice = notice.String()
	if len(collection.Notice) > 64<<10 {
		return fail("notice too large")
	}
	for code, name := range meta.Provinces {
		if err := addRegion(collection.Regions, code, name); err != nil {
			return fail("%v", err)
		}
	}
	for code, name := range meta.Cities {
		if err := addRegion(collection.Regions, code, name); err != nil {
			return fail("%v", err)
		}
	}
	var rows int64
	ended := false
	for scanner.Scan() {
		if counted.n > maxBytes {
			return fail("body larger than %d bytes", maxBytes)
		}
		line := scanner.Bytes()
		if ended {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			return fail("data after end line")
		}
		var row dnspupRow
		if err := strictJSON(line, &row); err != nil {
			return fail("line %d: %v", rows+2, err)
		}
		if row.Type == "end" {
			if row.Release != meta.Release || row.Rows != rows {
				return fail("end line %+v does not match %d rows of %s", row, rows, meta.Release)
			}
			ended = true
			continue
		}
		if row.Type != "prefix" || !listed[row.SourceID] {
			return fail("line %d: type %q source %q", rows+2, row.Type, row.SourceID)
		}
		rows++
		if rows > dnspupMaxRows {
			return fail("more than %d rows", dnspupMaxRows)
		}
		fact, keep, err := dnspupFact(row, collection.Regions)
		if err != nil {
			return fail("line %d: %v", rows+1, err)
		}
		if keep {
			collection.Facts = append(collection.Facts, fact)
		}
	}
	if err := scanner.Err(); err != nil {
		return fail("read: %v", err)
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return fail("gzip trailer: %v", err)
	}
	if counted.n > maxBytes {
		return fail("body larger than %d bytes", maxBytes)
	}
	if !ended {
		return fail("truncated (no end line)")
	}
	if len(collection.Facts) == 0 {
		return fail("no usable rows")
	}
	sort.Slice(collection.Sources, func(i, j int) bool { return collection.Sources[i].ID < collection.Sources[j].ID })
	return collection, meta.Release, nil
}

func strictJSON(line []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func addRegion(regions map[uint32]string, code, name string) error {
	value, err := strconv.ParseUint(code, 10, 32)
	if err != nil || value < 110000 || value > 999999 || name == "" || len(name) > 64 {
		return fmt.Errorf("bad region %q", code)
	}
	regions[uint32(value)] = name
	return nil
}

// dnspupFact turns one row into a build fact. Rows that only carry fields
// cdnca does not use yield keep=false.
func dnspupFact(row dnspupRow, regions map[uint32]string) (format.Fact, bool, error) {
	prefix, err := netip.ParsePrefix(row.Prefix)
	if err != nil || prefix != prefix.Masked() || prefix.String() != row.Prefix || prefix.Addr().Is4In6() {
		return format.Fact{}, false, fmt.Errorf("bad prefix %q", row.Prefix)
	}
	fact := format.Fact{Prefix: prefix, ASN: row.ASN}
	if row.Country != "" {
		if len(row.Country) != 2 || row.Country != strings.ToUpper(row.Country) {
			return format.Fact{}, false, fmt.Errorf("bad country %q", row.Country)
		}
		fact.Country, fact.CountryRank = row.Country, dnspupGeoRank
	}
	if row.Province != 0 || row.City != 0 {
		if fact.Country != "CN" || regions[row.Province] == "" || row.City != 0 && regions[row.City] == "" ||
			row.Province%10000 != 0 || row.City != 0 && row.City/10000*10000 != row.Province {
			return format.Fact{}, false, fmt.Errorf("bad region %d/%d", row.Province, row.City)
		}
		fact.Province, fact.City = row.Province, row.City
	}
	if row.Carrier != "" {
		fact.Tags |= dnspupCarrierTags[row.Carrier]
	}
	if row.IDC {
		fact.Tags |= format.TagIDCByCountry
	}
	return fact, fact.Tags != 0 || fact.ASN != 0 || fact.Country != "", nil
}
