// Package builder builds the signed IP intelligence library from a pluggable
// data Source. The binary format and release envelope live in
// libs/entitlement/ipintel; this package only turns a source's facts into
// an artifact. Production data is a dnspup export file uploaded by an
// operator (FileSource); tests and staging use FixtureSource.
package builder

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

var (
	ErrSource = errors.New("ip intel source failed")
	// ErrLicense rejects a build that lists a source outside the
	// redistribution allow list.
	ErrLicense = errors.New("ip intel source license not allowed")
)

// neverStale is the StaleAfter written into every library: the library does
// not expire by time (owner 2026-10-17: a newer library replaces the old
// one), so it is the largest instant the release format accepts
// (9999-12-31T23:59:59Z).
var neverStale = time.Unix(253402300799, 0).UTC()

// redistributableLicenses are the SPDX ids whose data may be shipped inside
// the signed node artifact (with the attribution kept in Notice).
var redistributableLicenses = map[string]bool{
	"CC-BY-4.0": true, "CC0-1.0": true, "MIT": true, "PDDL-1.0": true, "Unlicense": true, "WTFPL": true,
}

// licensedSources are the proprietary dnspup inputs the owner confirmed on
// 2026-10-17 may be shipped to customer nodes: each id is only accepted
// with exactly this license id (and an attribution).
var licensedSources = map[string]string{
	"ip2region-v4":       "LicenseRef-ip2region-commercial",
	"supplemental-0701":  "LicenseRef-dnspup-supplemental-0701",
	"manual-corrections": "LicenseRef-dnspup-manual",
	"dnspup-ip-library":  "LicenseRef-dnspup",
	// Confirmed by the owner on 2026-10-17 for routing (ASN) and Tor exit
	// tags; the upstream terms require attribution, kept in Notice.
	"ripe-ris":     "LicenseRef-ripe-ncc-ris",
	"peeringdb":    "LicenseRef-peeringdb-aup",
	"tor-exitlist": "LicenseRef-tor-project-exitlist",
}

// deniedSourceIDs are never accepted, whatever license they claim
// (ITDOG comparison evidence is not covered by the grant).
var deniedSourceIDs = map[string]bool{
	"itdog": true, "itdog-evidence": true, "itdog-auto-verified": true,
}

// CheckRedistributable enforces the license allow list: an SPDX license
// from redistributableLicenses, or one of licensedSources with its exact
// LicenseRef. Everything except CC0 / PDDL / Unlicense / WTFPL needs an
// attribution.
func CheckRedistributable(sources []format.Source) error {
	if len(sources) == 0 {
		return fmt.Errorf("%w: no sources", ErrLicense)
	}
	for _, source := range sources {
		licensed, isLicensed := licensedSources[source.ID]
		allowed := redistributableLicenses[source.License] && !strings.HasPrefix(source.License, "LicenseRef-") ||
			isLicensed && source.License == licensed
		if deniedSourceIDs[source.ID] || !allowed || isLicensed && source.License != licensed {
			return fmt.Errorf("%w: %s (%s)", ErrLicense, source.ID, source.License)
		}
		if source.License != "CC0-1.0" && source.License != "PDDL-1.0" && source.License != "Unlicense" &&
			source.License != "WTFPL" && source.Attribution == "" {
			return fmt.Errorf("%w: %s needs attribution", ErrLicense, source.ID)
		}
	}
	return nil
}

// Collection is everything one source provides for a build.
type Collection struct {
	// Sources is the provenance recorded in the artifact (id, license,
	// version/ref, file digests). At least one entry.
	Sources []format.Source
	// Notice carries license / attribution text shipped with the artifact.
	Notice string
	// Facts are the prefix claims; nesting is allowed (format.Build
	// flattens it).
	Facts []format.Fact
	// Regions names the GB/T 2260 province / city codes used by Facts.
	Regions map[uint32]string
	// DataUpdatedAt is when the upstream data last changed (zero: unknown,
	// the build time is used).
	DataUpdatedAt time.Time
	// SourceRelease is the upstream snapshot id (dnspup release), if any.
	SourceRelease string
}

// Source provides the facts of one build. Implementations must return the
// same Collection for the same upstream data so that rebuilds are
// byte-identical; any error aborts the build and the previous library stays
// served.
type Source interface {
	// ID names the source in logs and the operator page.
	ID() string
	Collect(ctx context.Context) (Collection, error)
}

// Fingerprint identifies a collection's content independently of fact order,
// revision, build id and time. Equal fingerprints mean "nothing changed".
func Fingerprint(collection Collection) string {
	hash := sha256.New()
	write := func(value string) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	write("cdnca-ip-intel-collection-fingerprint/v2")
	write(strconv.Itoa(format.FormatVersion))
	write(collection.SourceRelease)
	if !collection.DataUpdatedAt.IsZero() {
		write(collection.DataUpdatedAt.UTC().Format(time.RFC3339))
	}
	codes := make([]uint32, 0, len(collection.Regions))
	for code := range collection.Regions {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	for _, code := range codes {
		write(strconv.FormatUint(uint64(code), 10) + "=" + collection.Regions[code])
	}
	sources := append([]format.Source(nil), collection.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	for _, source := range sources {
		write(source.ID)
		write(source.License)
		write(source.Attribution)
		write(source.Ref)
		write(source.Role)
		files := append([]format.SourceFile(nil), source.Files...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		for _, file := range files {
			write(file.Path)
			write(file.SHA256)
		}
	}
	write(collection.Notice)
	facts := make([]string, len(collection.Facts))
	for index, fact := range collection.Facts {
		facts[index] = fact.Prefix.String() + "|" + strconv.FormatUint(fact.Tags, 16) + "|" +
			strconv.FormatUint(uint64(fact.ASN), 10) + "|" + fact.Country + "|" + strconv.FormatUint(uint64(fact.Province), 10) + "|" +
			strconv.FormatUint(uint64(fact.City), 10) + "|" + strconv.Itoa(int(fact.CountryRank))
	}
	sort.Strings(facts)
	for _, fact := range facts {
		write(fact)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// CompileRequest names the artifact.
type CompileRequest struct {
	Revision    uint64
	BuildID     string
	GeneratedAt time.Time
}

// Compile is a pure function of the collection and the request. It
// re-checks the license allow list before encoding anything.
func Compile(collection Collection, request CompileRequest) (format.Artifact, error) {
	if err := CheckRedistributable(collection.Sources); err != nil {
		return format.Artifact{}, err
	}
	generatedAt := request.GeneratedAt.UTC().Truncate(time.Second)
	dataUpdatedAt := collection.DataUpdatedAt.UTC().Truncate(time.Second)
	if dataUpdatedAt.IsZero() || dataUpdatedAt.After(generatedAt) {
		dataUpdatedAt = generatedAt
	}
	return format.Build(format.BuildInput{Revision: request.Revision, BuildID: request.BuildID,
		GeneratedAt: generatedAt, DataUpdatedAt: dataUpdatedAt, StaleAfter: neverStale,
		SourceRelease: collection.SourceRelease, Sources: collection.Sources, Regions: collection.Regions,
		Notice: collection.Notice, Facts: collection.Facts})
}
