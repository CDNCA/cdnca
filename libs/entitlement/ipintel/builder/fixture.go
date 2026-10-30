package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

// FixtureSchema is the static fact file read by FixtureSource.
const FixtureSchema = "cdnca.ip-intel.fixture/v1"

type fixtureDocument struct {
	Schema        string            `json:"schema"`
	Sources       []format.Source   `json:"sources"`
	Notice        string            `json:"notice"`
	DataUpdatedAt string            `json:"data_updated_at,omitempty"`
	Regions       map[string]string `json:"regions,omitempty"`
	Entries       []fixtureEntry    `json:"entries"`
}

type fixtureEntry struct {
	Prefix   string   `json:"prefix"`
	Tags     []string `json:"tags,omitempty"`
	ASN      uint32   `json:"asn,omitempty"`
	Country  string   `json:"country,omitempty"`
	Province uint32   `json:"province,omitempty"`
	City     uint32   `json:"city,omitempty"`
	// Rank orders geography claims (lower is more authoritative).
	Rank uint8 `json:"rank,omitempty"`
}

// FixtureSource serves a static fact file. It backs the tests and a staging
// environment without the production data source
// (LICENSE_IP_INTEL_FIXTURE_FILE).
type FixtureSource struct {
	id   string
	data []byte
}

// NewFixtureSource validates data once so a bad file fails at startup.
func NewFixtureSource(id string, data []byte) (*FixtureSource, error) {
	source := &FixtureSource{id: id, data: bytes.Clone(data)}
	if _, err := source.parse(); err != nil {
		return nil, err
	}
	return source, nil
}

// LoadFixtureSource reads a fixture file from disk.
func LoadFixtureSource(path string) (*FixtureSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read fixture: %v", ErrSource, err)
	}
	return NewFixtureSource("fixture", data)
}

func (source *FixtureSource) ID() string { return source.id }

func (source *FixtureSource) Collect(ctx context.Context) (Collection, error) {
	if err := ctx.Err(); err != nil {
		return Collection{}, err
	}
	return source.parse()
}

func (source *FixtureSource) parse() (Collection, error) {
	decoder := json.NewDecoder(bytes.NewReader(source.data))
	decoder.DisallowUnknownFields()
	var document fixtureDocument
	if err := decoder.Decode(&document); err != nil || decoder.More() || document.Schema != FixtureSchema ||
		len(document.Entries) == 0 {
		return Collection{}, fmt.Errorf("%w: fixture document", ErrSource)
	}
	collection := Collection{Sources: document.Sources, Notice: document.Notice, Regions: map[uint32]string{}}
	if document.DataUpdatedAt != "" {
		at, err := time.Parse(time.RFC3339, document.DataUpdatedAt)
		if err != nil {
			return Collection{}, fmt.Errorf("%w: fixture data_updated_at", ErrSource)
		}
		collection.DataUpdatedAt = at
	}
	for code, name := range document.Regions {
		value, err := strconv.ParseUint(code, 10, 32)
		if err != nil || name == "" {
			return Collection{}, fmt.Errorf("%w: fixture region %q", ErrSource, code)
		}
		collection.Regions[uint32(value)] = name
	}
	if len(collection.Sources) == 0 {
		digest := sha256.Sum256(source.data)
		collection.Sources = []format.Source{{ID: "fixture", Name: "cdnca fixture", URL: "repo:fixture",
			License: "CC0-1.0", Ref: "fixture", Role: "carrier,asn,country,idc",
			Files: []format.SourceFile{{Path: "fixture.json", SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(source.data))}}}}
	}
	for _, entry := range document.Entries {
		prefix, err := netip.ParsePrefix(entry.Prefix)
		if err != nil || prefix != prefix.Masked() || prefix.String() != entry.Prefix {
			return Collection{}, fmt.Errorf("%w: fixture prefix %q", ErrSource, entry.Prefix)
		}
		var tags uint64
		for _, name := range entry.Tags {
			bit, ok := format.TagByName(name)
			if !ok {
				return Collection{}, fmt.Errorf("%w: fixture tag %q", ErrSource, name)
			}
			tags |= bit
		}
		collection.Facts = append(collection.Facts, format.Fact{Prefix: prefix, Tags: tags, ASN: entry.ASN,
			Country: entry.Country, Province: entry.Province, City: entry.City, CountryRank: entry.Rank})
	}
	return collection, nil
}
