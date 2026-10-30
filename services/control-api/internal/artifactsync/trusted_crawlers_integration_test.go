//go:build integration

package artifactsync_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/jackc/pgx/v5"
)

// The official crawler ranges dataset is
// downloaded and verified, edgepublish reads it, each new revision asks for
// the CC scopes' republication once, and bytes that are not a dataset are
// refused (the previous one stays).
func TestArtifactSyncTrustedCrawlerDataset(t *testing.T) {
	f := newFixture(t)
	dataset := func(network string) []byte {
		content, err := crawlerdefaults.EncodeDataset(crawlerdefaults.Dataset{Schema: crawlerdefaults.DatasetSchema,
			GeneratedAt: "2026-10-20T00:00:00Z", Crawlers: []edgeconfig.CCV2TrustedCrawler{
				{Name: "openai", UserAgentTokens: []string{"GPTBot"}, Networks: []string{network}}}})
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	first := dataset("20.171.206.0/24")
	entry, err := artifactcatalog.TrustedCrawlersEntry("20261020", 1, first)
	if err != nil {
		t.Fatal(err)
	}
	f.license.Publish(entry, first)
	f.sync()
	read := func() *crawlerdefaults.Dataset {
		t.Helper()
		var value *crawlerdefaults.Dataset
		if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) (err error) {
			value, err = edgepublish.LoadTrustedCrawlerDatasetTx(t.Context(), tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if got := read(); got == nil || got.Crawlers[0].Networks[0] != "20.171.206.0/24" || f.recorder.crawlers != 1 {
		t.Fatalf("first dataset = %+v, republications %d", got, f.recorder.crawlers)
	}
	f.sync()
	if f.recorder.crawlers != 1 {
		t.Fatalf("unchanged dataset republished again: %d", f.recorder.crawlers)
	}
	bad := []byte(`{"schema":"cdnca.trusted-crawlers/v1","generated_at":"","crawlers":[{"name":"x"}]}`)
	badEntry, _ := artifactcatalog.TrustedCrawlersEntry("20261021", 2, bad)
	f.license.Publish(badEntry, bad)
	_ = f.syncer.SyncOnce(t.Context())
	if f.local()[entry.ArtifactID] != 1 || f.recorder.crawlers != 1 {
		t.Fatalf("bad dataset: local %v republications %d", f.local(), f.recorder.crawlers)
	}
	next := dataset("52.230.152.0/24")
	nextEntry, _ := artifactcatalog.TrustedCrawlersEntry("20261022", 3, next)
	f.license.Publish(nextEntry, next)
	f.sync()
	if got := read(); got == nil || got.Crawlers[0].Networks[0] != "52.230.152.0/24" || f.recorder.crawlers != 2 {
		t.Fatalf("next dataset = %+v, republications %d", got, f.recorder.crawlers)
	}
}
