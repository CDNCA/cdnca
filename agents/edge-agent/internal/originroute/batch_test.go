package originroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyBatchRollsBackEarlierPublishers(t *testing.T) {
	firstBaseline := testPolicy()
	firstBaseline.SiteID = "site-first"
	firstRuntime := &publisherRuntime{healthErrors: make(map[string]error)}
	firstPublisher, firstRoot := newTestPublisher(t, firstBaseline, firstRuntime)
	firstResult, err := firstPublisher.Apply(t.Context(), policyJSON(t, firstBaseline))
	if err != nil {
		t.Fatal(err)
	}

	secondBaseline := testPolicy()
	secondBaseline.SiteID = "site-second"
	secondRuntime := &publisherRuntime{healthErrors: make(map[string]error)}
	secondPublisher, secondRoot := newTestPublisher(t, secondBaseline, secondRuntime)
	secondResult, err := secondPublisher.Apply(t.Context(), policyJSON(t, secondBaseline))
	if err != nil {
		t.Fatal(err)
	}

	firstNext := firstBaseline
	firstNext.Revision = 2
	firstNext.VersionID = "route-v2"
	secondNext := secondBaseline
	secondNext.Revision = 2
	secondNext.VersionID = "route-v2"
	secondRuntime.precheckError = errors.New("injected second-site precheck failure")

	_, err = ApplyBatch(context.Background(), []BatchCandidate{
		{Publisher: firstPublisher, Policy: policyJSON(t, firstNext)},
		{Publisher: secondPublisher, Policy: policyJSON(t, secondNext)},
	})
	if err == nil || !errors.Is(err, ErrPrecheck) {
		t.Fatalf("ApplyBatch() error = %v, want ErrPrecheck", err)
	}
	assertPublisherPointer(t, firstRoot, "current", firstResult.Digest)
	assertPublisherPointer(t, firstRoot, "lkg", firstResult.Digest)
	assertPublisherPointer(t, secondRoot, "current", secondResult.Digest)
	assertPublisherPointer(t, secondRoot, "lkg", secondResult.Digest)
}

func assertPublisherPointer(t *testing.T, root, name, digest string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join("versions", digest) {
		t.Fatalf("%s target = %q, want digest %s", name, target, digest)
	}
}
