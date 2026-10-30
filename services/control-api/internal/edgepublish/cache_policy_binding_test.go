package edgepublish

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestCompileCachePolicyDistinguishesInheritedDisabledFromAbsent(t *testing.T) {
	siteID, definitionID := uuid.New(), uuid.New()
	absentDocument, absentRuntime, err := compileCachePolicy(siteID, nil)
	if err != nil || absentDocument != nil || absentRuntime.Mode != edgeconfig.CacheDisabled || absentRuntime.Revision != 0 {
		t.Fatalf("absent document=%+v runtime=%+v err=%v", absentDocument, absentRuntime, err)
	}
	fact := &cachePolicyFact{
		siteID: siteID, revision: 4, edgeSourceRevision: 12,
		bindingMode: "inherit", definitionID: definitionID, definitionRevision: 9,
		definitionSourceSiteID: uuid.New(),
		schemaVersion:          cachePolicySchemaV2, mode: edgeconfig.CacheDisabled,
		queryMode: edgeconfig.CacheQueryIgnore,
	}
	document, runtime, err := compileCachePolicy(siteID, fact)
	if err != nil || document == nil || document.Revision != 4 || runtime.Revision != 4 || runtime.Mode != edgeconfig.CacheDisabled {
		t.Fatalf("inherited disabled document=%+v runtime=%+v err=%v", document, runtime, err)
	}
	fact.bindingMode = ""
	if _, _, err := compileCachePolicy(siteID, fact); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing binding mode error=%v", err)
	}
}
