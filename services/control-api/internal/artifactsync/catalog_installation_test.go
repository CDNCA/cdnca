package artifactsync

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/jackc/pgx/v5"
)

type documentRow struct {
	document []byte
	err      error
}

func (row documentRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	*dest[0].(*[]byte) = row.document
	return nil
}

type documentQuerier struct{ row documentRow }

func (q documentQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return q.row }

// fix-plugverify2：当前目标安装只取已应用（已验签）目录信封里的 installation_id；没有已应用目录时为 nil
// （调用方据此不认任何安装记录）；存储的目录坏掉时报错，而不是当成“无目标”放过。
func TestVerifiedCatalogInstallation(t *testing.T) {
	entry, _ := testRuleEntry(t)
	encoded, err := testSigned(t, []artifactcatalog.Entry{entry}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	target, err := VerifiedCatalogInstallation(t.Context(), documentQuerier{documentRow{document: encoded}})
	if err != nil || target == nil || *target != testInstallationID {
		t.Fatalf("target=%v err=%v want %s", target, err, testInstallationID)
	}
	for name, row := range map[string]documentRow{"no applied catalog": {}, "no state row": {err: pgx.ErrNoRows}} {
		if target, err := VerifiedCatalogInstallation(t.Context(), documentQuerier{row}); err != nil || target != nil {
			t.Fatalf("%s: target=%v err=%v", name, target, err)
		}
	}
	if _, err := VerifiedCatalogInstallation(t.Context(), documentQuerier{documentRow{document: []byte(`{"x":1}`)}}); err == nil {
		t.Fatal("corrupt stored catalog accepted")
	}
	boom := errors.New("boom")
	if _, err := VerifiedCatalogInstallation(t.Context(), documentQuerier{documentRow{err: boom}}); !errors.Is(err, boom) {
		t.Fatalf("query error lost: %v", err)
	}
}
