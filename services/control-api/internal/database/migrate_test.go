package database

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsRejectsInvalidSets(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		wantErr string
	}{
		{
			name: "version gap",
			files: migrationFiles(
				"001_first.up.sql", "001_first.down.sql",
				"003_third.up.sql", "003_third.down.sql",
			),
			wantErr: "version gap: expected 2, found 3",
		},
		{
			name: "duplicate version",
			files: migrationFiles(
				"001_first.up.sql", "001_first.down.sql",
				"001_other.up.sql", "001_other.down.sql",
			),
			wantErr: "duplicate migration version 1",
		},
		{
			name:    "missing up",
			files:   migrationFiles("001_first.down.sql"),
			wantErr: "requires both up and down scripts",
		},
		{
			name:    "missing down",
			files:   migrationFiles("001_first.up.sql"),
			wantErr: "requires both up and down scripts",
		},
		{
			name: "mismatched names",
			files: migrationFiles(
				"001_first.up.sql", "001_other.down.sql",
			),
			wantErr: "names do not match",
		},
		{
			name: "invalid naming",
			files: migrationFiles(
				"1_first.up.sql", "1_first.down.sql",
			),
			wantErr: "invalid migration filename",
		},
		{
			name: "invalid zero version",
			files: migrationFiles(
				"000_first.up.sql", "000_first.down.sql",
			),
			wantErr: "invalid migration filename",
		},
		{
			name: "invalid slug",
			files: migrationFiles(
				"001_First.up.sql", "001_First.down.sql",
			),
			wantErr: "invalid migration filename",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadMigrationsFrom(tt.files)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadMigrationsFrom() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMigrationsReturnsCanonicalMetadata(t *testing.T) {
	files := migrationFiles("001_first_step.up.sql", "001_first_step.down.sql")
	files["001_first_step.up.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;\n")}
	files["001_first_step.down.sql"] = &fstest.MapFile{Data: []byte("SELECT 2;\n")}

	got, err := loadMigrationsFrom(files)
	if err != nil {
		t.Fatalf("loadMigrationsFrom() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("migration count = %d, want 1", len(got))
	}
	wantUpSHA := fmt.Sprintf("%x", sha256.Sum256([]byte("SELECT 1;\n")))
	wantDownSHA := fmt.Sprintf("%x", sha256.Sum256([]byte("SELECT 2;\n")))
	if got[0].identifier != "001_first_step" || got[0].upSHA256 != wantUpSHA || got[0].downSHA256 != wantDownSHA {
		t.Fatalf(
			"metadata = identifier %q up sha %q down sha %q, want %q %q %q",
			got[0].identifier, got[0].upSHA256, got[0].downSHA256,
			"001_first_step", wantUpSHA, wantDownSHA,
		)
	}
}

func TestLoadMigrationsRejectsTopLevelTransactionControl(t *testing.T) {
	tests := []struct {
		name      string
		direction string
		script    string
		want      string
	}{
		{name: "begin", direction: "up", script: "CREATE TABLE probe(id integer); BEGIN;", want: "BEGIN"},
		{name: "commit", direction: "up", script: "CREATE TABLE probe(id integer); COMMIT;", want: "COMMIT"},
		{name: "rollback", direction: "down", script: "ROLLBACK; DROP TABLE probe;", want: "ROLLBACK"},
		{name: "start transaction", direction: "up", script: "START TRANSACTION; SELECT 1;", want: "START TRANSACTION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := migrationFiles("001_probe.up.sql", "001_probe.down.sql")
			files["001_probe."+tt.direction+".sql"] = &fstest.MapFile{Data: []byte(tt.script)}
			_, err := loadMigrationsFrom(files)
			if err == nil || !strings.Contains(err.Error(), "transaction control "+tt.want) {
				t.Fatalf("loadMigrationsFrom() error = %v, want transaction control %s", err, tt.want)
			}
		})
	}
}

func TestLoadMigrationsAllowsTransactionWordsInsideSQLBodiesAndComments(t *testing.T) {
	files := migrationFiles("001_probe.up.sql", "001_probe.down.sql")
	files["001_probe.up.sql"] = &fstest.MapFile{Data: []byte(`
		-- BEGIN; COMMIT; ROLLBACK;
		/* START TRANSACTION; COMMIT; */
		CREATE FUNCTION probe() RETURNS void LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM 'COMMIT';
		END;
		$$;
		SELECT 'ROLLBACK';`)}

	if _, err := loadMigrationsFrom(files); err != nil {
		t.Fatalf("loadMigrationsFrom() error = %v", err)
	}
}

func TestEmbeddedMigrationsAreContiguousAndPaired(t *testing.T) {
	got, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("loadMigrations() returned no migrations")
	}
	for i, item := range got {
		if item.version != int64(i+1) {
			t.Fatalf("migration[%d].version = %d, want %d", i, item.version, i+1)
		}
	}
}

func migrationFiles(names ...string) fstest.MapFS {
	result := make(fstest.MapFS, len(names))
	for _, name := range names {
		result[name] = &fstest.MapFile{Data: []byte("SELECT 1;\n")}
	}
	return result
}
