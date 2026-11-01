package nativebackup

import (
	"context"
	"strings"
	"testing"
)

// answerExecutor answers psql/clickhouse-client queries by substring.
type answerExecutor struct{ answers map[string]string }

func (fake answerExecutor) Run(_ context.Context, command Command) error {
	joined := strings.Join(command.Args, " ")
	for needle, answer := range fake.answers {
		if strings.Contains(joined, needle) {
			if command.Stdout != nil {
				_, _ = command.Stdout.Write([]byte(answer + "\n"))
			}
			return nil
		}
	}
	return nil
}

func TestPostgresPreflightAcceptsNewerTargetAndRefusesOlder(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		ok         bool
	}{
		{"170011", "170011", true},
		{"170013", "170011", true},  // newer minor
		{"180002", "170011", true},  // newer major: logical restore
		{"170009", "170011", false}, // older minor
		{"160004", "170011", false}, // older major
	} {
		host := &Host{Layout: Layout{Root: t.TempDir()}, Database: DefaultDatabaseTarget(),
			Exec: answerExecutor{answers: map[string]string{"SHOW server_version_num": tc.have, "pg_database": "0"}}}
		err := postgresComponent{}.Preflight(context.Background(), host,
			ComponentRecord{Detail: map[string]string{"server_version_num": tc.want}}, Manifest{})
		if (err == nil) != tc.ok {
			t.Fatalf("have %s want %s: err=%v", tc.have, tc.want, err)
		}
		if err != nil && !strings.Contains(err.Error(), "restore_postgresql_version_mismatch") {
			t.Fatalf("unexpected error %v", err)
		}
	}
}

func TestClickHousePreflightAcceptsNewerTargetAndRefusesOlder(t *testing.T) {
	for _, tc := range []struct {
		have, want string
		ok         bool
	}{
		{"25.3.2.39", "25.3.2.39", true},
		{"25.8.1.1", "25.3.2.39", true},
		{"26.1", "25.3.2.39", true},
		{"25.3.1.9", "25.3.2.39", false},
		{"24.12.1.1", "25.3.2.39", false},
		{"garbage", "25.3.2.39", false},
	} {
		host := &Host{Layout: Layout{Root: t.TempDir()},
			Exec: answerExecutor{answers: map[string]string{"SELECT version()": tc.have, "EXISTS DATABASE": "0"}}}
		err := clickhouseComponent{}.Preflight(context.Background(), host,
			ComponentRecord{Detail: map[string]string{"present": "1", "server_version": tc.want}}, Manifest{})
		if (err == nil) != tc.ok {
			t.Fatalf("have %s want %s: err=%v", tc.have, tc.want, err)
		}
	}
}

func TestCompareDottedVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b  string
		order int
		ok    bool
	}{
		{"1.0.35", "1.0.35", 0, true},
		{"1.0.36", "1.0.35", 1, true},
		{"1.0.9", "1.0.35", -1, true},
		{"1.1", "1.0.99", 1, true},
		{"1.0", "1.0.0", 0, true},
		{"1.0.x", "1.0.0", 0, false},
	} {
		order, ok := compareDottedVersions(tc.a, tc.b)
		if order != tc.order || ok != tc.ok {
			t.Fatalf("%s vs %s: %d %v", tc.a, tc.b, order, ok)
		}
	}
}
