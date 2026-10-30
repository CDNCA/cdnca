//go:build !windows

package controlplaneupgrade

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSystemdProductionMigrationPhaseAndStepDeadline(t *testing.T) {
	commands := &productionCommands{}
	executor := &SystemdExecutor{config: SystemdConfig{StepTimeout: time.Second}, commands: commands}
	for _, phase := range []string{"expand", "contract"} {
		if _, err := executor.migrate(t.Context(), "/opt/cdnca/control-api/releases/digest/control-api", phase); err != nil {
			t.Fatal(err)
		}
	}
	joined := strings.Join(commands.calls, "\n")
	for _, required := range []string{
		"/usr/bin/env CDNCA_MIGRATION_PHASE=expand /opt/cdnca/control-api/releases/digest/control-api migrate up",
		"/usr/bin/env CDNCA_MIGRATION_PHASE=contract /opt/cdnca/control-api/releases/digest/control-api migrate up",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("commands omit %q: %s", required, joined)
		}
	}
	if len(commands.deadlines) != 2 || !commands.deadlines[0] || !commands.deadlines[1] {
		t.Fatalf("migration command deadlines = %v", commands.deadlines)
	}

	blocking := &productionCommands{block: true}
	executor.commands = blocking
	executor.config.StepTimeout = 15 * time.Millisecond
	started := time.Now()
	_, err := executor.runCommand(context.Background(), "systemctl", "restart", "cdnca-control-api.service")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restart deadline error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("step deadline was not enforced")
	}
}

type productionCommands struct {
	calls     []string
	deadlines []bool
	block     bool
}

func (commands *productionCommands) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	commands.calls = append(commands.calls, strings.Join(append([]string{name}, args...), " "))
	_, ok := ctx.Deadline()
	commands.deadlines = append(commands.deadlines, ok)
	if commands.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, nil
}
