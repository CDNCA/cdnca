package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

func nativeUpgradePreflightFixture() (nativeUpgradePreflightExpectation, []string, controlplaneupgrade.NativeStandaloneStatus) {
	expected := nativeUpgradePreflightExpectation{
		InstallationID: "8c6d430a-8d0c-4f77-9c18-73d4b22fc740", Version: "1.2.3",
		SourceCommit: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40),
		ArtifactSHA256: strings.Repeat("c", 64), RunnerSHA256: strings.Repeat("d", 64),
	}
	args := []string{"--installation-id", expected.InstallationID, "--version", expected.Version,
		"--source-commit", expected.SourceCommit, "--source-tree", expected.SourceTree,
		"--artifact-sha256", expected.ArtifactSHA256, "--runner-sha256", expected.RunnerSHA256}
	status := controlplaneupgrade.NativeStandaloneStatus{
		Schema: controlplaneupgrade.NativeStatusSchema, Ready: true, Reason: "ready", Phase: "idle",
		InstallationID: expected.InstallationID, ProtocolVersion: 1, ArtifactFormat: controlplaneupgrade.NativeManifestSchema,
		CurrentVersion: expected.Version, CurrentArtifactSHA256: expected.ArtifactSHA256,
		SourceCommit: expected.SourceCommit, SourceTree: expected.SourceTree, RunnerExeSHA256: expected.RunnerSHA256,
		RunnerPID: 123, StartID: "fixture:123", ObservedAt: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC),
	}
	return expected, args, status
}

func TestNativeUpgradePreflightArguments(t *testing.T) {
	expected, args, _ := nativeUpgradePreflightFixture()
	joined, reversed := []string{}, []string{}
	for index := 0; index < len(args); index += 2 {
		joined = append(joined, args[index]+"="+args[index+1])
		reversed = append([]string{args[index], args[index+1]}, reversed...)
	}
	for _, valid := range [][]string{args, joined, reversed} {
		actual, err := parseNativeUpgradePreflightArgs(valid)
		if err != nil || actual != expected {
			t.Fatalf("valid arguments rejected: got=%+v err=%v", actual, err)
		}
	}
	for _, version := range []string{"0.0.0", "999999999.999999999.999999999"} {
		candidate := append([]string{}, args...)
		candidate[3] = version
		if _, err := parseNativeUpgradePreflightArgs(candidate); err != nil {
			t.Fatalf("valid stable version rejected: %s", version)
		}
	}
	for index := 0; index < len(args); index += 2 {
		for _, candidate := range [][]string{
			append(append([]string{}, args[:index]...), args[index+2:]...),
			append(append([]string{}, args...), args[index], args[index+1]),
			append(append([]string{}, args...), args[index]+"="+args[index+1]),
		} {
			if _, err := parseNativeUpgradePreflightArgs(candidate); err == nil {
				t.Fatalf("missing/duplicate %s accepted", args[index])
			}
		}
		candidate := append([]string{}, args...)
		candidate[index+1] = ""
		if _, err := parseNativeUpgradePreflightArgs(candidate); err == nil {
			t.Fatalf("empty %s accepted", args[index])
		}
	}
	for _, extra := range [][]string{{"--unknown", "x"}, {"--status-file", "/tmp/status.json"}, {"positional"}, {"--"}, {"--help"}} {
		if _, err := parseNativeUpgradePreflightArgs(append(append([]string{}, args...), extra...)); err == nil {
			t.Fatalf("extra arguments accepted: %v", extra)
		}
	}
	if _, err := parseNativeUpgradePreflightArgs(args[:len(args)-1]); err == nil {
		t.Fatal("missing final flag value accepted")
	}
	if _, err := parseNativeUpgradePreflightArgs(nil); err == nil {
		t.Fatal("empty invocation accepted")
	}
	for _, test := range []struct {
		index int
		value string
	}{
		{0, "-installation-id"}, {1, strings.ToUpper(expected.InstallationID)},
		{1, "00000000-0000-0000-0000-000000000000"}, {1, "urn:uuid:" + expected.InstallationID},
		{1, "{" + expected.InstallationID + "}"}, {1, strings.ReplaceAll(expected.InstallationID, "-", "")},
		{1, "not-a-uuid"}, {3, "development"}, {3, "v1.2.3"}, {3, "1.02.3"},
		{3, "1.2.3-rc.1"}, {3, "1.2.3+build"}, {3, "1000000000.2.3"}, {3, "1.2"}, {3, "1.2.3\n"},
		{5, "main"}, {5, strings.Repeat("a", 39)}, {5, strings.Repeat("a", 41)}, {5, strings.Repeat("A", 40)},
		{7, strings.Repeat("z", 40)}, {7, strings.Repeat("b", 39)}, {7, strings.Repeat("B", 40)},
		{9, strings.Repeat("c", 63)}, {9, strings.Repeat("C", 64)}, {9, strings.Repeat("g", 64)},
		{11, strings.Repeat("d", 65)}, {11, strings.Repeat("D", 64)}, {11, " " + expected.RunnerSHA256},
	} {
		candidate := append([]string{}, args...)
		candidate[test.index] = test.value
		if _, err := parseNativeUpgradePreflightArgs(candidate); err == nil {
			t.Errorf("invalid argument accepted at index %d: %q", test.index, test.value)
		}
	}
}

func TestNativeUpgradePreflightCommandDoesNotReadConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-not-a-database")
	t.Setenv("CONTROL_UPGRADE_STATE_DIR", "/must-not-create-runtime-state")
	err := run([]string{"verify-native-upgrade", "--unknown", "DO_NOT_PRINT_TOKEN"})
	if err == nil || err.Error() != "invalid native upgrade preflight arguments" {
		t.Fatalf("command was not dispatched to strict readonly preflight: %v", err)
	}
}

func TestNativeUpgradePreflightStatusMatchesRelease(t *testing.T) {
	expected, _, status := nativeUpgradePreflightFixture()
	if err := verifyNativeUpgradePreflightStatus(status, expected); err != nil {
		t.Fatalf("matching ready release rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*controlplaneupgrade.NativeStandaloneStatus)
	}{
		{"schema", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Schema = "legacy" }},
		{"unready", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Ready = false }},
		{"reason", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Reason = "control_upgrade_runner_unconfirmed" }},
		{"empty reason", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Reason = "" }},
		{"busy", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Busy = true }},
		{"phase", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Phase = "draining" }},
		{"empty phase", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.Phase = "" }},
		{"protocol zero", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.ProtocolVersion = 0 }},
		{"protocol two", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.ProtocolVersion = 2 }},
		{"artifact format", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.ArtifactFormat = "legacy" }},
		{"installation", func(s *controlplaneupgrade.NativeStandaloneStatus) {
			s.InstallationID = "9c6d430a-8d0c-4f77-9c18-73d4b22fc740"
		}},
		{"version", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.CurrentVersion = "1.2.2" }},
		{"source commit", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.SourceCommit = strings.Repeat("e", 40) }},
		{"source tree", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.SourceTree = strings.Repeat("e", 40) }},
		{"artifact digest", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.CurrentArtifactSHA256 = strings.Repeat("e", 64) }},
		{"runner digest", func(s *controlplaneupgrade.NativeStandaloneStatus) { s.RunnerExeSHA256 = strings.Repeat("e", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := status
			test.change(&candidate)
			if err := verifyNativeUpgradePreflightStatus(candidate, expected); err == nil {
				t.Fatal("unready or mismatched runtime accepted")
			}
		})
	}
}

func TestNativeUpgradePreflightUsesSecureStatusReader(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "native_upgrade_preflight.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var command *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "runVerifyNativeUpgradePreflight" {
			command = function
		}
	}
	if command == nil {
		t.Fatal("preflight CLI command is missing")
	}
	calls := 0
	ast.Inspect(command.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ReadNativeStandaloneStatus" {
			return true
		}
		calls++
		owner, ok := selector.X.(*ast.Ident)
		if !ok || owner.Name != "controlplaneupgrade" || len(call.Args) != 3 {
			t.Fatal("CLI must reuse the production owned-process status reader")
		}
		path, ok := call.Args[0].(*ast.BasicLit)
		if !ok || path.Kind != token.STRING {
			t.Fatal("status path must be a fixed string")
		}
		if value, err := strconv.Unquote(path.Value); err != nil || value != "/run/cdnca-upgrade/status.json" {
			t.Fatal("status path changed")
		}
		installation, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok || installation.Sel.Name != "InstallationID" {
			t.Fatal("status reader must bind the expected installation")
		}
		now, ok := call.Args[2].(*ast.CallExpr)
		if !ok || len(now.Args) != 0 {
			t.Fatal("status freshness must use the current time")
		}
		clock, ok := now.Fun.(*ast.SelectorExpr)
		if !ok || clock.Sel.Name != "Now" {
			t.Fatal("status freshness clock changed")
		}
		if owner, ok := clock.X.(*ast.Ident); !ok || owner.Name != "time" {
			t.Fatal("status freshness clock must be time.Now")
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("owned-process status reader calls=%d, want 1", calls)
	}
}

func TestNativeUpgradePreflightErrorsDoNotExposeInputs(t *testing.T) {
	expected, args, status := nativeUpgradePreflightFixture()
	const private = "DO_NOT_PRINT_TOKEN_OR_PRIVATE_KEY"
	for _, index := range []int{0, 1, 3, 5, 7, 9, 11} {
		candidate := append([]string{}, args...)
		candidate[index] = private
		err := runVerifyNativeUpgradePreflight(candidate)
		if err == nil || strings.Contains(err.Error(), private) {
			t.Fatalf("invalid arguments were accepted or leaked: %v", err)
		}
	}
	status.Reason = private
	if err := verifyNativeUpgradePreflightStatus(status, expected); err == nil || strings.Contains(err.Error(), private) {
		t.Fatalf("unconfirmed status was accepted or leaked: %v", err)
	}
}
