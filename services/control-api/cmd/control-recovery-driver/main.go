package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func main() {
	if code := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); code != "" {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			ErrorCode string `json:"error_code"`
		}{ErrorCode: code})
		_, _ = fmt.Fprintln(os.Stderr, "control recovery driver failed")
		os.Exit(1)
	}
}

func run(parent context.Context, arguments []string, stdin io.Reader, stdout io.Writer) string {
	if parent == nil || len(arguments) == 0 {
		return "invalid_driver_invocation"
	}
	plan, err := loadPlan()
	if err != nil {
		return "driver_plan_invalid"
	}
	runtime, err := newDriverRuntime(plan)
	if err != nil {
		return "driver_state_unavailable"
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(plan.OperationTimeoutSeconds)*time.Second)
	defer cancel()
	operation := arguments[0]
	args := arguments[1:]
	switch operation {
	case "freeze":
		backupID, code := oneFlag(args, "backup-id")
		if code != "" {
			return code
		}
		output, code := runtime.freeze(ctx, backupID)
		return writeOutput(stdout, output, code)
	case "release":
		freezeID, code := oneFlag(args, "freeze-id")
		if code != "" {
			return code
		}
		_, code = runtime.release(context.WithoutCancel(ctx), freezeID)
		return code
	case "capture":
		values, code := namedFlags(args, "component", "backup-id", "freeze-id")
		if code != "" {
			return code
		}
		component, code := parseComponent(values["component"])
		if code != "" {
			return code
		}
		output, code := runtime.capture(ctx, component, values["backup-id"], values["freeze-id"])
		return writeOutput(stdout, output, code)
	case "preflight":
		targetID, code := oneFlag(args, "target-id")
		if code != "" {
			return code
		}
		var manifest controlbackup.Manifest
		if readInput(stdin, &manifest) != nil {
			return "preflight_manifest_invalid"
		}
		return runtime.preflight(ctx, manifest, targetID)
	case "restore":
		values, code := namedFlags(args, "component", "target-id")
		if code != "" {
			return code
		}
		component, code := parseComponent(values["component"])
		if code != "" {
			return code
		}
		var checkpoint controlbackup.ComponentCheckpoint
		if readInput(stdin, &checkpoint) != nil || checkpoint.Component != component {
			return "restore_checkpoint_invalid"
		}
		_, code = runtime.restore(ctx, component, checkpoint, values["target-id"])
		return code
	case "compensate":
		values, code := namedFlags(args, "component", "backup-id", "target-id")
		if code != "" {
			return code
		}
		component, code := parseComponent(values["component"])
		if code != "" {
			return code
		}
		_, code = runtime.compensate(context.WithoutCancel(ctx), component, values["backup-id"], values["target-id"])
		return code
	case "probe":
		values, code := namedFlags(args, "name", "target-id")
		if code != "" {
			return code
		}
		probe, code := parseProbe(values["name"])
		if code != "" {
			return code
		}
		var manifest controlbackup.Manifest
		if readInput(stdin, &manifest) != nil || manifest.Validate() != nil {
			return "probe_manifest_invalid"
		}
		return runtime.probe(ctx, probe, manifest, values["target-id"])
	default:
		return "unsupported_driver_operation"
	}
}

func oneFlag(arguments []string, name string) (string, string) {
	values, code := namedFlags(arguments, name)
	return values[name], code
}

func namedFlags(arguments []string, names ...string) (map[string]string, string) {
	set := flag.NewFlagSet("control-recovery-driver", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	values := make(map[string]*string, len(names))
	for _, name := range names {
		values[name] = set.String(name, "", "")
	}
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return nil, "invalid_driver_invocation"
	}
	result := make(map[string]string, len(names))
	for _, name := range names {
		if *values[name] == "" || !safeName.MatchString(*values[name]) {
			return nil, "invalid_driver_invocation"
		}
		result[name] = *values[name]
	}
	return result, ""
}

func parseComponent(value string) (controlbackup.Component, string) {
	component := controlbackup.Component(value)
	switch component {
	case controlbackup.ComponentPostgreSQL, controlbackup.ComponentClickHouse, controlbackup.ComponentJetStream:
		return component, ""
	default:
		return "", "unsupported_component"
	}
}

func parseProbe(value string) (controlbackup.ProbeName, string) {
	probe := controlbackup.ProbeName(value)
	switch probe {
	case controlbackup.ProbeDNS, controlbackup.ProbeAgentReconnect:
		return probe, ""
	default:
		return "", "unsupported_probe"
	}
}

func readInput(reader io.Reader, destination any) error {
	encoded, err := io.ReadAll(io.LimitReader(reader, maxDriverInput+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxDriverInput {
		return errors.New("driver input invalid")
	}
	return controlbackup.DecodeStrictJSON(encoded, destination)
}

func writeOutput(writer io.Writer, output json.RawMessage, code string) string {
	if code != "" {
		return code
	}
	if len(output) == 0 {
		return ""
	}
	if _, err := writer.Write(append(output, '\n')); err != nil {
		return uncertainCode
	}
	return ""
}
