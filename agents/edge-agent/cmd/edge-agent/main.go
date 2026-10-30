package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
)

const (
	defaultConfigPath = "/etc/cdnca-edge-agent/config.json"
	configPathEnv     = "CDNCA_EDGE_CONFIG"
)

type dependencies struct {
	load   func(string) (fileConfig, parsedTimeouts, error)
	build  func(fileConfig, parsedTimeouts, string) (clientRunner, error)
	bootID func() string
	// nativeRuntime switches a native node's OpenResty/Lua runtime to the
	// Agent's version before assembly (nil in tests).
	nativeRuntime func(context.Context, string, fileConfig, parsedTimeouts,
		func(string) (fileConfig, parsedTimeouts, error)) (fileConfig, parsedTimeouts)
}

type startupOptions struct {
	configPath  string
	checkConfig bool
	showVersion bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	var code int
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		code = executeEnrollment(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr, runEnrollment)
	} else if len(os.Args) > 1 && os.Args[1] == "xdp-probe" {
		code = xdpProbeCommand(os.Args[2:], os.Stdout)
	} else {
		code = execute(ctx, os.Args[1:], os.LookupEnv, os.Stderr, dependencies{
			load: loadConfig, build: assembleClient, bootID: uuid.NewString, nativeRuntime: startNativeRuntimeSwitch,
		})
	}
	stop()
	if code != 0 {
		os.Exit(code)
	}
}

func execute(ctx context.Context, args []string, lookupEnv func(string) (string, bool), output io.Writer, deps dependencies) int {
	logger := slog.New(slog.NewJSONHandler(output, nil))
	options, err := parseStartupOptions(args, lookupEnv)
	if err != nil {
		logger.Error("edge agent arguments rejected", "event", "startup_failed", "error", safeLogError(err))
		return 2
	}
	if options.showVersion {
		logger.Info("edge agent version", "event", "version", "agent_version", agentVersion, "build_id", buildID)
		return 0
	}
	if deps.load == nil {
		logger.Error("edge agent dependencies unavailable", "event", "startup_failed")
		return 1
	}
	config, timeouts, err := deps.load(options.configPath)
	if err != nil {
		logger.Error("edge agent configuration rejected", "event", "startup_failed", "error", safeLogError(err))
		return 1
	}
	if options.checkConfig {
		logger.Info("edge agent configuration valid", "event", "configuration_valid")
		return 0
	}
	if deps.build == nil || deps.bootID == nil {
		logger.Error("edge agent dependencies unavailable", "event", "startup_failed")
		return 1
	}
	if deps.nativeRuntime != nil {
		config, timeouts = deps.nativeRuntime(ctx, options.configPath, config, timeouts, deps.load)
	}
	bootID := deps.bootID()
	if parsed, parseErr := uuid.Parse(bootID); parseErr != nil || parsed.String() != bootID {
		logger.Error("edge agent boot identity unavailable", "event", "startup_failed")
		return 1
	}
	client, err := deps.build(config, timeouts, bootID)
	if err != nil {
		logger.Error("edge agent assembly failed", "event", "startup_failed", "error", safeLogError(err))
		return 1
	}
	nodeID := config.NodeID
	if config.Identity != nil {
		nodeID = config.Identity.NodeID
	}
	logger.Info("edge agent started", "event", "agent_started", "node_id", nodeID, "boot_id", bootID)
	if err := runClient(ctx, client); err != nil {
		logger.Error("edge agent stopped with an error", "event", "agent_failed", "error", safeLogError(err))
		return 1
	}
	logger.Info("edge agent stopped", "event", "agent_stopped")
	return 0
}

func parseStartupOptions(args []string, lookupEnv func(string) (string, bool)) (startupOptions, error) {
	path := defaultConfigPath
	if lookupEnv != nil {
		if value, exists := lookupEnv(configPathEnv); exists && value != "" {
			path = value
		}
	}
	flags := flag.NewFlagSet("edge-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&path, "config", path, "absolute path to the edge agent configuration")
	checkConfig := flags.Bool("check-config", false, "validate configuration without starting the agent")
	showVersion := flags.Bool("version", false, "print version metadata and exit")
	if err := flags.Parse(args); err != nil {
		return startupOptions{}, fmt.Errorf("parse arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return startupOptions{}, fmt.Errorf("unexpected positional arguments")
	}
	if *checkConfig && *showVersion {
		return startupOptions{}, fmt.Errorf("check-config and version cannot be combined")
	}
	if !*showVersion && !absoluteCleanPath(path) {
		return startupOptions{}, fmt.Errorf("configuration path must be absolute and clean")
	}
	return startupOptions{configPath: path, checkConfig: *checkConfig, showVersion: *showVersion}, nil
}
