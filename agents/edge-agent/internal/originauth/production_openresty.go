package originauth

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type ProductionOpenRestyCommandRunner func(context.Context, string, ...string) error

type ProductionOpenRestyConfig struct {
	Binary, RuntimePrefix, ConfigFile, LuaRoot string
	Run                                        ProductionOpenRestyCommandRunner
}

type ProductionOpenResty struct {
	binary, runtimePrefix, configFile, luaRoot string
	run                                        ProductionOpenRestyCommandRunner
}

func NewProductionOpenResty(config ProductionOpenRestyConfig) (*ProductionOpenResty, error) {
	if !cleanProductionRoot(config.Binary) || !cleanProductionRoot(config.RuntimePrefix) || !cleanProductionRoot(config.LuaRoot) ||
		config.ConfigFile == "" || filepath.IsAbs(config.ConfigFile) || filepath.Clean(config.ConfigFile) != config.ConfigFile ||
		strings.HasPrefix(config.ConfigFile, "../") || strings.ContainsAny(config.ConfigFile, "\x00\r\n") {
		return nil, ErrProductionArtifact
	}
	runner := config.Run
	if runner == nil {
		runner = runProductionOpenResty
	}
	return &ProductionOpenResty{binary: config.Binary, runtimePrefix: config.RuntimePrefix, configFile: config.ConfigFile, luaRoot: config.LuaRoot, run: runner}, nil
}

func (runtime *ProductionOpenResty) Precheck(ctx context.Context, candidate ProductionCandidate) error {
	if runtime == nil || ctx == nil || candidate.PublicationRevision == 0 || !cleanProductionRoot(candidate.PolicyPath) || len(candidate.Bindings) == 0 {
		return ErrProductionActivation
	}
	temporary, err := os.MkdirTemp(filepath.Dir(candidate.PolicyPath), ".originauth-precheck-")
	if err != nil {
		return ErrProductionActivation
	}
	defer os.RemoveAll(temporary)
	configPath := filepath.Join(temporary, "nginx.conf")
	httpInclude, _, err := OpenRestyIncludes(candidate.PolicyPath, candidate.Bindings[0])
	if err != nil {
		return ErrProductionActivation
	}
	var locations strings.Builder
	for index, binding := range candidate.Bindings {
		_, access, err := OpenRestyIncludes(candidate.PolicyPath, binding)
		if err != nil {
			return ErrProductionActivation
		}
		locations.WriteString("location = /origin-")
		locations.WriteString(strconv.Itoa(index))
		locations.WriteString(" {\n")
		locations.WriteString(access)
		locations.WriteString("}\n")
	}
	config := "error_log stderr notice;\nevents {}\nhttp {\nlua_package_path " + strconv.Quote(filepath.Join(runtime.luaRoot, "?.lua")+";;") + ";\n" +
		httpInclude + "server { listen unix:" + filepath.Join(temporary, "origin-auth.sock") + ";\n" + locations.String() + "}\n}\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return ErrProductionActivation
	}
	if err := runtime.run(ctx, runtime.binary, "-t", "-p", temporary+string(filepath.Separator), "-c", configPath); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrProductionActivation
	}
	return nil
}

func (runtime *ProductionOpenResty) Activate(ctx context.Context, candidate ProductionCandidate) error {
	if runtime == nil || ctx == nil || candidate.PublicationRevision == 0 || !cleanProductionRoot(candidate.PolicyPath) {
		return ErrProductionActivation
	}
	for _, arguments := range [][]string{{"-t", "-p", runtime.runtimePrefix + string(filepath.Separator), "-c", runtime.configFile},
		{"-s", "reload", "-p", runtime.runtimePrefix + string(filepath.Separator), "-c", runtime.configFile}} {
		if err := runtime.run(ctx, runtime.binary, arguments...); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrProductionActivation
		}
	}
	return nil
}

func runProductionOpenResty(ctx context.Context, binary string, arguments ...string) error {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

var _ ProductionRuntime = (*ProductionOpenResty)(nil)
