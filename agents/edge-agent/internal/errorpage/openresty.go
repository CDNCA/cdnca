package errorpage

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type OpenRestyCommandRunner func(context.Context, string, ...string) error
type OpenRestyHealthProbe func(context.Context, Artifact) error

type OpenRestyRuntimeConfig struct {
	Binary        string
	RuntimePrefix string
	ConfigFile    string
	Run           OpenRestyCommandRunner
	Probe         OpenRestyHealthProbe
}

type OpenRestyRuntime struct {
	binary, runtimePrefix, configFile string
	run                               OpenRestyCommandRunner
	probe                             OpenRestyHealthProbe
}

func NewOpenRestyRuntime(config OpenRestyRuntimeConfig) (*OpenRestyRuntime, error) {
	// The binary is executed, not written: nodes reach it through the installer's
	// /usr/local/openresty -> current release symlink, so only require a clean absolute path.
	if !cleanExecutablePath(config.Binary) || !cleanDirectiveAbsolutePath(config.RuntimePrefix) ||
		config.ConfigFile == "" || filepath.IsAbs(config.ConfigFile) || filepath.Clean(config.ConfigFile) != config.ConfigFile ||
		strings.ContainsAny(config.ConfigFile, "\x00\r\n") || strings.HasPrefix(config.ConfigFile, "../") || config.Probe == nil {
		return nil, ErrInvalidPolicy
	}
	runner := config.Run
	if runner == nil {
		runner = runOpenRestyCommand
	}
	return &OpenRestyRuntime{binary: config.Binary, runtimePrefix: config.RuntimePrefix, configFile: config.ConfigFile, run: runner, probe: config.Probe}, nil
}

func (runtime *OpenRestyRuntime) Precheck(ctx context.Context, release string) error {
	if runtime == nil || ctx == nil || !cleanAbsolutePath(release) {
		return ErrPrecheck
	}
	policyPath := filepath.Join(release, "policy.lua")
	info, err := os.Lstat(policyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		return ErrPrecheck
	}
	temporary, err := os.MkdirTemp(filepath.Dir(release), ".errorpage-precheck-")
	if err != nil {
		return ErrPrecheck
	}
	defer os.RemoveAll(temporary)
	configPath := filepath.Join(temporary, "nginx.conf")
	config := "error_log stderr notice;\nevents {}\nhttp { init_by_lua_block { " +
		"local chunk, load_error = loadfile(" + strconv.Quote(policyPath) + "); " +
		"if not chunk then error(load_error) end; local policy = chunk(); " +
		"if type(policy) ~= 'table' or type(policy.bindings) ~= 'table' or type(policy.resources) ~= 'table' then error('invalid error page policy') end } }\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return ErrPrecheck
	}
	if err := runtime.run(ctx, runtime.binary, "-t", "-p", withOpenRestySlash(temporary), "-c", configPath); err != nil {
		return sanitizedOpenRestyError(ctx, ErrPrecheck)
	}
	return nil
}

func (runtime *OpenRestyRuntime) Activate(ctx context.Context, release string) error {
	if runtime == nil || ctx == nil || !cleanAbsolutePath(release) {
		return ErrActivate
	}
	if err := runtime.run(ctx, runtime.binary, "-t", "-p", withOpenRestySlash(runtime.runtimePrefix), "-c", runtime.configFile); err != nil {
		return sanitizedOpenRestyError(ctx, ErrPrecheck)
	}
	if err := runtime.run(ctx, runtime.binary, "-s", "reload", "-p", withOpenRestySlash(runtime.runtimePrefix), "-c", runtime.configFile); err != nil {
		return sanitizedOpenRestyError(ctx, ErrActivate)
	}
	return nil
}

func (runtime *OpenRestyRuntime) Health(ctx context.Context, _ string, artifact Artifact) error {
	if runtime == nil || ctx == nil || artifact.Revision == 0 || !validDigest(artifact.Digest) {
		return ErrHealth
	}
	if err := runtime.probe(ctx, artifact); err != nil {
		return sanitizedOpenRestyError(ctx, ErrHealth)
	}
	return nil
}

func (runtime *OpenRestyRuntime) Stop(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrActivate
	}
	if err := runtime.run(ctx, runtime.binary, "-t", "-p", withOpenRestySlash(runtime.runtimePrefix), "-c", runtime.configFile); err != nil {
		return sanitizedOpenRestyError(ctx, ErrPrecheck)
	}
	if err := runtime.run(ctx, runtime.binary, "-s", "reload", "-p", withOpenRestySlash(runtime.runtimePrefix), "-c", runtime.configFile); err != nil {
		return sanitizedOpenRestyError(ctx, ErrActivate)
	}
	return nil
}

func OpenRestyIncludes(policyPath, handlerPath, siteID string) (string, string, error) {
	parsedSiteID, siteErr := uuidParseCanonical(siteID)
	if !cleanDirectiveAbsolutePath(policyPath) || !cleanDirectiveAbsolutePath(handlerPath) || siteErr != nil || parsedSiteID == "" {
		return "", "", ErrInvalidPolicy
	}
	httpInclude := "init_by_lua_block {\n" +
		"  local ok, policy = pcall(dofile, " + strconv.Quote(policyPath) + ")\n" +
		"  if ok and type(policy) == 'table' and type(policy.bindings) == 'table' and type(policy.resources) == 'table' then\n" +
		"    cdnca_error_policy = policy\n" +
		"  else\n" +
		"    cdnca_error_policy = nil\n" +
		"  end\n" +
		"}\n"
	var codes strings.Builder
	for status := 400; status <= 599; status++ {
		if status > 400 {
			codes.WriteByte(' ')
		}
		codes.WriteString(strconv.Itoa(status))
	}
	siteInclude := "set $cdnca_error_status 500;\n" +
		"set $cdnca_error_category origin_response;\n" +
		"set $cdnca_error_site " + strconv.Quote(siteID) + ";\n" +
		"proxy_intercept_errors on;\n" +
		"error_page " + codes.String() + " = @cdnca_error_page;\n" +
		"location @cdnca_error_page {\n" +
		"  internal;\n" +
		"  set $cdnca_error_status $status;\n" +
		"  content_by_lua_file " + handlerPath + ";\n" +
		"}\n"
	return httpInclude, siteInclude, nil
}

func uuidParseCanonical(value string) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", ErrInvalidPolicy
	}
	return parsed.String(), nil
}

func runOpenRestyCommand(ctx context.Context, binary string, arguments ...string) error {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func sanitizedOpenRestyError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

func withOpenRestySlash(path string) string { return path + string(filepath.Separator) }

func cleanExecutablePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func cleanDirectiveAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n\"'`;{}")
}

var _ Runtime = (*OpenRestyRuntime)(nil)
