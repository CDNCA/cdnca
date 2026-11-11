package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
)

// checkPurgeReinstall: a managed WAF
// node is purged and reinstalled. uninstall --purge removed the WAF engine
// extension (/var/lib/cdnca-edge) but, before the fix, kept the dynamic
// routing state; the new agent's Recover started OpenResty from the old
// nginx.conf, whose load_module names the removed module, and the agent
// exited on every start. Here: the old configuration really fails on this
// OpenResty (dlopen), Recover sets it aside instead and returns, and once the
// engine is installed again the next publication serves and blocks.
// It returns the runtime that runs afterwards and its shared root (where its
// error.log is).
func checkPurgeReinstall(h *harness, config dynroute.Config, previous *dynroute.Runtime, input dynroute.Input) (*dynroute.Runtime, string) {
	ctx := h.ctx
	_ = previous.Stop(ctx)
	root := filepath.Join(*state, "purge-reinstall")
	engine := filepath.Join(root, "waf-crs")
	if err := copyTree(*modSecurity, engine); err != nil {
		check("purge-reinstall-engine", false, "%v", err)
		return previous, config.SharedRoot
	}
	nodeConfig := config
	nodeConfig.StateRoot, nodeConfig.SharedRoot = filepath.Join(root, "node"), filepath.Join(root, "shared")
	nodeConfig.WAFEngine = func() (*dynwaf.Engine, error) {
		return &dynwaf.Engine{ModulePath: filepath.Join(engine, "modules", "ngx_http_modsecurity_module.so"),
			UnicodeMapPath: filepath.Join(engine, "unicode.mapping")}, nil
	}
	pl1 := profileNamed(input.Profiles, "system/crs-pl1")
	sites := objects(makeSite(1, "shop.d13.test", 1, portPlain), withWAF(makeSite(5, "waf.d13.test", 1, portPlain), pl1))
	input.Objects = sites
	nodePID := func() string {
		raw, _ := os.ReadFile(filepath.Join(nodeConfig.SharedRoot, "nginx.pid"))
		return strings.TrimSpace(string(raw))
	}

	installed, err := dynroute.New(nodeConfig)
	if err == nil {
		_, err = installed.Apply(ctx, input)
	}
	a, b := get(portPlain, "waf.d13.test", sqli), get(portPlain, "shop.d13.test", "/index.html")
	check("purge-reinstall-before", err == nil && a.status == 403 && b.status == 200, "attack %d shop %d %v", a.status, b.status, err)
	if err != nil {
		return previous, config.SharedRoot
	}

	// uninstall --purge as before the fix: OpenResty stopped, the engine
	// extension removed, the dynamic routing state left behind
	_ = installed.Stop(ctx)
	if err := os.Rename(engine, engine+".purged"); err != nil {
		check("purge-reinstall-purge", false, "%v", err)
		return previous, config.SharedRoot
	}
	conf := filepath.Join(nodeConfig.SharedRoot, "nginx.conf")
	output, oldErr := exec.CommandContext(ctx, nodeConfig.OpenResty, "-p", nodeConfig.SharedRoot+"/", "-c", conf, "-t").CombinedOutput()
	check("purge-reinstall-old-config-fails", oldErr != nil && strings.Contains(string(output), "ngx_http_modsecurity_module.so"),
		"nginx -t on the left-behind configuration: %v %.200s", oldErr, output)

	// the reinstalled agent starts: Recover must not fail
	reinstalled, err := dynroute.New(nodeConfig)
	if err == nil {
		err = reinstalled.Recover(ctx)
	}
	_, staleErr := os.Stat(conf + ".stale")
	check("purge-reinstall-recover", err == nil && nodePID() == "" && !reinstalled.Applied() && staleErr == nil,
		"recover %v master %q applied %v stale kept %v", err, nodePID(), reinstalled.Applied(), staleErr)
	if err != nil {
		return previous, config.SharedRoot
	}

	// the new install brings the engine back; the next publication is applied
	// as on a node never applied
	if err := os.Rename(engine+".purged", engine); err != nil {
		check("purge-reinstall-engine-back", false, "%v", err)
		return previous, config.SharedRoot
	}
	result, err := reinstalled.Apply(ctx, input)
	a, b = get(portPlain, "waf.d13.test", sqli), get(portPlain, "shop.d13.test", "/index.html")
	check("purge-reinstall-publication", err == nil && result.Started && a.status == 403 && b.status == 200 && nodePID() != "",
		"started %v attack %d shop %d master %q %v", result.Started, a.status, b.status, nodePID(), err)
	return reinstalled, nodeConfig.SharedRoot
}
