package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// marketPluginChecks (ML-25, ADR 0012 §20, U14): a market tenant's site
// mounts a free official pack (system/bot-bad-ua: base protection) and a
// paid one (system/waf-sensitive-file, standing for a pack whose catalog
// entry requires a plugin). With the supply not including that plugin the
// control plane publishes the site with the paid mount withheld
// (rulepack.Withhold, the function edgepublish uses): the node accepts the
// reduced document, the site keeps serving, the base pack still refuses a
// bad bot while the paid pack's probe reaches the origin. The plugin back
// restores the full mounts and the probe is refused again.
func marketPluginChecks(h *harness, packs *rulePackFixture, sites []edgesite.Site) {
	block, _ := json.Marshal("block")
	full, err := packs.officialPackSecurity(*official, map[string]rulepack.Params{
		"system-bot-bad-ua": {"action": block}, "system-waf-sensitive-file": {"action": block}})
	check("market-plugins-fixture", err == nil, "%v", err)
	if err != nil {
		return
	}
	compiled := map[string]*rulepack.CompiledPack{}
	for _, name := range []string{"system-bot-bad-ua", "system-waf-sensitive-file"} {
		text, err := os.ReadFile(filepath.Join(*official, name+".json"))
		if err == nil {
			var pack *rulepack.CompiledPack
			if pack, err = rulepack.Compile(text); err == nil {
				compiled[pack.SHA256] = pack
			}
		}
		if err != nil {
			check("market-plugins-fixture", false, "%s: %v", name, err)
			return
		}
	}
	lib := rulepack.Security{ResolvedSHA256: full.ResolvedSHA256}
	raw, _ := json.Marshal(full.Mounts)
	if err := json.Unmarshal(raw, &lib.Mounts); err != nil {
		check("market-plugins-fixture", false, "%v", err)
		return
	}
	reduced, withheld, err := rulepack.Withhold(lib, compiled, func(mount rulepack.Mount) bool {
		return mount.PackID == "system/waf-sensitive-file"
	})
	check("market-plugins-withhold", err == nil && withheld && len(reduced.Mounts) == 1 &&
		reduced.ResolvedSHA256 != full.ResolvedSHA256, "%+v %t %v", reduced.Mounts, withheld, err)
	if err != nil || !withheld {
		return
	}
	var base edgesite.Security
	raw, _ = json.Marshal(reduced)
	if err := json.Unmarshal(raw, &base); err != nil {
		check("market-plugins-withhold", false, "%v", err)
		return
	}

	const host = "market.d13.test"
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	bot := "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
	run := func(name string, revision int64, security edgesite.Security) (page, probe, badBot int) {
		site := withMounts(makeSite(23, host, revision, portPlain), security)
		h.apply(name, append(append([]edgesite.Site(nil), sites...), site)...)
		return getUA(portPlain, host, "/index.html", browser).status, getUA(portPlain, host, "/backup.sql", browser).status,
			getUA(portPlain, host, "/index.html", bot).status
	}
	page, probe, badBot := run("market-plugins-full-apply", 1, full)
	check("market-plugins-full", page == 200 && probe == 403 && badBot == 403,
		"page %d /backup.sql %d bad bot %d", page, probe, badBot)
	page, probe, badBot = run("market-plugins-base-apply", 2, base)
	check("market-plugins-base-only", page == 200 && probe != 403 && badBot == 403,
		"page %d /backup.sql %d (want served) bad bot %d", page, probe, badBot)
	page, probe, badBot = run("market-plugins-restored-apply", 3, full)
	check("market-plugins-restored", page == 200 && probe == 403 && badBot == 403,
		"page %d /backup.sql %d bad bot %d", page, probe, badBot)
}
