package rulepack

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// crsApps are the OWASP CRS official rule exclusion plugins
// (coreruleset/plugin-registry, status tested, Apache-2.0) pinned in
// testdata/crs-apps/upstream/PINS.txt: key, display name, registered ID
// range start.
var crsApps = []struct {
	key, name, description string
	first                  int
}{
	{"cpanel", "cPanel", "cPanel/WHM 面板", 9510000},
	{"dokuwiki", "DokuWiki", "DokuWiki 维基", 9509000},
	{"drupal", "Drupal", "Drupal 内容管理系统", 9506000},
	{"nextcloud", "Nextcloud", "Nextcloud 网盘（含 WebDAV/CalDAV/CardDAV）", 9508000},
	{"phpbb", "phpBB", "phpBB 论坛", 9512000},
	{"phpmyadmin", "phpMyAdmin", "phpMyAdmin 数据库管理", 9513000},
	{"wordpress", "WordPress", "WordPress（原版，不含第三方插件）", 9507000},
	{"xenforo", "XenForo", "XenForo 论坛", 9511000},
}

const crsAppGoldenDir = "testdata/crs-apps"

type crsAppPin struct{ tag, commit, sha256 string }

// crsAppPins reads PINS.txt: "<key> <tag> <commit> <file> <sha256>".
func crsAppPins(t *testing.T) map[string]crsAppPin {
	t.Helper()
	file, err := os.Open(filepath.Join(crsAppGoldenDir, "upstream", "PINS.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pins := map[string]crsAppPin{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 5 {
			t.Fatalf("PINS.txt line %q", scanner.Text())
		}
		pins[fields[0]+"/"+fields[3]] = crsAppPin{tag: fields[1], commit: fields[2], sha256: fields[4]}
	}
	return pins
}

// buildCRSAppPack converts one pinned plugin: its config and before files
// verbatim (a config file of only comments is left out); the after file
// (phpMyAdmin: configuration-time SecRuleUpdateTargetById, node-wide) is not
// carried.
func buildCRSAppPack(t *testing.T, pins map[string]crsAppPin, index int) Pack {
	t.Helper()
	app := crsApps[index]
	pack := Pack{Schema: Schema, PackID: "system/app-" + app.key, Layer: LayerSystem, Engine: EngineCRSApp,
		EngineMinVersion: 1, Name: app.name, LicenseSPDX: "Apache-2.0", ParamsSchema: map[string]ParamSpec{},
		Exports: []string{}, Defaults: Params{}}
	mapped := false
	for _, stage := range []string{CRSAppStageConfig, CRSAppStageBefore} {
		name := app.key + "-rule-exclusions-" + stage + ".conf"
		pin, ok := pins[app.key+"/"+name]
		if !ok {
			t.Fatalf("%s is not pinned", name)
		}
		content, err := os.ReadFile(filepath.Join(crsAppGoldenDir, "upstream", app.key, name))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(content); hex.EncodeToString(sum[:]) != pin.sha256 {
			t.Fatalf("%s sha256 does not match pinned %s", name, pin.sha256)
		}
		pack.Version = strings.TrimPrefix(pin.tag, "v")
		pack.Description = "OWASP CRS 官方应用排除插件 " + app.key + "-rule-exclusions-plugin " + pin.tag +
			"（提交 " + pin.commit[:12] + "）：适配" + app.description + "的已知误报，只放宽该应用的特定路径与参数；仅对选择了此应用类型的网站生效"
		directives, err := crsAppDirectives(string(content))
		if err != nil {
			t.Fatal(err)
		}
		if len(directives) == 0 {
			continue
		}
		// The only change to the upstream text: libmodsecurity's recommended
		// request body rules are the node's (CRSAppParserRuleIDs).
		text := string(content)
		for upstream, node := range CRSAppParserRuleIDs {
			text = strings.ReplaceAll(text, "ctl:ruleRemoveById="+strconv.Itoa(upstream)+",", "ctl:ruleRemoveById="+strconv.Itoa(node)+",")
			text = strings.ReplaceAll(text, "ctl:ruleRemoveById="+strconv.Itoa(upstream)+"\"", "ctl:ruleRemoveById="+strconv.Itoa(node)+"\"")
		}
		if text != string(content) {
			mapped = true
		}
		pack.Rules = append(pack.Rules, Rule{ID: stage, Name: app.name + " " + stage,
			App: &CRSAppRules{Stage: stage, FirstID: app.first, LastID: app.first + 999, Text: text}})
	}
	if mapped {
		pack.Description += "；原文中 libmodsecurity 请求体规则 200002/200003/200004/200007 改为本节点对应规则 10001/10004/10005/10003"
	}
	return pack
}

// TestCRSAppPacksMatchGenerator converts the pinned plugins and requires the
// golden packs to be exactly their canonical bytes (-update rewrites).
func TestCRSAppPacksMatchGenerator(t *testing.T) {
	pins := crsAppPins(t)
	for index, app := range crsApps {
		compiled, err := CompilePack(buildCRSAppPack(t, pins, index))
		if err != nil {
			t.Fatalf("%s: %v", app.key, err)
		}
		path := filepath.Join(crsAppGoldenDir, "app-"+app.key+".json")
		if *updateGolden {
			if err := os.WriteFile(path, compiled.Canonical, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		golden, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(golden, compiled.Canonical) {
			t.Fatalf("%s is stale; rerun with -update", path)
		}
		_, loaded, err := LoadCRSApp(golden, compiled.SHA256)
		if err != nil || loaded.Key != app.key || loaded.FirstID != app.first || loaded.Before == "" {
			t.Fatalf("%s: load %v %+v", app.key, err, loaded.Ref)
		}
		if IsCRSProfilePack(compiled.Pack.PackID) || !IsCRSAppPack(compiled.Pack.PackID) {
			t.Fatalf("%s: pack id namespace", app.key)
		}
	}
}

func TestCRSAppTextRefusesWideningDirectives(t *testing.T) {
	ok := `SecRule REQUEST_FILENAME "@endsWith /wp-login.php" "id:9507100,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942430;ARGS:redirect_to"`
	if _, err := ValidateCRSAppText(ok, 9507000, 9507999); err != nil {
		t.Fatalf("narrow exclusion refused: %v", err)
	}
	for name, text := range map[string]string{
		"engine off":       `SecAction "id:9507100,phase:1,pass,nolog,ctl:ruleEngine=Off"`,
		"allow":            `SecRule REQUEST_URI "@rx ." "id:9507100,phase:1,allow,nolog"`,
		"deny":             `SecRule REQUEST_URI "@rx ." "id:9507100,phase:1,deny,status:403"`,
		"out of range id":  `SecAction "id:9506100,phase:1,pass,nolog"`,
		"remove own rules": `SecAction "id:9507100,phase:1,pass,nolog,ctl:ruleRemoveById=10000-10999"`,
		"engine directive": `SecRuleEngine Off`,
		"remove by id":     `SecRuleRemoveById 942100`,
		"update target":    `SecRuleUpdateTargetById 942200 "!REQUEST_COOKIES"`,
		"include":          `Include /etc/passwd`,
		"exec":             `SecRule REQUEST_URI "@rx ." "id:9507100,phase:1,pass,exec:/bin/sh"`,
		"pm from file":     `SecRule REQUEST_URI "@pmFromFile x.data" "id:9507100,phase:1,pass,nolog"`,
		"setvar score":     `SecAction "id:9507100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=10000"`,
		"setvar paranoia":  `SecAction "id:9507100,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=0"`,
		"cdnca tx":         `SecAction "id:9507100,phase:1,pass,nolog,setvar:tx.cdnca_sqli_mode=off"`,
		"dangling":         "SecAction \"id:9507100,phase:1,pass,nolog\" \\",
		"skip unknown":     `SecAction "id:9507100,phase:1,pass,nolog,skipAfter:CDNCA-EX-9421"`,
		"no pass":          `SecAction "id:9507100,phase:1,nolog"`,
		"phase 5":          `SecAction "id:9507100,phase:5,pass,nolog"`,
	} {
		if _, err := ValidateCRSAppText(text, 9507000, 9507999); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
