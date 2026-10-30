//go:build !windows

package controlplaneupgrade

import "testing"

// 卡 41：随包的 root 恢复手册是升级可新增/更新的单个归属文件；其他 docs 路径仍按普通文件不得改动。
func TestNativeRecoveryRunbookIsSingleOwnedFile(t *testing.T) {
	manifest := func(extra map[string][]byte) NativeManifest {
		files := map[string][]byte{"bin/control-api": nativeELF("c"), "bin/agent-gateway": nativeELF("g"),
			"static/web/index.html": []byte("<html></html>"), "migrations/001_base.up.sql": []byte("SELECT 1;"),
			"migrations/001_base.down.sql": []byte("SELECT 1;")}
		for name, content := range extra {
			files[name] = content
		}
		value, _ := nativeManifestFixture()
		value.Files = nativeFilesForTest(files)
		return value
	}
	plain := manifest(nil)
	withRunbook := manifest(map[string][]byte{"docs/platform-admin-recovery.md": []byte("# v1\n")})
	for name, test := range map[string]struct {
		current, candidate NativeManifest
		accepted           bool
	}{
		"introduced":           {plain, withRunbook, true},
		"updated":              {withRunbook, manifest(map[string][]byte{"docs/platform-admin-recovery.md": []byte("# v2\n")}), true},
		"removed":              {withRunbook, plain, false},
		"other doc added":      {plain, manifest(map[string][]byte{"docs/other.md": []byte("# x\n")}), false},
		"other doc next to it": {withRunbook, manifest(map[string][]byte{"docs/platform-admin-recovery.md": []byte("# v1\n"), "docs/platform-admin-recovery.md.bak": []byte("x")}), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nativeCompatibleFiles(test.current, test.candidate); got != test.accepted {
				t.Fatalf("accepted=%v want %v", got, test.accepted)
			}
		})
	}
}
