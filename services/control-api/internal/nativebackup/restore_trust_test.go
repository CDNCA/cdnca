package nativebackup

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// 主控声明兼容 Rocky/AlmaLinux/RHEL 8–10：对象存储 CA 锚点在 /etc/pki/ca-trust，
// 信任库用 update-ca-trust extract 重建（install-rustfs.py trust_layout）。
// 恢复必须按备份里实际带的锚点选命令，不能固定调用 Debian 的 update-ca-certificates。
func TestRestoreRebuildsTrustStoreOfTheArchivedAnchor(t *testing.T) {
	for _, family := range []struct {
		name, anchor, tool, call string
	}{
		{"debian", "/usr/local/share/ca-certificates/cdnca-objectstore.crt", "/usr/sbin/update-ca-certificates", "/usr/sbin/update-ca-certificates "},
		{"rhel", "/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt", "/usr/bin/update-ca-trust", "/usr/bin/update-ca-trust extract"},
	} {
		t.Run(family.name, func(t *testing.T) {
			if !slices.ContainsFunc(configPaths, func(path treePath) bool { return path.Path == family.anchor }) {
				t.Fatalf("config component does not archive %s", family.anchor)
			}
			rig := newRig(t)
			rig.details = map[ComponentName]map[string]string{ComponentConfig: {"paths": "/etc/cdnca-control," + family.anchor}}
			bundle := rig.backupBundle()
			_ = os.Remove(rig.host.Layout.Path("/usr/sbin/update-ca-certificates"))
			writeFile(t, rig.host.Layout.Path(family.tool))
			writeFile(t, rig.host.Layout.Path(family.anchor)) // what the config component restored
			executor := &fakeExecutor{}
			rig.host.Exec = executor
			if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err != nil {
				t.Fatal(err)
			}
			var trust []string
			for _, call := range executor.calls {
				if strings.Contains(call, "update-ca") {
					trust = append(trust, call)
				}
			}
			if len(trust) != 1 || trust[0] != family.call {
				t.Fatalf("trust store calls = %q, want %q", trust, family.call)
			}
		})
	}
}

// 跨发行版族恢复（Debian 备份恢复到 RHEL 或反过来）在任何改动前拒绝：
// 锚点目录、clamd 套接字、PostgreSQL 布局都不同。
func TestRestoreRefusesAnchorOfAnotherOSFamily(t *testing.T) {
	rig := newRig(t)
	rig.details = map[ComponentName]map[string]string{ComponentConfig: {"paths": "/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt"}}
	bundle := rig.backupBundle() // the rig target is Debian
	_, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity})
	if err == nil || !strings.Contains(err.Error(), "restore_target_os_family_mismatch") {
		t.Fatalf("err = %v", err)
	}
	for _, entry := range rig.journal {
		if strings.HasPrefix(entry, "restore ") {
			t.Fatalf("restored before refusing: %v", rig.journal)
		}
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}
