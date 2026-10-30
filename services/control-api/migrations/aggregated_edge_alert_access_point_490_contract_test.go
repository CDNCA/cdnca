package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 490: the aggregated-edge schedule alert e-mail
// template body says 「接入点」 instead of 「供给」. Only that one template row
// changes; migration 420 stays byte-for-byte as released.
const (
	migration490Version         = 490
	migration490PreviousVersion = 489
	migration490ID              = "490_aggregated_edge_alert_access_point"
	migration490PreviousID      = "489_installation_ban_node_ticket"
	migration490PreviousUpSHA   = "355e03eb8e87828a78801d2c4cbc17abcc654aeba92f78f62e147ba5177947da"
	migration490PreviousDownSHA = "a35456bba9f7bd3429b7c4872dfa006725cd3464505a6b5d474e12197aed8200"
	migration490UpSHA           = "309e8d8dcea2473d3be5c88448c7fbb8f3b7f1e7b08750db41142a7e7966b48d"
	migration490DownSHA         = "12ed9a7ef6d47a8214dcbd8d286266a06670d4262ce44ab18b058cac8484a6eb"

	migration490OldBody = "站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个供给或保持当前指向（冻结时可解冻并切换或保持冻结）。"
	migration490NewBody = "站点 {{.site_domain}} 的线路 {{.line}}：{{.alert_text}}。源站状态：{{.origin}}。请打开调度页 {{.link}} 选择切到某个接入点或保持当前指向（冻结时可解冻并切换或保持冻结）。"
	migration490Where   = "WHERE template_id='aggregated_edge.schedule.alert.zh-cn' AND version=1 AND channel='email' AND"
)

func TestAggregatedEdgeAlertAccessPoint490Contract(t *testing.T) {
	read := func(name string) string {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, script := range []struct {
		name, sha string
		from, to  string
		required  []string
	}{
		{migration490ID + ".up.sql", migration490UpSHA, migration490OldBody, migration490NewBody, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration490PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration490PreviousVersion),
			"migration_id='" + migration490PreviousID + "'", migration490PreviousUpSHA, migration490PreviousDownSHA,
			"ERRCODE='P4900'",
		}},
		{migration490ID + ".down.sql", migration490DownSHA, migration490NewBody, migration490OldBody, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration490Version),
			"migration_id='" + migration490ID + "'", "ERRCODE='P4901'",
		}},
	} {
		body := read(script.name)
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(body))); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		// UPDATE 只命中这一行模板，且只在正文仍是另一版原文时才改；改完立即恢复不可变触发器。
		update := "UPDATE notification_templates\nSET body='" + script.to + "'\n" + migration490Where + "\n    body='" + script.from + "';"
		required := append(script.required, update,
			"ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;",
			"ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;")
		for _, want := range required {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", script.name, want)
			}
		}
		if strings.Count(body, "UPDATE ") != 1 || strings.Contains(body, "INSERT ") || strings.Contains(body, "DELETE ") {
			t.Errorf("%s must only update the one template body", script.name)
		}
		if strings.Index(body, "ENABLE TRIGGER") < strings.Index(body, "UPDATE notification_templates") {
			t.Errorf("%s re-enables the immutability trigger before the update", script.name)
		}
	}
	// 历史迁移 420 原文不动；新正文只差「供给」→「接入点」一处。
	if !strings.Contains(read("420_aggregated_edge_fixed.up.sql"), "'"+migration490OldBody+"'") {
		t.Error("420 must keep the released template body")
	}
	if strings.Replace(migration490OldBody, "供给", "接入点", 1) != migration490NewBody || strings.Contains(migration490NewBody, "供给") {
		t.Error("490 must only replace 供给 with 接入点")
	}
}
