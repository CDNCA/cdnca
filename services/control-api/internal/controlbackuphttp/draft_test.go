package controlbackuphttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"golang.org/x/crypto/ssh"
)

func sftpTarget(extra string) string {
	return `{"name":"nas","kind":"sftp","enabled":true,"host":"nas.example.test","port":22,"username":"backup",
	  "remote_dir":"/srv/cdnca","host_key_sha256":"SHA256:` + strings.Repeat("Q", 43) + `"` + extra + `}`
}

func saveSFTP(t *testing.T, h *harness, extra string) {
	t.Helper()
	body := `{"expected_revision":"` + h.revision() + `","schedule":{"enabled":false,"weekdays":[1],"hour":3,"minute":0},
	  "keep_local":5,"keep_remote":5,"targets":[` + sftpTarget(extra) + `]}`
	if got := h.do(http.MethodPut, Prefix+"/settings", body); got.Code != http.StatusOK {
		t.Fatalf("save = %d %s", got.Code, got.Body)
	}
}

func refusal(t *testing.T, got interface{ Result() *http.Response }, body []byte) (code, field string) {
	t.Helper()
	var envelope struct {
		Error struct {
			Code    string            `json:"code"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	return envelope.Error.Code, envelope.Error.Details["field"]
}

func newPrivateKey(t *testing.T) string {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// A02: 测试连接 probes the target as it is on screen (an edited one merged over
// the stored settings at the console's revision), not the saved row, and
// saves nothing. A03 (same class): switching the SFTP auth needs a matching
// new credential; save and probe refuse alike.
func TestProbeTestsTheDraftAndAuthSwitchNeedsNewCredential(t *testing.T) {
	h := newHarness(t)
	var probed []nativebackup.Target
	h.handler.dependencies.Probe = func(_ context.Context, target nativebackup.Target) error {
		probed = append(probed, target)
		return errors.New("recorded")
	}
	saveSFTP(t, h, `,"password":"old-ssh-password"`)
	before, _ := nativebackup.LoadSettings(h.layout)
	probe := func(target string) (int, string) {
		got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":`+target+`}`)
		return got.Code, got.Body.String()
	}

	// New, unsaved target: probed as given; it never inherits the stored secret of a same-named target.
	if code, body := probe(strings.Replace(sftpTarget(`,"password":"draft-password"`), "nas.example.test", "new.example.test", 1)); code != http.StatusOK {
		t.Fatalf("new draft = %d %s", code, body)
	}
	if code, body := probe(sftpTarget(``)); code != http.StatusBadRequest {
		t.Fatalf("new draft without credential = %d %s", code, body)
	}
	// Edited target: the draft host/dir with the stored password.
	edited := strings.Replace(strings.Replace(sftpTarget(`,"auth":"password"`), "nas.example.test", "nas2.example.test", 1), "/srv/cdnca", "/srv/edited", 1)
	edited = strings.Replace(edited, `{"name"`, `{"stored_name":"nas","name"`, 1)
	if code, body := probe(edited); code != http.StatusOK {
		t.Fatalf("edited draft = %d %s", code, body)
	}
	last := probed[len(probed)-1]
	if len(probed) != 2 || probed[0].Host != "new.example.test" || probed[0].Password != "draft-password" ||
		last.Host != "nas2.example.test" || last.RemoteDir != "/srv/edited" || last.Password != "old-ssh-password" {
		t.Fatalf("probed %+v", probed)
	}
	if after, _ := nativebackup.LoadSettings(h.layout); after.Targets[0].Host != before.Targets[0].Host {
		t.Fatal("a probe changed the saved settings")
	}
	if got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"stale","target":`+edited+`}`); got.Code != http.StatusConflict {
		t.Fatalf("stale probe = %d %s", got.Code, got.Body)
	}

	// password → private_key: no / invalid key refused by probe and save; nothing probed.
	privateKey := newPrivateKey(t)
	encodedKey, _ := json.Marshal(privateKey)
	for _, test := range []struct{ extra, code string }{
		{`,"auth":"private_key"`, "control_backup_auth_changed"},
		{`,"auth":"private_key","private_key":""`, "control_backup_auth_changed"},
		{`,"auth":"private_key","private_key":"not a key"`, "control_backup_invalid_private_key"},
		{`,"auth":"private_key","password":"old-ssh-password"`, "control_backup_invalid_settings"},
	} {
		target := strings.Replace(sftpTarget(test.extra), `{"name"`, `{"stored_name":"nas","name"`, 1)
		count := len(probed)
		got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":`+target+`}`)
		if code, field := refusal(t, got, got.Body.Bytes()); got.Code != http.StatusBadRequest || code != test.code || field != "private_key" || len(probed) != count {
			t.Fatalf("probe %s = %d %s", test.extra, got.Code, got.Body)
		}
		save := h.do(http.MethodPut, Prefix+"/settings", `{"expected_revision":"`+h.revision()+`","schedule":{"enabled":false,"weekdays":[1],"hour":3,"minute":0},
		  "keep_local":5,"keep_remote":5,"targets":[`+target+`]}`)
		if code, field := refusal(t, save, save.Body.Bytes()); save.Code != http.StatusBadRequest || code != test.code || field != "private_key" {
			t.Fatalf("save %s = %d %s", test.extra, save.Code, save.Body)
		}
	}
	// A valid new key passes; then private_key → password needs a password, not a key.
	saveSFTP(t, h, `,"stored_name":"nas","auth":"private_key","private_key":`+string(encodedKey))
	if stored, _ := nativebackup.LoadSettings(h.layout); stored.Targets[0].PrivateKey != privateKey || stored.Targets[0].Password != "" {
		t.Fatalf("switched target %+v", stored.Targets[0].Host)
	}
	for _, test := range []struct{ extra, code string }{
		{`,"auth":"password"`, "control_backup_auth_changed"},
		{`,"auth":"password","password":` + string(encodedKey), "control_backup_invalid_password"},
	} {
		target := strings.Replace(sftpTarget(test.extra), `{"name"`, `{"stored_name":"nas","name"`, 1)
		got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":`+target+`}`)
		if code, field := refusal(t, got, got.Body.Bytes()); got.Code != http.StatusBadRequest || code != test.code || field != "password" {
			t.Fatalf("probe back %s = %d %s", test.extra, got.Code, got.Body)
		}
	}
	saveSFTP(t, h, `,"stored_name":"nas","auth":"password","password":"new-ssh-password"`)
}

// X08 (same class): a malformed S3 endpoint is refused by probe and save with
// the target and field named, before any connection.
func TestS3EndpointRefusalNamesTheField(t *testing.T) {
	h := newHarness(t)
	probed := 0
	h.handler.dependencies.Probe = func(context.Context, nativebackup.Target) error { probed++; return nil }
	s3 := func(endpoint string) string {
		return `{"name":"rustfs","kind":"s3","enabled":true,"endpoint":"` + endpoint + `","region":"us-east-1","bucket":"cdnca-backups",
		  "prefix":"cdnca/","access_key":"AKIA1","secret_key":"secret-1"}`
	}
	for _, endpoint := range []string{"https://", "rustfs.internal:9000", "ftp://rustfs.internal", "http://rustfs.internal:9000", "https://rustfs.internal/x"} {
		got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":`+s3(endpoint)+`}`)
		if code, field := refusal(t, got, got.Body.Bytes()); got.Code != http.StatusBadRequest || code != "control_backup_invalid_endpoint" || field != "endpoint" {
			t.Fatalf("probe %q = %d %s", endpoint, got.Code, got.Body)
		}
		save := h.do(http.MethodPut, Prefix+"/settings", `{"expected_revision":"`+h.revision()+`","schedule":{"enabled":false,"weekdays":[1],"hour":3,"minute":0},
		  "keep_local":5,"keep_remote":5,"targets":[`+s3(endpoint)+`]}`)
		if code, field := refusal(t, save, save.Body.Bytes()); save.Code != http.StatusBadRequest || code != "control_backup_invalid_endpoint" || field != "endpoint" {
			t.Fatalf("save %q = %d %s", endpoint, save.Code, save.Body)
		}
	}
	if probed != 0 {
		t.Fatalf("probed %d malformed targets", probed)
	}
	got := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":`+s3("https://rustfs.internal:9000")+`}`)
	if got.Code != http.StatusOK || probed != 1 {
		t.Fatalf("valid probe = %d %s probed=%d", got.Code, got.Body, probed)
	}
}
