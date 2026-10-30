package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/evalreport"
)

// -gate-std：fast 只取 waf-comparison 的 --fast 样本，full 取全部；报告记文件摘要与条数。
func TestGateStdSource(t *testing.T) {
	dir := t.TempDir()
	write := func(name, lines string) {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		_, _ = writer.Write([]byte(lines))
		_ = writer.Close()
		if err := os.WriteFile(filepath.Join(dir, name+".jsonl.gz"), buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("wafcomp-mal", `{"id":"m1","method":"GET","uri":"/?a=1","attack":true,"fast":true}`+"\n"+`{"id":"m2","method":"GET","uri":"/","attack":true}`+"\n")
	write("wafcomp-legit", `{"id":"l1","method":"POST","uri":"/","data":"é","latin1":true,"fast":true}`+"\n")
	saved := *stdDir
	*stdDir = dir
	defer func() { *stdDir = saved }()
	fast, err := gateStdSource(evalreport.StdFast)
	if err != nil || fast.Files[0].Requests != 1 || fast.Files[1].Requests != 1 || len(fast.Files[0].SHA256) != 64 {
		t.Fatalf("fast %+v %v", fast, err)
	}
	full, err := gateStdSource(evalreport.StdFull)
	if err != nil || full.Files[0].Requests != 2 || full.Files[0].SHA256 != fast.Files[0].SHA256 {
		t.Fatalf("full %+v %v", full, err)
	}
	var ids []string
	_ = gateStdScan("wafcomp-legit", evalreport.StdFast, func(request stdRequest) {
		data, _ := stdWire(request)
		if data != "\xe9" {
			t.Fatalf("latin1 body %q", data)
		}
		ids = append(ids, request.ID)
	})
	if len(ids) != 1 {
		t.Fatalf("ids %v", ids)
	}
	if _, err := gateStdSource("half"); err == nil {
		t.Fatal("bad mode accepted")
	}
}
