package edgeconfig

import (
	"os"
	"strings"
	"testing"
)

// CC v2 引擎自己应答的每个出口都要先打拦截页标记：除 block_exit 本身外不允许直接 ngx.exit。
func TestCCv2EngineTagsEveryExit(t *testing.T) {
	raw, err := os.ReadFile("../../edge/openresty/ccv2/engine.lua")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	// The variable is configurable (dynamic routing writes
	// cdnca_security_block_page); its default is the v7 renderer's.
	helper := "local function block_exit(status)\n    pcall(function() ngx.var[vars.block_page] = \"1\" end)\n    return ngx.exit(status)\nend\n"
	if strings.Count(source, helper) != 1 || !strings.Contains(source, "block_page = \""+BlockPageVariable+"\"") {
		t.Fatal("engine.lua must define block_exit tagging the block page variable (default " + BlockPageVariable + ")")
	}
	if rest := strings.Replace(source, helper, "", 1); strings.Contains(rest, "ngx.exit(") {
		t.Fatal("engine.lua must exit through block_exit")
	}
	if strings.Count(source, "block_exit(") < 2 {
		t.Fatal("engine.lua has no block_exit call sites")
	}
}
