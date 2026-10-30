package edgeconfig

// FX60/NF38 block pages. A request the node answers itself with a block page
// (WAF / bound security rule 403, CC v2 ban, 429, challenge page) sets
// BlockPageVariable to "1"; the access log carries it as "blocked":true and the
// control plane drops such requests from package traffic when
// block_page_not_counted is on.
//
// edge/openresty/ccv2/engine.lua runs MarkBlockPageLua (block_exit) before
// every ngx.exit it answers itself (reject429, state_failure, temporary_ban,
// send_page challenges, challenge redirects, the 403/405/503 exits); the
// variable is declared for every telemetry server.
const (
	BlockPageVariable = "cdnca_security_block_page"
	MarkBlockPageLua  = "ngx.var." + BlockPageVariable + ` = "1"`
)
