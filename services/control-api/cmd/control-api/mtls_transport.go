package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
)

// mTLS 出站拨号方式（协议 T1）：<组件>_MTLS_TRANSPORT=direct|tunnel，默认 tunnel——
// 经 wss://<原主机名>:443/mtls/v1/tunnel/<target> 走 CDN，内层仍是原 TLS 1.3 双向证书握手；
// direct 直连原 host:port（兼容、排障）。<组件>_MTLS_TUNNEL_URL=https://host[:port] 覆盖外层入口。
// 只改拨号：URL、主机名比对、证书与 CA 钉扎都不变。
const (
	pluginRuntimeMTLSComponent = "PLUGIN_RUNTIME" // 授权端 9448：插件运行时/复核回报/规则情报
	marketMTLSComponent        = "MARKET"         // MARKET_URL 市场成员接口
)

// mtlsDialer 返回 originURL 的拨号函数；direct 为 nil（http.Transport 自己直连）。
func mtlsDialer(component, originURL, target string) (mtlstunnel.DialFunc, error) {
	mode := strings.TrimSpace(os.Getenv(component + "_MTLS_TRANSPORT"))
	dial, err := mtlstunnel.Dialer(mode, originURL, strings.TrimSpace(os.Getenv(component+"_MTLS_TUNNEL_URL")), target)
	if err != nil {
		return nil, fmt.Errorf("%s_MTLS_TRANSPORT: %w", component, err)
	}
	return dial, nil
}

func pluginRuntimeDialer(originURL string) (mtlstunnel.DialFunc, error) {
	return mtlsDialer(pluginRuntimeMTLSComponent, originURL, mtlstunnel.TargetPluginRuntime)
}
