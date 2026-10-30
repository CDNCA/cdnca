// Command gateway-cdn-poc is the ADR 0013 PoC: Agent <-> CDN-like L7 proxy
// (TLS terminated by the proxy) <-> Gateway over the real agent.v1 gRPC
// bidirectional streams. See run.sh.
package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: gateway-cdn-poc pki|gateway|control|agent [flags]")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := flags.String("pki", "./out/pki", "PKI directory")
	name := flags.String("name", "gw-a", "gateway name")
	mtls := flags.String("mtls", "", "direct mTLS listen address")
	grpcOrigin := flags.String("grpc-origin", "", "TLS gRPC origin listen address (signed headers)")
	wsOrigin := flags.String("ws-origin", "", "HTTPS WebSocket tunnel origin listen address")
	shared := flags.String("shared", "", "gateway: one port serving direct gRPC mTLS and the WebSocket tunnel")
	trusted := flags.String("trusted", "", "gateway: trusted CDN back-to-origin ranges cidr=Header,...")
	listen := flags.String("listen", "", "control: HTTPS listen address for /downloads/node-install-defaults")
	defaults := flags.String("defaults", "", "control: node-install-defaults JSON file")
	control := flags.String("control", "", "agent: control-plane URL; endpoints come from its node-install-defaults")
	label := flags.String("label", "", "agent: scenario label sent on the tunnel upgrade (PoC stats only)")
	xff := flags.String("xff", "", "agent: forged X-Forwarded-For sent on the tunnel upgrade")
	stats := flags.String("stats", "", "stats JSON file")
	endpoints := flags.String("endpoints", "", "agent endpoints mode=host:port,...")
	heartbeat := flags.Duration("heartbeat", 15*time.Second, "heartbeat interval")
	total := flags.Duration("total", time.Minute, "agent total run time")
	session := flags.Duration("session", time.Minute, "agent per-session cap")
	result := flags.String("result", "", "agent result JSON file")
	_ = flags.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "pki":
		err = runPKI(*dir)
	case "gateway":
		err = runGateway(*dir, *name, *mtls, *grpcOrigin, *wsOrigin, *shared, *trusted, *stats, *heartbeat)
	case "control":
		err = runControl(*dir, *listen, *defaults)
	case "agent":
		tunnelLabel, tunnelForgedXFF = *label, *xff
		list := *endpoints
		if *control != "" {
			if list, err = endpointsFromControl(*dir, *control); err != nil {
				log.Fatal(err)
			}
		}
		err = runAgent(*dir, list, *heartbeat, *total, *session, *result)
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}
