package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger := log.New(os.Stderr, "agent-gateway ", log.Ldate|log.Ltime|log.LUTC)
	if len(os.Args) > 1 && os.Args[1] == "bind" {
		if err := runBindCommand(context.Background(), os.Args[2:], os.Stdin); err != nil {
			logger.Printf("bind failed: %v", err)
			os.Exit(1)
		}
		return
	}
	cfg, err := loadConfig()
	if err != nil {
		logger.Printf("configuration rejected: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, logger); err != nil {
		logger.Printf("process failed: %v", err)
		os.Exit(1)
	}
}

type logger interface {
	Printf(string, ...any)
}

func run(ctx context.Context, cfg config, output logger) error {
	r, err := buildRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer r.close()
	if r.sched302Err != nil {
		output.Printf("schedule302 table delivery disabled: %v", r.sched302Err)
	}
	if r.autoDefenseErr != nil {
		output.Printf("auto defense channel disabled: %v", r.autoDefenseErr)
	}
	if r.installationBanErr != nil {
		output.Printf("installation ban delivery disabled: %v", r.installationBanErr)
	}
	if r.signerTrustErr != nil {
		output.Printf("edge signer trust delivery disabled: %v", r.signerTrustErr)
	}
	if r.securityBanErr != nil {
		output.Printf("security ban list delivery disabled: %v", r.securityBanErr)
	}
	if r.siteDropErr != nil {
		output.Printf("site drop list delivery disabled: %v", r.siteDropErr)
	}
	if r.gatewayAddressErr != nil {
		output.Printf("gateway address change delivery disabled: %v", r.gatewayAddressErr)
	}
	if r.l4LiveErr != nil {
		output.Printf("L4 live connection relay disabled: %v", r.l4LiveErr)
	}
	if r.marketProbesErr != nil {
		output.Printf("market probe relay disabled: %v", r.marketProbesErr)
	}
	output.Printf("listening: enrollment=%s agent=%s health=%s instance=%s version=%s", r.enrollmentListener.Addr(), r.agentListener.Addr(), r.healthListener.Addr(), cfg.instanceID, cfg.version)
	return r.serve(ctx)
}
