package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/gatewayregistry"
	"github.com/jackc/pgx/v5/pgxpool"
)

// control-api gateway-entrypoint ensure.
func runGatewayEntrypoint(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "ensure" {
		return errors.New("usage: control-api gateway-entrypoint ensure --address HOST:PORT --server-name HOST --transport ws [--tunnel-host HOST] [--trust-loopback-header H]")
	}
	flags := flag.NewFlagSet("gateway-entrypoint ensure", flag.ContinueOnError)
	address := flags.String("address", "", "node entry host:port")
	serverName := flags.String("server-name", "", "inner TLS server name of the Gateway")
	transport := flags.String("transport", gatewayregistry.TransportWS, "grpc or ws")
	tunnelHost := flags.String("tunnel-host", "", "outer SNI/Host of a ws entry")
	loopback := flags.String("trust-loopback-header", "", "trust 127.0.0.1 (console nginx) for this real-IP header")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return errors.New("DATABASE_URL is invalid")
	}
	defer pool.Close()
	if err := gatewayregistry.EnsureInstallEntrypoint(ctx, pool, gatewayregistry.Entrypoint{Address: *address, ServerName: *serverName,
		Transport: *transport, TunnelHost: *tunnelHost}, *loopback); err != nil {
		return fmt.Errorf("ensure Gateway entry point: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "gateway entry point %s (%s) present\n", strings.ToLower(*address), *transport)
	return err
}
