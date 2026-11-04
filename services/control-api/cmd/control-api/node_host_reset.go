package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

// runResetNodeHostDelivery repairs a node reinstalled ("重装此节点") on a
// control plane whose enrollment did not yet reset the distributors' state:
// the new host gets its service ticket, signer trust, bans and site
// configuration again (nodeidentity.ResetReinstalledHost). Root only; it
// refuses a node enrolled once.
//
//	control-api reset-node-host-delivery --node-id UUID
func runResetNodeHostDelivery(args []string, output io.Writer) error {
	if !platformRecoveryRoot(runtime.GOOS, os.Getuid(), os.Geteuid()) {
		return errors.New("reset_node_host_delivery_requires_linux_root")
	}
	flags := flag.NewFlagSet("reset-node-host-delivery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rawNodeID := flags.String("node-id", "", "node ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: control-api reset-node-host-delivery --node-id UUID")
	}
	nodeID, err := uuid.Parse(*rawNodeID)
	if err != nil || nodeID == uuid.Nil || nodeID.String() != *rawNodeID {
		return errors.New("usage: control-api reset-node-host-delivery --node-id UUID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	store := nodeidentity.NewStore(pool).WithReinstallRepublisher(edgeautopublish.RepublishReinstalledNodeTx)
	result, err := store.ResetReinstalledHost(ctx, nodeID, "cli-reset-node-host-delivery/"+uuid.NewString())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
