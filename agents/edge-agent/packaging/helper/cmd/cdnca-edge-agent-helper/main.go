package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
)

const fixedAgentAccount = "cdnca-edge"

var (
	errCommandUsage = errors.New("invalid helper command")
	errRootRequired = errors.New("root is required")
)

type commandActions struct {
	euid    func() int
	keyInit func() error
	serve   func(context.Context) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := dispatch(ctx, os.Args[1:], productionActions()); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "cdnca edge agent helper: startup failed")
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, arguments []string, actions commandActions) error {
	if actions.euid == nil || actions.keyInit == nil || actions.serve == nil || actions.euid() != 0 {
		return errRootRequired
	}
	if len(arguments) != 1 {
		return errCommandUsage
	}
	switch arguments[0] {
	case "key-init":
		return actions.keyInit()
	case "serve":
		return actions.serve(ctx)
	default:
		return errCommandUsage
	}
}

func productionActions() commandActions {
	return commandActions{euid: os.Geteuid, keyInit: initializeReceiptKey, serve: serveProduction}
}

func initializeReceiptKey() error {
	agentGID, err := fixedAgentGID()
	if err != nil {
		return err
	}
	journalConfig, err := helper.ProductionJournalConfig()
	if err != nil {
		return err
	}
	if _, err := helper.NewJournalStore(journalConfig); err != nil {
		return err
	}
	keyConfig, err := helper.ProductionKeyConfig(agentGID)
	if err != nil {
		return err
	}
	key, err := helper.LoadReceiptKey(keyConfig)
	if err == nil {
		_, err = helper.EnsureReceiptKey(keyConfig, key.KeyID)
		return err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keyID := "helper-" + time.Now().UTC().Format("20060102T150405Z")
	_, err = helper.EnsureReceiptKey(keyConfig, keyID)
	return err
}

func serveProduction(ctx context.Context) error {
	if err := initializeReceiptKey(); err != nil {
		return err
	}
	agentGID, err := fixedAgentGID()
	if err != nil {
		return err
	}
	keyConfig, err := helper.ProductionKeyConfig(agentGID)
	if err != nil {
		return err
	}
	receiptKey, err := helper.LoadReceiptKeyPair(keyConfig)
	if err != nil {
		return err
	}
	releaseKey, err := helper.LoadPinnedReleasePublicKey()
	if err != nil {
		return err
	}
	listener, err := helper.ListenerFromSystemd()
	if err != nil {
		return err
	}
	defer listener.Close()
	service, err := helper.NewService(helper.ServiceConfig{
		Paths: helper.RuntimePaths{
			StateDirectory:   helper.ProductionStateDirectory,
			ReleaseRoot:      helper.ProductionReleaseRoot,
			AcceptedManifest: helper.ProductionAcceptedManifest,
		},
		OwnerUID: 0, OwnerGID: 0, ReceiptKey: receiptKey,
		ReleasePublicKey: releaseKey, Runner: helper.PackagingRunner{}, Now: time.Now,
	})
	if err != nil {
		return err
	}
	return helper.Serve(ctx, listener, service)
}

func fixedAgentGID() (uint32, error) {
	account, err := user.Lookup(fixedAgentAccount)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}
