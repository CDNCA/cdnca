package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// runAdminAccessAllowlist is the recovery path for the platform
// administration access allowlist: an administrator locked out by the list
// runs, as root on the control host,
//
//	DATABASE_URL=... control-api admin-access-allowlist disable
//
// which turns the policy off (the list is kept) and writes an audit event.
// `status` prints the current policy. No HTTP adapter exists for disable.
func runAdminAccessAllowlist(args []string, output io.Writer) error {
	if len(args) != 1 || args[0] != "disable" && args[0] != "status" {
		return errors.New("usage: control-api admin-access-allowlist disable|status")
	}
	if !platformRecoveryRoot(runtime.GOOS, os.Getuid(), os.Geteuid()) {
		return errors.New("admin_access_allowlist_requires_linux_root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("admin_access_allowlist_database_unavailable")
	}
	defer pool.Close()
	store := identity.NewStore(pool)
	var policy identity.AdminAccessPolicy
	if args[0] == "disable" {
		policy, err = store.DisableAdminAccessPolicy(ctx, uuid.NewString())
	} else {
		policy, err = store.ReadAdminAccessPolicy(ctx)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(policy)
}
