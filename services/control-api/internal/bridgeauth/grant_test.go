package bridgeauth

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func licensed(context.Context, pgx.Tx) (bool, error) { return true, nil }

func grant(t *testing.T, kind string) *Grant {
	t.Helper()
	g, err := NewGrant(uuid.New(), "cbb_AAAAAAAAAAAAAAAAAAAAAA", uuid.New(), kind, uuid.New(), licensed)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The fixed permission sets of ADR 0019 §4.4: nothing outside them.
func TestGrantAllowsOnlyFixedPermissionSet(t *testing.T) {
	outside := []string{"platform.admin", "billing_bridge.manage", "package_subscriptions.read", "packages.manage",
		"reseller.customers.read", "identity.users.read", "api_keys.manage", ""}
	reseller, platform := grant(t, OwnerReseller), grant(t, OwnerPlatform)
	if !reseller.Allows(PermissionResellerCustomersManage) {
		t.Fatal("reseller grant must allow reseller.customers.manage")
	}
	for _, permission := range append(outside, PermissionSubscriptionsManage, PermissionBillingAdjustments,
		PermissionIdentityUsersManage) {
		if reseller.Allows(permission) {
			t.Errorf("reseller grant allows %q", permission)
		}
	}
	for _, permission := range []string{PermissionSubscriptionsManage, PermissionBillingAdjustments, PermissionIdentityUsersManage} {
		if !platform.Allows(permission) {
			t.Errorf("platform grant refuses %q", permission)
		}
	}
	for _, permission := range append(outside, PermissionResellerCustomersManage) {
		if platform.Allows(permission) {
			t.Errorf("platform grant allows %q", permission)
		}
	}
}

func TestGrantRequiresEveryField(t *testing.T) {
	id, owner, user := uuid.New(), uuid.New(), uuid.New()
	for name, build := range map[string]func() (*Grant, error){
		"no key row":   func() (*Grant, error) { return NewGrant(uuid.Nil, "k", owner, OwnerPlatform, user, licensed) },
		"no key id":    func() (*Grant, error) { return NewGrant(id, "", owner, OwnerPlatform, user, licensed) },
		"no owner":     func() (*Grant, error) { return NewGrant(id, "k", uuid.Nil, OwnerPlatform, user, licensed) },
		"bad kind":     func() (*Grant, error) { return NewGrant(id, "k", owner, "tenant", user, licensed) },
		"no user":      func() (*Grant, error) { return NewGrant(id, "k", owner, OwnerPlatform, uuid.Nil, licensed) },
		"no licensing": func() (*Grant, error) { return NewGrant(id, "k", owner, OwnerPlatform, user, nil) },
	} {
		if g, err := build(); err == nil || g != nil {
			t.Errorf("%s: grant built", name)
		}
	}
	var none *Grant
	if none.Valid() || none.Allows(PermissionSubscriptionsManage) || none.VerifyTx(t.Context(), nil) == nil {
		t.Fatal("nil grant must refuse everything")
	}
	if grant(t, OwnerPlatform).VerifyTx(t.Context(), nil) == nil {
		t.Fatal("VerifyTx without a transaction must refuse")
	}
}

// Only the billing bridge facade (internal/billingbridge, after signature
// verification) builds a Grant; the session and API key paths never do, so a
// Bearer or CdncaKey request cannot reach any bridge branch.
func TestOnlyBillingBridgeBuildsGrants(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(raw), "bridgeauth.NewGrant(") {
			return nil
		}
		if filepath.Dir(path) != filepath.Join(root, "internal", "billingbridge") {
			t.Errorf("%s builds a bridge grant", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
