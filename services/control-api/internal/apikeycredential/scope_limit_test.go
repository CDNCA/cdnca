package apikeycredential

import (
	"fmt"
	"testing"
)

// fix-apikeysimple：密钥 scopes 上限 128（迁移 574），校验时不能把 33～128 个权限的密钥当成非法凭据。
func TestCanonicalPermissionsAcceptsUpTo128(t *testing.T) {
	values := make([]string, 0, 129)
	for index := 0; index < 129; index++ {
		values = append(values, fmt.Sprintf("module%03d.read", index))
	}
	if _, ok := canonicalPermissions(values[:57]); !ok {
		t.Fatal("canonicalPermissions(57) rejected")
	}
	if _, ok := canonicalPermissions(values[:128]); !ok {
		t.Fatal("canonicalPermissions(128) rejected")
	}
	if _, ok := canonicalPermissions(values); ok {
		t.Fatal("canonicalPermissions(129) accepted")
	}
}
