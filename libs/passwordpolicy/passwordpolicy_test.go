package passwordpolicy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name     string
		password string
		unmet    []string
	}{
		{"7 位拒绝", "Abc1234", []string{UnmetLength}},
		{"8 位纯数字拒绝", "12345678", []string{UnmetCharacterClasses}},
		{"8 位纯小写拒绝", "abcdefgh", []string{UnmetCharacterClasses}},
		{"字母加数字通过", "abcd1234", nil},
		{"大小写通过", "abcdEFGH", nil},
		{"符号加数字通过", "!@#$1234", nil},
		{"全部符号均可用", Symbols + "a", nil},
		{"含空格拒绝", "abcd 1234", []string{UnmetInvalidCharacter}},
		{"含中文拒绝", "abcd1234密码", []string{UnmetInvalidCharacter}},
		{"含全角拒绝", "abcd１２３４", []string{UnmetCharacterClasses, UnmetInvalidCharacter}},
		{"含 emoji 拒绝", "abcd1234😀", []string{UnmetInvalidCharacter}},
		{"含制表符拒绝", "abcd\t1234", []string{UnmetInvalidCharacter}},
		{"含 DEL 拒绝", "abcd1234\x7f", []string{UnmetInvalidCharacter}},
		{"空串", "", []string{UnmetLength, UnmetCharacterClasses}},
		{"1024 字节通过", strings.Repeat("a1", 512), nil},
		{"1025 字节拒绝", strings.Repeat("a1", 512) + "b", []string{UnmetLength}},
		{"短且单类且非法", "a 1", []string{UnmetLength, UnmetInvalidCharacter}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.password)
			unmet, ok := UnmetOf(err)
			if tc.unmet == nil {
				if err != nil {
					t.Fatalf("Check(%q) = %v, want nil", tc.password, err)
				}
				return
			}
			if !ok || !reflect.DeepEqual(unmet, tc.unmet) {
				t.Fatalf("Check(%q) unmet = %v (%v), want %v", tc.password, unmet, err, tc.unmet)
			}
		})
	}
}

func TestUnmetOfWrapped(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", Check("1234567"))
	if unmet, ok := UnmetOf(wrapped); !ok || len(unmet) != 2 {
		t.Fatalf("UnmetOf(wrapped) = %v, %v", unmet, ok)
	}
	if _, ok := UnmetOf(fmt.Errorf("other")); ok {
		t.Fatal("UnmetOf(other) reported a policy error")
	}
}
