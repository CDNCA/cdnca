package entitlementsync

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// 续租提前量为租期 1/3，不设上限；下限 1 分钟。
func TestRenewalDelayLeadIsOneThirdOfLifetime(t *testing.T) {
	issued := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name     string
		lifetime time.Duration
		at       time.Duration // 距签发
		want     time.Duration
	}{
		{"7d_at_issue", 7 * 24 * time.Hour, 0, 7 * 24 * time.Hour * 2 / 3},
		{"30d_at_issue", 30 * 24 * time.Hour, 0, 20 * 24 * time.Hour},
		{"30d_inside_lead", 30 * 24 * time.Hour, 21 * 24 * time.Hour, 0},
		{"30d_before_lead", 30 * 24 * time.Hour, 19 * 24 * time.Hour, 24 * time.Hour},
		{"short_floor", 90 * time.Second, 0, 30 * time.Second},
		{"expired", time.Hour, 2 * time.Hour, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease := entitlement.Lease{NotBefore: issued.Unix(), ExpiresAt: issued.Add(tc.lifetime).Unix()}
			if got := renewalDelay(issued.Add(tc.at), lease); got != tc.want {
				t.Fatalf("renewalDelay = %s, want %s", got, tc.want)
			}
		})
	}
}
