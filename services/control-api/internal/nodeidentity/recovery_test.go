package nodeidentity

import (
	"encoding/hex"
	"testing"
	"time"
)

// recoveryMessageVector is shared with agents/edge-agent/internal/enrollment
// recovery_test.go: both sides must build the same signed bytes.
const recoveryMessageVector = "cdnca/node-certificate-recovery/v1\n" +
	"request_id=0192f0e0-0000-7000-8000-000000000001\n" +
	"sent_time=2026-10-21T08:00:00.5Z\n" +
	"node_id=0192f0e0-0000-7000-8000-0000000000aa\n" +
	"certificate_sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n" +
	"csr_sha256=cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34\n" +
	"nonce=0101010101010101010101010101010101010101010101010101010101010101"

func TestRecoveryMessageMatchesSharedVector(t *testing.T) {
	nonce, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	got := RecoveryMessage("0192f0e0-0000-7000-8000-000000000001", time.Date(2026, 10, 21, 8, 0, 0, 5e8, time.UTC),
		"0192f0e0-0000-7000-8000-0000000000aa", []byte("abc"), []byte("def"), nonce)
	if string(got) != recoveryMessageVector {
		t.Fatalf("RecoveryMessage =\n%s\nwant\n%s", got, recoveryMessageVector)
	}
}

func TestRecoveryDurationText(t *testing.T) {
	for value, want := range map[time.Duration]string{
		25 * time.Minute:                 "25分钟",
		2*time.Hour + 5*time.Minute:      "2小时5分钟",
		3*24*time.Hour + 4*time.Hour + 1: "3天4小时",
	} {
		if got := recoveryDurationText(value); got != want {
			t.Fatalf("recoveryDurationText(%s) = %q, want %q", value, got, want)
		}
	}
}
