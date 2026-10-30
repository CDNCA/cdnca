package realtimecapture

import (
	"strings"
	"testing"
)

const header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func TestKernelListenerCountsConnectionsIndependentlyAndAcceptsObservedZero(t *testing.T) {
	for _, test := range []struct {
		name, rows string
		want       uint64
	}{
		{"zero", "0: 00000000:0050 00000000:0000 0A 0:0 00:0 0 0 0 1\n", 0},
		{"active-and-timewait", "0: 00000000:0050 00000000:0000 0A 0:0 00:0 0 0 0 1\n1: 0100007F:0050 0100007F:FFFF 01 0:0 00:0 0 0 0 2\n2: 0100007F:0050 0100007F:FFFE 06 0:0 00:0 0 0 0 3\n", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readListeners([]uint16{80}, strings.NewReader(header+test.rows), strings.NewReader(header))
			if err != nil || !got[80].Listening || got[80].Connections != test.want || got[80].Evidence == ([32]byte{}) {
				t.Fatalf("snapshot=%+v err=%v", got, err)
			}
		})
	}
}

func TestKernelMissingOrMalformedSourceNeverBecomesZero(t *testing.T) {
	for _, source := range []string{"", header, header + "broken\n", header + "0: invalid 00000000:0000 0A 0:0 00:0 0 0 0 1\n"} {
		if _, err := readListeners([]uint16{80}, strings.NewReader(source), strings.NewReader(header)); err == nil {
			t.Fatal("unavailable source accepted")
		}
	}
}
