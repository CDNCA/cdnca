package packagingtoolset

import (
	"regexp"
	"strings"
	"testing"
)

// the hand-written grammars accept exactly what the regular
// expressions they replace accepted.
var (
	referenceVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	referenceDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func TestGrammarsMatchRegexp(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 4)
	inputs := []string{"", "1", "1.0.35", "v1.0.36-rc.1_x", ".1", "-1", "_1", "1.0 35", "1.0.35\n", "\n1.0.35", "1/0", "é1", "1é",
		sha, sha[:63], sha + "0", strings.ToUpper(sha), sha[:63] + "g", sha[:63] + "\n", "\n" + sha[1:], strings.Repeat("A", 128), strings.Repeat("A", 129)}
	for c := 0; c < 256; c++ {
		inputs = append(inputs, string(rune(c)), "a"+string(rune(c)), sha[:63]+string(rune(c)), string([]byte{byte(c)}), "a"+string([]byte{byte(c)}))
	}
	for _, input := range inputs {
		if got, want := versionGrammar(input), referenceVersion.MatchString(input); got != want {
			t.Errorf("versionGrammar(%q) = %v, regexp %v", input, got, want)
		}
		if got, want := hexDigest(input), referenceDigest.MatchString(input); got != want {
			t.Errorf("hexDigest(%q) = %v, regexp %v", input, got, want)
		}
	}
}

// The gateway and control check every heartbeat's report (measured: 2.3% of the
// gateway's cycles at a 100 ms heartbeat, regexp 2.0%).
func BenchmarkValidHeartbeatReport(b *testing.B) {
	sha := strings.Repeat("0123456789abcdef", 4)
	b.ReportAllocs()
	for b.Loop() {
		if !Valid("ok", "1.0.35", "", true, "ok", "", sha, sha) {
			b.Fatal("invalid")
		}
	}
}
