package edgeconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func passthroughBundleSpec() Spec {
	spec := multiListenerBundleSpec()
	stream := &spec.L4StreamsV2[0]
	stream.AdditionalListeners = []L4AdditionalListenerV2{
		{ID: "44444444-4444-4444-8444-444444444444", Protocol: "tcp", Address: "*", Port: 18444},
	}
	stream.TLSPassthrough = true
	stream.ServerNames = []string{"b.example.com", "a.example.com", "*.example.com"}
	return spec
}

func TestTLSPassthroughBundleSortsServerNames(t *testing.T) {
	spec := passthroughBundleSpec()
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil || len(set.Streams) != 1 {
		t.Fatalf("decode artifact: %+v %v", set, err)
	}
	if got := set.Streams[0]; !got.TLSPassthrough || !slices.Equal(got.ServerNames, []string{"*.example.com", "a.example.com", "b.example.com"}) {
		t.Fatalf("passthrough stream = %+v", got)
	}
	if !slices.Equal(spec.L4StreamsV2[0].ServerNames, []string{"b.example.com", "a.example.com", "*.example.com"}) {
		t.Fatal("normalization mutated the caller's server names")
	}

}

func TestPlainStreamOmitsPassthroughFields(t *testing.T) {
	bundle, err := buildStreams(multiListenerBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	artifact := bundle.Files[L4RuntimeV2ArtifactPath]
	if bytes.Contains(artifact, []byte("tls_passthrough")) || bytes.Contains(artifact, []byte("server_names")) {
		t.Fatalf("plain stream artifact gained passthrough keys: %s", artifact)
	}
}

func TestTLSPassthroughBundleRejectsInvalidStreams(t *testing.T) {
	for name, change := range map[string]func(*L4StreamRuntimeV2){
		"names without passthrough": func(stream *L4StreamRuntimeV2) { stream.TLSPassthrough = false },
		"no names":                  func(stream *L4StreamRuntimeV2) { stream.ServerNames = nil },
		"udp primary":               func(stream *L4StreamRuntimeV2) { stream.Listener.Protocol = "udp" },
		"udp additional":            func(stream *L4StreamRuntimeV2) { stream.AdditionalListeners[0].Protocol = "udp" },
		"duplicate name":            func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"a.example.com", "a.example.com"} },
		"upper case":                func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"A.example.com"} },
		"inner wildcard":            func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"a.*.example.com"} },
		"partial wildcard":          func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"a*.example.com"} },
		"bare wildcard":             func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"*"} },
		"wildcard on a TLD":         func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"*.com"} },
		"double wildcard":           func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"*.*.example.com"} },
		"single label":              func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"localhost"} },
		"trailing dot":              func(stream *L4StreamRuntimeV2) { stream.ServerNames = []string{"a.example.com."} },
		"too many": func(stream *L4StreamRuntimeV2) {
			stream.ServerNames = nil
			for index := 0; index <= L4ServerNamesMax; index++ {
				stream.ServerNames = append(stream.ServerNames, string(rune('a'+index%26))+string(rune('a'+index/26))+".example.com")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := passthroughBundleSpec()
			change(&spec.L4StreamsV2[0])
			if _, err := buildStreams(spec); err == nil {
				t.Fatal("invalid passthrough stream accepted")
			}
		})
	}
}
