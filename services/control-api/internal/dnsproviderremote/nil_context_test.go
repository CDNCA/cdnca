package dnsproviderremote

import (
	"errors"
	"testing"
)

func TestPublicEntriesRejectNilContextBeforeSourceOrHTTP(t *testing.T) {
	config := testProviderConfig()
	source := &staticSource{config: config, err: errors.New("source unavailable")}
	adapter := newStaticTestAdapter(t, source)
	challenge := testChallenge()
	handle, err := encodeTestHandle(t, challenge, config, recordHandle{
		Provider: providerCloudflare, Zone: testZone, ZoneID: "remote-zone", RecordID: "remote-record", Owner: testOwner,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge.TXTHandle = handle

	if _, err := Open(nil, source, testHandleKeyring(t)); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("Open(nil) error=%v, want %s", err, CodeInvalidInput)
	}
	if _, err := adapter.PresentTXT(nil, testChallenge()); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("PresentTXT(nil) error=%v, want %s", err, CodeInvalidInput)
	}
	if _, _, err := adapter.RecoverTXT(nil, testChallenge()); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("RecoverTXT(nil) error=%v, want %s", err, CodeInvalidInput)
	}
	if err := adapter.ObserveTXT(nil, challenge); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("ObserveTXT(nil) error=%v, want %s", err, CodeInvalidInput)
	}
	if err := adapter.DeleteTXT(nil, challenge); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("DeleteTXT(nil) error=%v, want %s", err, CodeInvalidInput)
	}
	if source.callCount() != 0 {
		t.Fatalf("nil-context calls reached Resolve: %d", source.callCount())
	}
}

func TestSourceFailureAcceptsNilContext(t *testing.T) {
	if err := sourceFailure(nil); ErrorCodeOf(err) != CodeSourceUnavailable {
		t.Fatalf("sourceFailure(nil)=%v, want %s", err, CodeSourceUnavailable)
	}
}
