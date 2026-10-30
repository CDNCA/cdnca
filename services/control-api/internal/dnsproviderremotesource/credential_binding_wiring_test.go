package dnsproviderremotesource

import (
	"bytes"
	"os"
	"testing"
)

func TestRemoteCredentialConsumersRequireBoundAuthority(t *testing.T) {
	for _, path := range []string{"source.go", "reconcile.go"} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(source, []byte("BoundCredentialCipher")) ||
			!bytes.Contains(source, []byte("boundCredentialDecryptor{")) {
			t.Fatalf("%s does not require bound credential decryption", path)
		}
	}
}
