package edgeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestConfigurationBundleBudgetIsEnforcedBeforeAndAfterMarshal(t *testing.T) {
	files := make(map[string][]byte, MaxConfigurationBundleFiles+1)
	for index := 0; index <= MaxConfigurationBundleFiles; index++ {
		files[fmt.Sprintf("security/%04d.json", index)] = []byte("{}")
	}
	if _, err := newBundle(files); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("newBundle(too many files) error = %v, want ErrInvalidBundle", err)
	}

	bundle, err := newBundle(map[string][]byte{"nginx.conf": bytes.Repeat([]byte("x"), MaxConfigurationBundleWireBytes)})
	if err != nil {
		t.Fatalf("newBundle() error = %v", err)
	}
	if _, err := MarshalBundle(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("MarshalBundle(oversized wire) error = %v, want ErrInvalidBundle", err)
	}

	valid, err := newBundle(map[string][]byte{"nginx.conf": []byte("events {}\n")})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalBundle(valid)
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(wire, bytes.Repeat([]byte(" "), MaxConfigurationBundleWireBytes-len(wire)+1)...)
	if _, err := UnmarshalBundle(oversized); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("UnmarshalBundle(oversized wire) error = %v, want ErrInvalidBundle", err)
	}
}
