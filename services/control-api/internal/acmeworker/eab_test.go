package acmeworker

import (
	"bytes"
	"context"
	"testing"
)

type staticEAB struct {
	keyID string
	key   []byte
	calls int
}

func (e *staticEAB) ExternalAccountBinding(context.Context, string) (string, []byte, bool, error) {
	e.calls++
	if e.keyID == "" {
		return "", nil, false, nil
	}
	return e.keyID, bytes.Clone(e.key), true, nil
}

// A CA that requires External Account Binding (ZeroSSL,
// Google Trust Services). No credentials: refused before registering, with
// acme_eab_required. Wrong credentials: the CA's refusal is
// acme_eab_required too. Right credentials: the account registers with the
// binding (checked by the test CA's HMAC) and the order completes.
func TestWorkerRegistersWithExternalAccountBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for name, test := range map[string]struct {
		eab      *staticEAB
		want     ErrorCode
		accounts int
	}{
		"no credentials":    {eab: &staticEAB{}, want: CodeEABRequired, accounts: 0},
		"wrong credentials": {eab: &staticEAB{keyID: "kid-1", key: bytes.Repeat([]byte{0x01}, 32)}, want: CodeEABRequired, accounts: 1},
		"unknown key ID":    {eab: &staticEAB{keyID: "kid-9", key: key}, want: CodeEABRequired, accounts: 1},
		"credentials":       {eab: &staticEAB{keyID: "kid-1", key: key}, accounts: 1},
	} {
		t.Run(name, func(t *testing.T) {
			protocol := newProtocolServer(t, testNow, protocolOptions{eabKeys: map[string][]byte{"kid-1": key}})
			records := &challengeRecords{}
			worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: map[string]IssuedCertificate{}}, nil)
			worker.deps.EAB = test.eab
			_, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "eab.example.test"))
			if test.want == "" && err != nil || test.want != "" && ErrorCodeOf(err) != test.want {
				t.Fatalf("Issue() error = %v, want %q", err, test.want)
			}
			if protocol.newAccountAttempts != test.accounts || test.eab.calls != 1 {
				t.Fatalf("account attempts = %d (want %d), EAB lookups = %d", protocol.newAccountAttempts, test.accounts, test.eab.calls)
			}
		})
	}
}

// A CA without EAB keeps registering without a binding, and an EAB source
// that has none for it is not an error.
func TestWorkerWithoutEABRequirementIgnoresMissingCredentials(t *testing.T) {
	protocol := newProtocolServer(t, testNow, protocolOptions{})
	records := &challengeRecords{}
	worker := newTestWorker(t, protocol, records, records, &memoryCertificates{items: map[string]IssuedCertificate{}}, nil)
	worker.deps.EAB = &staticEAB{}
	if _, err := worker.Issue(context.Background(), validIssueRequest(ChallengeHTTP01, "plain.example.test")); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
}
