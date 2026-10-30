package helper

import "testing"

func TestAuthorizedPeerAcceptsOnlyAgentAccountOrRoot(t *testing.T) {
	policy := socketPolicy{path: ProductionSocketPath, uid: 991, gid: 992}
	tests := []struct {
		name string
		peer PeerIdentity
		want bool
	}{
		{name: "fixed agent account", peer: PeerIdentity{PID: 10, UID: 991, GID: 992}, want: true},
		{name: "root agent", peer: PeerIdentity{PID: 11, UID: 0, GID: 0}, want: true},
		{name: "root uid with foreign gid", peer: PeerIdentity{UID: 0, GID: 992}, want: false},
		{name: "root uid with unrelated gid", peer: PeerIdentity{UID: 0, GID: 4}, want: false},
		{name: "agent uid with root gid", peer: PeerIdentity{UID: 991, GID: 0}, want: false},
		{name: "foreign uid with root gid", peer: PeerIdentity{UID: 1000, GID: 0}, want: false},
		{name: "agent uid with wrong gid", peer: PeerIdentity{UID: 991, GID: 993}, want: false},
		{name: "wrong uid with agent gid", peer: PeerIdentity{UID: 990, GID: 992}, want: false},
		{name: "nobody", peer: PeerIdentity{UID: 65534, GID: 65534}, want: false},
		{name: "unprivileged login user", peer: PeerIdentity{UID: 1000, GID: 1000}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := authorizedPeer(test.peer, policy); got != test.want {
				t.Fatalf("authorizedPeer(%+v) = %v, want %v", test.peer, got, test.want)
			}
		})
	}
}

// A policy that resolved the fixed account to root must not widen root
// acceptance to other groups; the account is required to be unprivileged.
func TestAuthorizedPeerRootPolicyStillRequiresExactPair(t *testing.T) {
	policy := socketPolicy{path: ProductionSocketPath, uid: 0, gid: 0}
	if !authorizedPeer(PeerIdentity{UID: 0, GID: 0}, policy) {
		t.Fatal("root peer rejected")
	}
	if authorizedPeer(PeerIdentity{UID: 0, GID: 1}, policy) || authorizedPeer(PeerIdentity{UID: 1, GID: 0}, policy) {
		t.Fatal("partial root identity authorized")
	}
}
