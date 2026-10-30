package challenge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type recordingPrechecker struct{ calls int }

func (checker *recordingPrechecker) Precheck(context.Context, string, string) error {
	checker.calls++
	return nil
}

func writeReleaseConfig(t *testing.T, release, config string) {
	t.Helper()
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "nginx.conf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The legacy renderer and site runtime v2 both load the policy by
// policy_path in init_by_lua (libs/edgeconfig config.go renderChallengeInit,
// listener_runtime_security.go listenerChallengeInitLua).
func challengeInitConfig(root, policyID string, version uint64) string {
	path := filepath.Join(root, "challenge", "policies", policyID, "versions", fmt.Sprintf("%020d.json", version))
	return fmt.Sprintf("http {\n  init_by_lua_block {\n    module_0001.init({ policy_path = %q, state_dict = \"cdnca_challenge_state\" })\n"+
		"    local sites = {\n      { module = \"cdnca_challenge_site_x\", policy_path = %q, state_dict = \"cdnca_challenge_state\" },\n    }\n  }\n}\n", path, path)
}

func TestPolicyPrecheckerRefusesReleaseWithoutInstalledPolicy(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	release := filepath.Join(root, "releases", "r1")
	writeReleaseConfig(t, release, challengeInitConfig(root, binding.PolicyID, binding.PolicyVersion))
	delegate := &recordingPrechecker{}
	checker, err := NewPolicyPrechecker(root, "nginx.conf", delegate)
	if err != nil {
		t.Fatal(err)
	}
	err = checker.Precheck(context.Background(), "v1", release)
	if !errors.Is(err, ErrPolicyNotInstalled) || delegate.calls != 0 {
		t.Fatalf("missing policy: err=%v delegate calls=%d", err, delegate.calls)
	}

	installer, err := NewArtifactInstaller(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.InstallJSON(testChallengeArtifactJSON(t, binding,
		"current-challenge-secret-material-01", "previous-challenge-secret-material-1"), binding); err != nil {
		t.Fatal(err)
	}
	if err := checker.Precheck(context.Background(), "v1", release); err != nil || delegate.calls != 1 {
		t.Fatalf("installed policy: err=%v delegate calls=%d", err, delegate.calls)
	}

	// Another version of the same policy is not this release's policy.
	writeReleaseConfig(t, release, challengeInitConfig(root, binding.PolicyID, binding.PolicyVersion+1))
	if err := checker.Precheck(context.Background(), "v1", release); !errors.Is(err, ErrPolicyNotInstalled) || delegate.calls != 1 {
		t.Fatalf("other version: err=%v delegate calls=%d", err, delegate.calls)
	}

	// A damaged sealed file is not an installed policy either.
	sealed := filepath.Join(root, "challenge", "policies", binding.PolicyID, "versions", fmt.Sprintf("%020d.json", binding.PolicyVersion))
	writeReleaseConfig(t, release, challengeInitConfig(root, binding.PolicyID, binding.PolicyVersion))
	if err := os.WriteFile(sealed, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checker.Precheck(context.Background(), "v1", release); !errors.Is(err, ErrPolicyNotInstalled) || delegate.calls != 1 {
		t.Fatalf("damaged policy: err=%v delegate calls=%d", err, delegate.calls)
	}
}

func TestPolicyPrecheckerPassesReleasesWithoutChallenge(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(root, "releases", "r1")
	writeReleaseConfig(t, release, "http {\n  server { listen 80; }\n}\n")
	delegate := &recordingPrechecker{}
	checker, err := NewPolicyPrechecker(root, "nginx.conf", delegate)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker.Precheck(context.Background(), "v1", release); err != nil || delegate.calls != 1 {
		t.Fatalf("no challenge: err=%v delegate calls=%d", err, delegate.calls)
	}
}

func TestPolicyPrecheckerRefusesPolicyPathsOutsideTheStateRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	release := filepath.Join(root, "releases", "r1")
	delegate := &recordingPrechecker{}
	checker, err := NewPolicyPrechecker(root, "nginx.conf", delegate)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{
		challengeInitConfig("/var/lib/elsewhere", binding.PolicyID, binding.PolicyVersion),
		fmt.Sprintf("policy_path = %q", filepath.Join(root, "challenge", "policies", "not-a-uuid", "versions", "00000000000000000007.json")),
		fmt.Sprintf("policy_path = %q", filepath.Join(root, "challenge", "policies", binding.PolicyID, "versions", "7.json")),
		fmt.Sprintf("policy_path = %q", filepath.Join(root, "challenge", "policies", binding.PolicyID, "current.json")),
	} {
		writeReleaseConfig(t, release, config)
		if err := checker.Precheck(context.Background(), "v1", release); !errors.Is(err, ErrPolicyNotInstalled) {
			t.Fatalf("%s: err=%v", config, err)
		}
	}
	if delegate.calls != 0 {
		t.Fatalf("delegate ran %d times", delegate.calls)
	}
}
