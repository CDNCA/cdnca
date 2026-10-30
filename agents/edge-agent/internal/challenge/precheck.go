package challenge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ErrPolicyNotInstalled refuses a release whose JS challenge loads a policy
// version this node has not installed (the challenge secret rollout has not
// reached it). nginx -t accepts such a configuration, but the master's
// init_by_lua fails ("no valid challenge policy"), so the release must never
// be reloaded.
var ErrPolicyNotInstalled = errors.New("challenge policy is not installed on this node")

// maxReleaseConfigBytes bounds the configuration read for the check.
const maxReleaseConfigBytes = 256 << 20

// policyPathPattern finds the engine's policy_path option, as both renderers
// write it (Go %q, a valid Lua string).
var policyPathPattern = regexp.MustCompile(`policy_path\s*=\s*("(?:[^"\\\n]|\\.)*")`)

type releasePrechecker interface {
	Precheck(context.Context, string, string) error
}

// PolicyPrechecker refuses a release before the runtime precheck when a
// challenge policy it loads is missing or invalid under stateRoot (the root
// the challenge artifact installer writes to).
type PolicyPrechecker struct {
	stateRoot  string
	configFile string
	delegate   releasePrechecker
}

func NewPolicyPrechecker(stateRoot, configFile string, delegate releasePrechecker) (*PolicyPrechecker, error) {
	if !cleanAbsoluteNonRoot(stateRoot) || configFile == "" || filepath.IsAbs(configFile) ||
		filepath.Clean(configFile) != configFile || strings.HasPrefix(configFile, "..") || delegate == nil {
		return nil, invalid("invalid challenge policy precheck configuration")
	}
	return &PolicyPrechecker{stateRoot: stateRoot, configFile: configFile, delegate: delegate}, nil
}

func (checker *PolicyPrechecker) Precheck(ctx context.Context, versionID, releasePath string) error {
	if checker == nil || !filepath.IsAbs(releasePath) {
		return invalid("invalid challenge policy precheck")
	}
	config, err := readReleaseConfig(filepath.Join(releasePath, checker.configFile))
	if err != nil {
		return err
	}
	for _, match := range policyPathPattern.FindAllSubmatch(config, -1) {
		path, err := strconv.Unquote(string(match[1]))
		if err != nil {
			return fmt.Errorf("%w: unreadable policy_path", ErrPolicyNotInstalled)
		}
		if err := checker.verifyPolicyPath(path); err != nil {
			return err
		}
	}
	return checker.delegate.Precheck(ctx, versionID, releasePath)
}

func readReleaseConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing to load; the runtime precheck (nginx -t) refuses it.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read release configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxReleaseConfigBytes {
		return nil, invalid("release configuration is not a bounded regular file")
	}
	return os.ReadFile(path)
}

// verifyPolicyPath accepts <stateRoot>/challenge/policies/<id>/versions/<20
// digit version>.json holding that installed version.
func (checker *PolicyPrechecker) verifyPolicyPath(path string) error {
	prefix := filepath.Join(checker.stateRoot, "challenge", "policies") + string(filepath.Separator)
	rest, ok := strings.CutPrefix(path, prefix)
	parts := strings.Split(rest, string(filepath.Separator))
	if !ok || filepath.Clean(path) != path || len(parts) != 3 || parts[1] != "versions" ||
		len(parts[2]) != 25 || !strings.HasSuffix(parts[2], ".json") {
		return fmt.Errorf("%w: policy path %s is outside %s", ErrPolicyNotInstalled, path, prefix)
	}
	policyID, err := uuid.Parse(parts[0])
	version, versionErr := strconv.ParseUint(strings.TrimSuffix(parts[2], ".json"), 10, 64)
	if err != nil || policyID.String() != parts[0] || versionErr != nil || version == 0 || version > MaxPolicyVersion {
		return fmt.Errorf("%w: invalid policy path %s", ErrPolicyNotInstalled, path)
	}
	return VerifyInstalledPolicy(checker.stateRoot, parts[0], version)
}

// VerifyInstalledPolicy reports whether the sealed policy version the engine
// loads exists under stateRoot and still compiles (its keys readable).
func VerifyInstalledPolicy(stateRoot, policyID string, version uint64) error {
	versions, err := openDirectoryPath(filepath.Join(stateRoot, "challenge", "policies", policyID, "versions"), false)
	if err != nil {
		return fmt.Errorf("%w: policy %s version %d (%v)", ErrPolicyNotInstalled, policyID, version, err)
	}
	defer versions.Close()
	stored, exists, err := readStoredPolicy(versions, versionFilename(version))
	if err != nil || !exists || stored.policy.PolicyVersion != version {
		return fmt.Errorf("%w: policy %s version %d", ErrPolicyNotInstalled, policyID, version)
	}
	return nil
}
