package updater

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const downloadPolicyStateFile = "download-policy.json"

// InstalledDownloadPolicy is what install-node.sh pinned from the upgrade
// trust document: the fixed endpoint and the root that verifies it.
type InstalledDownloadPolicy struct {
	Host      string
	Port      uint16
	Addresses []string
	RootPEM   []byte
	Timeout   time.Duration
}

// downloadPolicyState is the adopted policy on disk: the control-signed
// policy and the issue time of the execution that carried it.
type downloadPolicyState struct {
	IssuedAt int64                             `json:"issued_at"`
	Policy   entitlement.UpgradeDownloadPolicy `json:"policy"`
}

// PolicyDownloader is the upgrade Downloader whose endpoint follows the
// control plane (fix-btenv3): an upgrade execution verified with the
// installed control key may carry the control plane's current download
// policy (addresses, port, root), so a control plane moved to another host
// or between the plain and BaoTa layouts keeps upgrading its nodes without
// reinstalling them. Only the same host is accepted (it is the TLS name the
// node verifies); "system" keeps the root selected at install time. The
// newest policy by execution issue time wins and survives restarts.
type PolicyDownloader struct {
	mu        sync.Mutex
	dir       string
	installed InstalledDownloadPolicy
	issuedAt  int64
	current   entitlement.UpgradeDownloadPolicy
	active    *HTTPSDownloader
}

func NewPolicyDownloader(dir string, installed InstalledDownloadPolicy) (*PolicyDownloader, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || installed.Host == "" || installed.Port == 0 ||
		len(installed.Addresses) == 0 || len(installed.RootPEM) == 0 || installed.Timeout <= 0 {
		return nil, fmt.Errorf("%w: incomplete download policy", ErrDownloadPolicy)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	downloader := &PolicyDownloader{dir: dir, installed: installed,
		current: entitlement.UpgradeDownloadPolicy{Host: installed.Host, Port: installed.Port,
			Addresses: append([]string(nil), installed.Addresses...), RootCA: entitlement.UpgradeDownloadSystemRoot}}
	active, err := downloader.build(downloader.current)
	if err != nil {
		return nil, err
	}
	downloader.active = active
	downloader.restore()
	return downloader, nil
}

// restore applies the persisted policy; an unusable file is ignored (the
// installed policy stays) and replaced by the next adopted one.
func (downloader *PolicyDownloader) restore() {
	content, err := os.ReadFile(filepath.Join(downloader.dir, downloadPolicyStateFile))
	if err != nil {
		return
	}
	var state downloadPolicyState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || state.IssuedAt <= 0 || state.Policy.Host != downloader.installed.Host {
		return
	}
	active, err := downloader.build(state.Policy)
	if err != nil {
		return
	}
	downloader.issuedAt, downloader.current, downloader.active = state.IssuedAt, state.Policy, active
}

// Adopt applies the policy of a verified execution issued at issuedAt
// (unix seconds). It reports whether the endpoint changed; a policy for
// another host, an older one or an unusable one is ignored.
func (downloader *PolicyDownloader) Adopt(policy *entitlement.UpgradeDownloadPolicy, downloadURL string, issuedAt int64) (bool, error) {
	if downloader == nil || policy == nil {
		return false, nil
	}
	downloader.mu.Lock()
	defer downloader.mu.Unlock()
	if policy.Host != downloader.installed.Host || issuedAt < downloader.issuedAt || policy.Validate(downloadURL) != nil {
		return false, nil
	}
	if issuedAt == downloader.issuedAt || samePolicy(*policy, downloader.current) {
		if issuedAt > downloader.issuedAt {
			downloader.issuedAt = issuedAt
		}
		return false, nil
	}
	active, err := downloader.build(*policy)
	if err != nil {
		return false, nil
	}
	state, err := json.Marshal(downloadPolicyState{IssuedAt: issuedAt, Policy: *policy})
	if err != nil {
		return false, err
	}
	if err := writeOwnerOnlyFile(downloader.dir, downloadPolicyStateFile, state); err != nil {
		return false, err
	}
	copied := *policy
	copied.Addresses = append([]string(nil), policy.Addresses...)
	downloader.issuedAt, downloader.current, downloader.active = issuedAt, copied, active
	return true, nil
}

// Current is the endpoint in use (for status and tests).
func (downloader *PolicyDownloader) Current() entitlement.UpgradeDownloadPolicy {
	downloader.mu.Lock()
	defer downloader.mu.Unlock()
	current := downloader.current
	current.Addresses = append([]string(nil), current.Addresses...)
	return current
}

func (downloader *PolicyDownloader) Download(ctx context.Context, request DownloadRequest, destination io.Writer) error {
	downloader.mu.Lock()
	active := downloader.active
	downloader.mu.Unlock()
	return active.Download(ctx, request, destination)
}

func (downloader *PolicyDownloader) build(policy entitlement.UpgradeDownloadPolicy) (*HTTPSDownloader, error) {
	rootPEM := downloader.installed.RootPEM
	if policy.RootCA != entitlement.UpgradeDownloadSystemRoot {
		rootPEM = []byte(policy.RootCA)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("%w: download root CA is invalid", ErrDownloadPolicy)
	}
	addresses := make([]netip.Addr, 0, len(policy.Addresses))
	for _, raw := range policy.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid fixed address", ErrDownloadPolicy)
		}
		addresses = append(addresses, address.Unmap())
	}
	return NewHTTPSDownloader(HTTPSPolicy{
		Hosts:   map[string]HostPolicy{policy.Host: {Addresses: addresses, Ports: []uint16{policy.Port}}},
		Timeout: downloader.installed.Timeout, RootCAs: roots,
	})
}

func samePolicy(left, right entitlement.UpgradeDownloadPolicy) bool {
	if left.Host != right.Host || left.Port != right.Port || left.RootCA != right.RootCA || len(left.Addresses) != len(right.Addresses) {
		return false
	}
	for index := range left.Addresses {
		if left.Addresses[index] != right.Addresses[index] {
			return false
		}
	}
	return true
}

func writeOwnerOnlyFile(dir, name string, content []byte) error {
	temporary, err := os.CreateTemp(dir, ".download-policy-*.json")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(dir, name)); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
