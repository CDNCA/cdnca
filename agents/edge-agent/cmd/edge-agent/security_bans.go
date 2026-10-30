package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
)

// securityBanRuntime applies the ban list library's snapshots:
// verifies the control plane signature with the node's artifact trust,
// keeps revision order, posts the runtime part to the loopback health server
// (cdnca_banlist.apply) and raises the listed bans to the kernel firewall
// like CC / WAF automatic bans. The last applied snapshot is re-posted after
// OpenResty restarts (reapply, from the runtime status poller).
type securityBanRuntime struct {
	nodeID    string
	trusted   securityban.TrustedKeyFunc
	healthURL string
	client    *http.Client
	now       func() time.Time

	mu      sync.Mutex
	applied *securityban.List
	// kernel: listed bans waiting for the kernel ban path (WAF queue line
	// form), drained by the runtime status poller's goroutine.
	kernel      bytes.Buffer
	reappliedAt time.Time
}

func newSecurityBanRuntime(nodeID string, trusted securityban.TrustedKeyFunc, healthURL string, timeout time.Duration,
	now func() time.Time) *securityBanRuntime {
	if nodeID == "" || trusted == nil || healthURL == "" || now == nil {
		return nil
	}
	return &securityBanRuntime{nodeID: nodeID, trusted: trusted, healthURL: healthURL, now: now,
		client: &http.Client{
			Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, ResponseHeaderTimeout: timeout},
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}}
}

var errSecurityBanStale = errors.New("security ban list revision is older than the node's")

// ApplySecurityBans implements gatewayclient.SecurityBanApplier.
func (runtime *securityBanRuntime) ApplySecurityBans(encoded []byte) gatewayclient.SecurityBanResult {
	list, err := securityban.Open(encoded, runtime.nodeID, runtime.trusted)
	switch {
	case errors.Is(err, securityban.ErrUntrusted):
		return gatewayclient.SecurityBanResult{ErrorCode: securityban.ErrorUntrusted}
	case err != nil:
		return gatewayclient.SecurityBanResult{ErrorCode: securityban.ErrorInvalid}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.applied != nil && list.Revision < runtime.applied.Revision {
		return gatewayclient.SecurityBanResult{ErrorCode: securityban.ErrorStale}
	}
	result, err := runtime.post(context.Background(), list)
	if err != nil {
		slog.Warn("security ban list not applied", "revision", list.Revision, "error", err)
		code := securityban.ErrorRuntime
		if errors.Is(err, errSecurityBanStale) {
			code = securityban.ErrorStale
		}
		return gatewayclient.SecurityBanResult{ErrorCode: code}
	}
	runtime.applied = &list
	runtime.raiseKernel(list)
	slog.Info("security ban list applied", "revision", list.Revision, "bans", result.Bans, "releases", result.Releases)
	return gatewayclient.SecurityBanResult{Applied: true, Bans: result.Bans, Releases: result.Releases}
}

type securityBanApplyResult struct {
	Revision uint64 `json:"revision"`
	Bans     uint32 `json:"bans"`
	Releases uint32 `json:"releases"`
	Error    string `json:"error"`
}

func (runtime *securityBanRuntime) post(ctx context.Context, list securityban.List) (securityBanApplyResult, error) {
	body, err := json.Marshal(list.Runtime(runtime.now()))
	if err != nil {
		return securityBanApplyResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, runtime.healthURL+securityBansSuffix, bytes.NewReader(body))
	if err != nil {
		return securityBanApplyResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := runtime.client.Do(request)
	if err != nil {
		return securityBanApplyResult{}, err
	}
	defer response.Body.Close()
	var result securityBanApplyResult
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	_ = json.Unmarshal(raw, &result)
	switch {
	case response.StatusCode == http.StatusConflict:
		return result, errSecurityBanStale
	case response.StatusCode != http.StatusOK:
		return result, errors.New("ban list endpoint answered " + response.Status + " " + result.Error)
	case result.Revision != list.Revision:
		return result, errors.New("ban list endpoint applied another revision")
	}
	return result, nil
}

// raiseKernel queues listed bans for the kernel ban path (WAF queue line
// form, "<site>|<client>|<until>"); releases are left to expiry there (the
// OpenResty release takes effect at once). Called with mu held.
func (runtime *securityBanRuntime) raiseKernel(list securityban.List) {
	now := runtime.now().Unix()
	for _, ban := range list.Bans {
		if ban.Until > now && runtime.kernel.Len() < 4<<20 {
			runtime.kernel.WriteString(ban.SiteID + "|" + ban.Client + "|" + strconv.FormatInt(ban.Until, 10) + "\n")
		}
	}
}

// drainKernel returns and forgets the queued kernel lines.
func (runtime *securityBanRuntime) drainKernel() []byte {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	lines := append([]byte(nil), runtime.kernel.Bytes()...)
	runtime.kernel.Reset()
	return lines
}

// securityBanReapplyInterval: how often the applied snapshot is posted again
// (an OpenResty restart loses the dictionary; the same revision is accepted
// again and changes nothing otherwise).
const securityBanReapplyInterval = 30 * time.Second

// reapply posts the applied snapshot again at most every interval; called
// from the runtime status poller.
func (runtime *securityBanRuntime) reapply(ctx context.Context) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now := runtime.now()
	if runtime.applied == nil || now.Before(runtime.reappliedAt.Add(securityBanReapplyInterval)) {
		return
	}
	runtime.reappliedAt = now
	if _, err := runtime.post(ctx, *runtime.applied); err != nil && !errors.Is(err, errSecurityBanStale) {
		slog.Debug("security ban list re-apply failed", "error", err)
	}
}
