package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// siteDropHostPusher hands the level D site names (primary and aliases,
// leading wildcards kept) to OpenResty, whose dynamic routing closes the
// requests (444) and TLS / QUIC handshakes selecting them (攻击自动升级 D 级,
// esc-node §4). PushHosts replaces the whole set; ClearHosts empties it. The
// set lives in a shared dictionary: a reload keeps it, a restart empties it
// and the executor pushes it again.
type siteDropHostPusher interface {
	PushHosts(ctx context.Context, hosts []string) error
	ClearHosts(ctx context.Context) error
}

// siteDropControlPath is the control socket location (cdnca_site_admin.lua).
const siteDropControlPath = "/site-drop"

// maxSiteDropBody stays below the control server's client_max_body_size 4m
// (edgeskeleton writeControlServer).
const maxSiteDropBody = 4<<20 - 4096

// controlSocketHostPusher is the siteDropHostPusher on the OpenResty control
// socket (edgeskeleton.ControlSocket under the state root).
type controlSocketHostPusher struct {
	client *http.Client
}

func newControlSocketHostPusher(socketPath string) *controlSocketHostPusher {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", socketPath)
	}}
	return &controlSocketHostPusher{client: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

func (p *controlSocketHostPusher) PushHosts(ctx context.Context, hosts []string) error {
	if hosts == nil {
		hosts = []string{}
	}
	body, err := json.Marshal(struct {
		Hosts []string `json:"hosts"`
	}{hosts})
	if err != nil {
		return err
	}
	if len(body) > maxSiteDropBody {
		return fmt.Errorf("site drop hosts: %d bytes exceed the control socket limit", len(body))
	}
	return p.do(ctx, http.MethodPut, body)
}

func (p *controlSocketHostPusher) ClearHosts(ctx context.Context) error {
	return p.do(ctx, http.MethodDelete, nil)
}

func (p *controlSocketHostPusher) do(ctx context.Context, method string, body []byte) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://cdnca-control"+siteDropControlPath, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("site drop hosts %s: %w", method, err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("site drop hosts %s: status %d: %s", method, response.StatusCode, bytes.TrimSpace(answer))
	}
	return nil
}
