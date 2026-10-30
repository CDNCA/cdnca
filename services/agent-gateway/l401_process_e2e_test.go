package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const l401ProcessTimeout = 4 * time.Minute

type l401ProcessE2EConfig struct {
	natsURL             string
	natsCredentialsFile string
	natsCAFile          string
	controlBaseURL      string
	controlCAFile       string
	controlTokenFile    string
	controlScopeID      string
	nodeID              string
	oldRolloutID        string
	newRolloutID        string
	oldDeploymentID     string
	newDeploymentID     string
	agentBinary         string
	agentConfigFile     string
}

type l401CommandEvidence struct {
	command   *agentv1.DeploymentCommand
	sequence  uint64
	published time.Time
}

type l401StatusEvidence struct {
	status    *agentv1.DeploymentStatus
	sequence  uint64
	published time.Time
}

type l401RolloutSnapshot struct {
	ID              string `json:"id"`
	ConfigVersionID string `json:"config_version_id"`
	State           string `json:"state"`
	Progress        struct {
		Total     int `json:"total"`
		Pending   int `json:"pending"`
		Running   int `json:"running"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
		Cancelled int `json:"cancelled"`
	} `json:"progress"`
}

type l401DeploymentPage struct {
	Items []struct {
		ID      string  `json:"id"`
		NodeID  *string `json:"node_id"`
		Attempt uint32  `json:"attempt"`
		State   string  `json:"state"`
	} `json:"items"`
}

func loadL401ProcessE2EConfig(lookup func(string) (string, bool)) (l401ProcessE2EConfig, bool, error) {
	if lookup == nil {
		return l401ProcessE2EConfig{}, false, fmt.Errorf("L4-01 environment lookup is required")
	}
	enabled, _ := lookup("L401_PROCESS_E2E")
	if enabled == "" {
		return l401ProcessE2EConfig{}, false, nil
	}
	if enabled != "1" {
		return l401ProcessE2EConfig{}, true, fmt.Errorf("L401_PROCESS_E2E must equal 1")
	}
	required := func(name string) (string, error) {
		value, ok := lookup(name)
		if !ok || value == "" || strings.TrimSpace(value) != value {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	var config l401ProcessE2EConfig
	var err error
	for _, field := range []struct {
		name string
		set  func(string)
	}{
		{"L401_NATS_URL", func(value string) { config.natsURL = value }},
		{"L401_CONTROL_BASE_URL", func(value string) { config.controlBaseURL = value }},
		{"L401_CONTROL_BEARER_TOKEN_FILE", func(value string) { config.controlTokenFile = value }},
		{"L401_CONTROL_SCOPE_ID", func(value string) { config.controlScopeID = value }},
		{"L401_NODE_ID", func(value string) { config.nodeID = value }},
		{"L401_OLD_ROLLOUT_ID", func(value string) { config.oldRolloutID = value }},
		{"L401_NEW_ROLLOUT_ID", func(value string) { config.newRolloutID = value }},
		{"L401_OLD_DEPLOYMENT_ID", func(value string) { config.oldDeploymentID = value }},
		{"L401_NEW_DEPLOYMENT_ID", func(value string) { config.newDeploymentID = value }},
		{"L401_AGENT_BINARY", func(value string) { config.agentBinary = value }},
		{"L401_AGENT_CONFIG_FILE", func(value string) { config.agentConfigFile = value }},
	} {
		value, loadErr := required(field.name)
		if loadErr != nil {
			return l401ProcessE2EConfig{}, true, loadErr
		}
		field.set(value)
	}
	config.natsCredentialsFile, _ = lookup("L401_NATS_CREDENTIALS_FILE")
	config.natsCAFile, _ = lookup("L401_NATS_CA_FILE")
	config.controlCAFile, _ = lookup("L401_CONTROL_CA_FILE")
	if err = validateL401URL(config.natsURL, true); err != nil {
		return l401ProcessE2EConfig{}, true, err
	}
	if err = validateL401URL(config.controlBaseURL, false); err != nil {
		return l401ProcessE2EConfig{}, true, err
	}
	if strings.HasPrefix(config.natsURL, "tls://") && config.natsCAFile == "" {
		return l401ProcessE2EConfig{}, true, fmt.Errorf("L401_NATS_CA_FILE is required for TLS")
	}
	identities := []string{config.controlScopeID, config.nodeID, config.oldRolloutID, config.newRolloutID,
		config.oldDeploymentID, config.newDeploymentID}
	seen := make(map[string]bool, len(identities))
	for _, identity := range identities {
		parsed, parseErr := uuid.Parse(identity)
		if parseErr != nil || parsed == uuid.Nil || parsed.String() != identity || seen[identity] {
			return l401ProcessE2EConfig{}, true, fmt.Errorf("L4-01 identities must be distinct canonical UUIDs")
		}
		seen[identity] = true
	}
	for _, file := range []struct {
		path       string
		executable bool
		private    bool
	}{
		{config.controlTokenFile, false, true},
		{config.agentBinary, true, false},
		{config.agentConfigFile, false, false},
		{config.natsCredentialsFile, false, true},
		{config.natsCAFile, false, false},
		{config.controlCAFile, false, false},
	} {
		if file.path == "" {
			continue
		}
		info, statErr := os.Lstat(file.path)
		if statErr != nil || !filepath.IsAbs(file.path) || filepath.Clean(file.path) != file.path ||
			info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || file.executable && info.Mode().Perm()&0o111 == 0 ||
			file.private && info.Mode().Perm()&0o077 != 0 {
			return l401ProcessE2EConfig{}, true, fmt.Errorf("L4-01 input file is invalid")
		}
	}
	return config, true, nil
}

func validateL401URL(value string, natsURL bool) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("L4-01 endpoint URL is invalid")
	}
	if natsURL {
		if parsed.Scheme != "nats" && parsed.Scheme != "tls" || parsed.Path != "" {
			return fmt.Errorf("L4-01 NATS URL must use nats or tls")
		}
		return nil
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && l401Loopback(parsed.Hostname())) {
		return fmt.Errorf("L4-01 Control URL requires HTTPS outside loopback")
	}
	return nil
}

func l401Loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func TestL401GatewayProcessE2E(t *testing.T) {
	config, enabled, err := loadL401ProcessE2EConfig(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("L401_PROCESS_E2E=1 is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), l401ProcessTimeout)
	defer cancel()

	connection := connectL401NATS(t, config)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		t.Fatal("L4-01 JetStream is unavailable")
	}
	natsConfig := DefaultNATSCommandBusConfig()
	commands := loadL401QueuedCommands(t, js, natsConfig, config)
	oldCommand := commands[config.oldDeploymentID]
	newCommand := commands[config.newDeploymentID]
	if oldCommand == nil || newCommand == nil || !oldCommand.published.Before(newCommand.published) ||
		oldCommand.command.GetRolloutId() != config.oldRolloutID || newCommand.command.GetRolloutId() != config.newRolloutID {
		t.Fatal("L4-01 Control did not queue the exact ordered old/new rollout commands before Agent start")
	}
	statusInfo, err := js.StreamInfo(natsConfig.StatusStream)
	if err != nil {
		t.Fatal("L4-01 status stream is unavailable")
	}
	firstStatusSequence := statusInfo.State.LastSeq + 1
	client := newL401ControlClient(t, config)
	assertL401RolloutExists(t, ctx, client, config, config.oldRolloutID, oldCommand.command.GetConfigVersionId())
	assertL401RolloutExists(t, ctx, client, config, config.newRolloutID, newCommand.command.GetConfigVersionId())

	stopAgent := startL401Agent(t, config)
	t.Cleanup(stopAgent)
	statuses := waitL401TerminalStatuses(t, ctx, js, natsConfig, config, commands, firstStatusSequence)
	oldStatus := statuses[config.oldDeploymentID]
	newStatus := statuses[config.newDeploymentID]
	if oldStatus == nil || newStatus == nil || !oldStatus.published.After(newCommand.published) {
		t.Fatal("L4-01 did not prove the older rollout terminal status arrived after the newer rollout was queued")
	}
	if oldStatus.status.GetConfigVersionId() != oldCommand.command.GetConfigVersionId() ||
		newStatus.status.GetConfigVersionId() != newCommand.command.GetConfigVersionId() {
		t.Fatal("L4-01 terminal status changed the authoritative deployment/config identity")
	}
	waitL401ControlFinalState(t, ctx, client, config, config.oldRolloutID, config.oldDeploymentID)
	waitL401ControlFinalState(t, ctx, client, config, config.newRolloutID, config.newDeploymentID)
	waitL401CommandsAcknowledged(t, ctx, js, natsConfig.CommandStream, oldCommand.sequence, newCommand.sequence)
	t.Logf("L401_GATEWAY_PROCESS_E2E PASS old_status_puback=%s/%d new_status_puback=%s/%d",
		natsConfig.StatusStream, oldStatus.sequence, natsConfig.StatusStream, newStatus.sequence)
}

func connectL401NATS(t *testing.T, config l401ProcessE2EConfig) *nats.Conn {
	t.Helper()
	options := []nats.Option{nats.Name("cdnca-l401-process-e2e"), nats.Timeout(5 * time.Second), nats.MaxReconnects(0)}
	if config.natsCredentialsFile != "" {
		options = append(options, nats.UserCredentials(config.natsCredentialsFile))
	}
	if config.natsCAFile != "" {
		certificate, err := os.ReadFile(config.natsCAFile)
		if err != nil {
			t.Fatal("L4-01 NATS CA could not be read")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			t.Fatal("L4-01 NATS CA is invalid")
		}
		options = append(options, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}))
	}
	connection, err := nats.Connect(config.natsURL, options...)
	if err != nil {
		t.Fatal("L4-01 NATS connection failed")
	}
	return connection
}

func loadL401QueuedCommands(t *testing.T, js nats.JetStreamContext, natsConfig NATSCommandBusConfig,
	config l401ProcessE2EConfig,
) map[string]*l401CommandEvidence {
	t.Helper()
	info, err := js.StreamInfo(natsConfig.CommandStream)
	if err != nil || info.State.Msgs == 0 {
		t.Fatal("L4-01 command stream has no Control-produced input")
	}
	first := info.State.FirstSeq
	if info.State.LastSeq-first > 10_000 {
		first = info.State.LastSeq - 10_000
	}
	wantSubject := natsConfig.CommandSubjectPrefix + "." + config.nodeID
	result := make(map[string]*l401CommandEvidence, 2)
	for sequence := first; sequence <= info.State.LastSeq; sequence++ {
		message, getErr := js.GetMsg(natsConfig.CommandStream, sequence)
		if errors.Is(getErr, nats.ErrMsgNotFound) {
			continue
		}
		if getErr != nil {
			t.Fatal("L4-01 command readback failed")
		}
		if message.Subject != wantSubject {
			continue
		}
		command := new(agentv1.DeploymentCommand)
		if (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, command) != nil {
			continue
		}
		if command.GetDeploymentId() != config.oldDeploymentID && command.GetDeploymentId() != config.newDeploymentID {
			continue
		}
		if message.Header.Get(nats.MsgIdHdr) != command.GetEvent().GetEventId() || message.Sequence == 0 || message.Time.IsZero() {
			t.Fatal("L4-01 command wire identity is invalid")
		}
		result[command.GetDeploymentId()] = &l401CommandEvidence{command: command, sequence: message.Sequence, published: message.Time}
	}
	return result
}

func newL401ControlClient(t *testing.T, config l401ProcessE2EConfig) *http.Client {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if config.controlCAFile != "" {
		certificate, err := os.ReadFile(config.controlCAFile)
		if err != nil {
			t.Fatal("L4-01 Control CA could not be read")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			t.Fatal("L4-01 Control CA is invalid")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func l401ControlGet(t *testing.T, ctx context.Context, client *http.Client, config l401ProcessE2EConfig,
	path string, target any,
) {
	t.Helper()
	token, err := os.ReadFile(config.controlTokenFile)
	if err != nil || strings.TrimSpace(string(token)) == "" {
		t.Fatal("L4-01 Control token is unavailable")
	}
	endpoint, err := url.Parse(config.controlBaseURL)
	if err != nil {
		t.Fatal("L4-01 Control URL is invalid")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	query := endpoint.Query()
	query.Set("scope_id", config.controlScopeID)
	if strings.HasSuffix(path, "/deployments") {
		query.Set("limit", "100")
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		t.Fatal("L4-01 Control request could not be built")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("L4-01 Control request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		t.Fatalf("L4-01 Control request returned %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(payload) > 1<<20 {
		t.Fatal("L4-01 Control response exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatal("L4-01 Control response is invalid")
	}
}

func assertL401RolloutExists(t *testing.T, ctx context.Context, client *http.Client, config l401ProcessE2EConfig,
	rolloutID, configVersionID string,
) {
	t.Helper()
	var snapshot l401RolloutSnapshot
	l401ControlGet(t, ctx, client, config, "/v1/admin/site-rollouts/"+url.PathEscape(rolloutID), &snapshot)
	if snapshot.ID != rolloutID || snapshot.ConfigVersionID != configVersionID {
		t.Fatal("L4-01 Control rollout does not match the queued Gateway command")
	}
}

func startL401Agent(t *testing.T, config l401ProcessE2EConfig) func() {
	t.Helper()
	logFile, err := os.OpenFile(filepath.Join(t.TempDir(), "edge-agent.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("L4-01 Agent log could not be created")
	}
	command := exec.Command(config.agentBinary, "-config", config.agentConfigFile)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal("L4-01 Agent could not start")
	}
	return func() {
		if command.Process == nil {
			_ = logFile.Close()
			return
		}
		_ = command.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		_ = logFile.Close()
	}
}

func waitL401TerminalStatuses(t *testing.T, ctx context.Context, js nats.JetStreamContext,
	natsConfig NATSCommandBusConfig, config l401ProcessE2EConfig, commands map[string]*l401CommandEvidence, firstSequence uint64,
) map[string]*l401StatusEvidence {
	t.Helper()
	result := make(map[string]*l401StatusEvidence, 2)
	bus := &NATSCommandBus{config: natsConfig}
	next := firstSequence
	for len(result) < 2 {
		if ctx.Err() != nil {
			t.Fatal("L4-01 terminal statuses timed out")
		}
		info, err := js.StreamInfo(natsConfig.StatusStream)
		if err != nil {
			t.Fatal("L4-01 status stream readback failed")
		}
		for sequence := next; sequence <= info.State.LastSeq; sequence++ {
			message, getErr := js.GetMsg(natsConfig.StatusStream, sequence)
			if errors.Is(getErr, nats.ErrMsgNotFound) {
				continue
			}
			if getErr != nil {
				t.Fatal("L4-01 status message readback failed")
			}
			status := new(agentv1.DeploymentStatus)
			if (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, status) != nil ||
				(status.GetDeploymentId() != config.oldDeploymentID && status.GetDeploymentId() != config.newDeploymentID) ||
				status.GetState() != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				continue
			}
			if !l401StatusMatchesCommand(status, commands[status.GetDeploymentId()]) {
				t.Fatal("L4-01 terminal status does not match the authoritative command identity")
			}
			if !bus.exactDeploymentStatusHeaders(message.Header, status.GetEvent().GetEventId(), message.Data) ||
				message.Subject != natsConfig.StatusSubjectPrefix+".generic-v2."+config.nodeID+"."+status.GetEvent().GetEventId() ||
				message.Sequence == 0 || message.Time.IsZero() {
				t.Fatal("L4-01 terminal status is not the exact Gateway durable publication")
			}
			result[status.GetDeploymentId()] = &l401StatusEvidence{status: status, sequence: message.Sequence, published: message.Time}
		}
		next = info.State.LastSeq + 1
		if len(result) < 2 {
			time.Sleep(250 * time.Millisecond)
		}
	}
	return result
}

func l401StatusMatchesCommand(status *agentv1.DeploymentStatus, evidence *l401CommandEvidence) bool {
	return status != nil && evidence != nil && evidence.command != nil &&
		status.GetDeploymentId() == evidence.command.GetDeploymentId() &&
		status.GetAttempt() == evidence.command.GetAttempt() &&
		status.GetConfigVersionId() == evidence.command.GetConfigVersionId()
}

func waitL401ControlFinalState(t *testing.T, ctx context.Context, client *http.Client, config l401ProcessE2EConfig,
	rolloutID, deploymentID string,
) {
	t.Helper()
	for ctx.Err() == nil {
		var rollout l401RolloutSnapshot
		l401ControlGet(t, ctx, client, config, "/v1/admin/site-rollouts/"+url.PathEscape(rolloutID), &rollout)
		var deployments l401DeploymentPage
		l401ControlGet(t, ctx, client, config, "/v1/admin/site-rollouts/"+url.PathEscape(rolloutID)+"/deployments", &deployments)
		for _, deployment := range deployments.Items {
			if deployment.ID == deploymentID && deployment.NodeID != nil && *deployment.NodeID == config.nodeID &&
				deployment.State == "healthy" && rollout.State == "succeeded" && rollout.Progress.Succeeded == rollout.Progress.Total {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("L4-01 Control rollout did not reach the exact final deployment state")
}

func waitL401CommandsAcknowledged(t *testing.T, ctx context.Context, js nats.JetStreamContext, stream string,
	sequences ...uint64,
) {
	t.Helper()
	for ctx.Err() == nil {
		remaining := 0
		for _, sequence := range sequences {
			_, err := js.GetMsg(stream, sequence)
			if err == nil {
				remaining++
				continue
			}
			if !errors.Is(err, nats.ErrMsgNotFound) {
				t.Fatal("L4-01 command acknowledgement readback failed")
			}
		}
		if remaining == 0 {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("L4-01 Gateway did not acknowledge both authoritative command deliveries")
}
