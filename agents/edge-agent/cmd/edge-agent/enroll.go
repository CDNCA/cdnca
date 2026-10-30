package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/enrollment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
)

const (
	defaultIdentityDir   = "/etc/cdnca-edge-agent/identity"
	defaultMachineIDFile = "/etc/machine-id"
	// defaultJournalDir matches install-node.sh JOURNAL_DIR; its
	// gateway-endpoints.json is the GatewayHello list the daemon persisted.
	defaultJournalDir = "/var/lib/cdnca-edge-agent/gateway-journal"
)

type enrollmentRunner func(context.Context, enrollment.Config, []byte) (enrollment.Result, error)

func runEnrollment(ctx context.Context, config enrollment.Config, token []byte) (enrollment.Result, error) {
	return enrollment.Run(ctx, config, token)
}

func executeEnrollment(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, run enrollmentRunner) int {
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	flags := flag.NewFlagSet("edge-agent enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	address := flags.String("gateway-address", "", "Gateway enrollment host:port; omitted: the enrollment addresses of the persisted Gateway list, in order")
	serverName := flags.String("gateway-server-name", "", "Gateway TLS server name")
	rootCA := flags.String("gateway-root-ca-file", "", "absolute Gateway root CA path")
	transport := flags.String("gateway-transport", "grpc", "grpc (direct) or ws (WebSocket tunnel /agent/v1/enroll)")
	tunnelHost := flags.String("gateway-tunnel-host", "", "outer SNI/Host for the ws transport (CDN name)")
	identityDir := flags.String("identity-dir", defaultIdentityDir, "absolute identity output directory")
	machineID := flags.String("machine-id-file", defaultMachineIDFile, "absolute machine ID path")
	tokenFile := flags.String("token-file", "", "owner-only enrollment token file; stdin when omitted")
	openRestyVersion := flags.String("openresty-version", "", "installed OpenResty version metadata")
	journalDir := flags.String("journal-dir", defaultJournalDir, "absolute Agent journal directory (gateway-endpoints.json) used when --gateway-address is omitted")
	timeout := flags.Duration("timeout", 30*time.Second, "enrollment deadline")
	// Install resume (fz-x13): no Gateway call, only the pending state.
	printPendingCSR := flags.Bool("print-pending-csr-sha256", false, "print the hex SHA-256 of the pending enrollment CSR and exit")
	recoverFrom := flags.String("recover-from-response", "", "owner-only file with the controller's copy of the enrollment response; assembles the identity from the pending state")
	rejectArguments := func() int {
		logger.Error("edge agent enrollment arguments rejected", "event", "enrollment_failed", "error", "invalid enrollment arguments")
		return 2
	}
	parseErr := flags.Parse(args)
	if parseErr == nil && (*printPendingCSR || *recoverFrom != "") {
		if flags.NArg() != 0 || (*printPendingCSR && *recoverFrom != "") || *address != "" || *tokenFile != "" {
			return rejectArguments()
		}
		return resumeEnrollment(*identityDir, *machineID, *recoverFrom, stdout, logger)
	}
	if parseErr != nil || flags.NArg() != 0 || *timeout <= 0 || *timeout > 10*time.Minute || *rootCA == "" ||
		(*transport != "grpc" && *transport != "ws") || (*tunnelHost != "" && *transport != "ws") {
		return rejectArguments()
	}
	// targets: the explicit endpoint, or (ADR 0013 §5.2) every published
	// Gateway enrollment port; the server name belongs to each entry, so an
	// explicit one only goes with an explicit address.
	type target struct{ address, serverName, transport, tunnelHost string }
	var targets []target
	if *address != "" {
		if *serverName == "" {
			return rejectArguments()
		}
		targets = []target{{*address, *serverName, *transport, *tunnelHost}}
	} else {
		if *serverName != "" || *transport != "grpc" || *tunnelHost != "" || !filepath.IsAbs(*journalDir) {
			return rejectArguments()
		}
		endpoints, err := gatewayclient.LoadLearnedEndpoints(filepath.Join(*journalDir, "gateway-endpoints.json"))
		if err != nil {
			logger.Error("edge agent enrollment has no Gateway address", "event", "enrollment_failed", "error", "no --gateway-address and no persisted Gateway list")
			return 2
		}
		for _, endpoint := range endpoints {
			if endpoint.EnrollmentAddress != "" && endpoint.ServerName != "" && endpoint.Transport == "grpc" {
				targets = append(targets, target{endpoint.EnrollmentAddress, endpoint.ServerName, "grpc", ""})
			}
		}
		if len(targets) == 0 {
			logger.Error("edge agent enrollment has no Gateway address", "event", "enrollment_failed", "error", "persisted Gateway list has no enrollment address")
			return 2
		}
	}
	var token []byte
	var err error
	if *tokenFile == "" {
		token, err = enrollment.ReadToken(stdin)
	} else {
		token, err = enrollment.ReadTokenFile(*tokenFile)
	}
	if err != nil {
		logger.Error("edge agent enrollment input rejected", "event", "enrollment_failed", "error", safeLogError(err))
		return 1
	}
	defer zeroBytes(token)
	if run == nil {
		logger.Error("edge agent enrollment unavailable", "event", "enrollment_failed")
		return 1
	}
	capabilities := agentCapabilities(*openRestyVersion)
	if capabilities.BuildId == "" {
		capabilities.BuildId = "development"
	}
	if capabilities.OperatingSystem == "" {
		capabilities.OperatingSystem = runtime.GOOS
	}
	if capabilities.Architecture == "" {
		capabilities.Architecture = runtime.GOARCH
	}
	callCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var result enrollment.Result
	for index, item := range targets {
		result, err = run(callCtx, enrollment.Config{
			Address: item.address, ServerName: item.serverName, RootCAFile: *rootCA,
			Transport: item.transport, TunnelHost: item.tunnelHost,
			IdentityDir: *identityDir, MachineIDFile: *machineID,
			SupportedVersions: &commonv1.ProtocolVersionRange{
				Minimum: &commonv1.ProtocolVersion{Major: 1},
				Maximum: &commonv1.ProtocolVersion{Major: 1},
			},
			Capabilities: capabilities,
		}, token)
		// Only a Gateway-side failure (unreachable, disabled, refused) moves
		// on; the pending CSR/request ID is reused, so retries are idempotent.
		if err == nil || !errors.Is(err, enrollment.ErrEnrollmentRejected) || callCtx.Err() != nil || index == len(targets)-1 {
			break
		}
		logger.Warn("edge agent enrollment endpoint failed; trying the next Gateway", "event", "enrollment_retry", "endpoint_index", index, "error", safeLogError(err))
	}
	if err != nil {
		logger.Error("edge agent enrollment failed", "event", "enrollment_failed", "error", safeLogError(err))
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		logger.Error("edge agent enrollment result unavailable", "event", "enrollment_failed", "error", fmt.Sprintf("write result: %v", err))
		return 1
	}
	logger.Info("edge agent enrollment completed", "event", "enrollment_completed", "node_id", result.NodeID)
	return 0
}

// resumeEnrollment: without a response file prints the pending CSR digest;
// with one commits the identity and prints the enrollment result.
func resumeEnrollment(identityDir, machineID, responseFile string, stdout io.Writer, logger *slog.Logger) int {
	if responseFile == "" {
		digest, err := enrollment.PendingCSRSHA256(identityDir)
		if err != nil {
			logger.Error("edge agent pending enrollment unavailable", "event", "enrollment_resume_failed", "error", safeLogError(err))
			return 1
		}
		_, _ = fmt.Fprintln(stdout, digest)
		return 0
	}
	response, err := enrollment.ReadRecoveryResponseFile(responseFile)
	if err != nil {
		logger.Error("edge agent recovery response rejected", "event", "enrollment_resume_failed", "error", safeLogError(err))
		return 1
	}
	result, err := enrollment.Resume(enrollment.ResumeConfig{
		IdentityDir: identityDir, MachineIDFile: machineID,
		SupportedVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1},
			Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
	}, response)
	if err != nil {
		logger.Error("edge agent identity recovery failed", "event", "enrollment_resume_failed", "error", safeLogError(err))
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		logger.Error("edge agent enrollment result unavailable", "event", "enrollment_resume_failed", "error", fmt.Sprintf("write result: %v", err))
		return 1
	}
	logger.Info("edge agent identity recovered", "event", "enrollment_resumed", "node_id", result.NodeID)
	return 0
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
