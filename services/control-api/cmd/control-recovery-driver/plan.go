package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

const driverPlanSchema = "cdnca.control-recovery-driver.plan/v1"

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type driverPlan struct {
	Schema                  string                   `json:"schema"`
	StateDirectory          string                   `json:"state_directory"`
	ArtifactDirectory       string                   `json:"artifact_directory"`
	OperationTimeoutSeconds int64                    `json:"operation_timeout_seconds"`
	Kubernetes              kubernetesPlan           `json:"kubernetes"`
	Components              map[string]componentPlan `json:"components"`
	JetStream               jetStreamPlan            `json:"jetstream"`
	DNSProbe                dnsProbePlan             `json:"dns_probe"`
	AgentProbe              agentProbePlan           `json:"agent_probe"`
}

type kubernetesPlan struct {
	APIServer            string         `json:"api_server"`
	NamespaceFile        string         `json:"namespace_file"`
	TokenFile            string         `json:"token_file"`
	CAFile               string         `json:"ca_file"`
	SettleTimeoutSeconds int64          `json:"settle_timeout_seconds"`
	Workloads            []workloadPlan `json:"workloads"`
}

type workloadPlan struct {
	Name string `json:"name"`
}

type componentPlan struct {
	Preflight  commandPlan `json:"preflight"`
	Capture    commandPlan `json:"capture"`
	Restore    commandPlan `json:"restore"`
	Compensate commandPlan `json:"compensate"`
}

type commandPlan struct {
	Path        string            `json:"path"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"environment"`
}

type jetStreamPlan struct {
	URL                   string `json:"url"`
	CredentialsFile       string `json:"credentials_file"`
	CAFile                string `json:"ca_file"`
	ClientCertFile        string `json:"client_cert_file"`
	ClientKeyFile         string `json:"client_key_file"`
	TopologyFile          string `json:"topology_file"`
	NodeID                string `json:"node_id"`
	NodeIDUnderscore      string `json:"node_id_underscore"`
	RequestTimeoutSeconds int64  `json:"request_timeout_seconds"`
}

type dnsProbePlan struct {
	Hostname          string   `json:"hostname"`
	ExpectedAddresses []string `json:"expected_addresses"`
	TimeoutSeconds    int64    `json:"timeout_seconds"`
	IntervalSeconds   int64    `json:"interval_seconds"`
}

type agentProbePlan struct {
	URL             string `json:"url"`
	CAFile          string `json:"ca_file"`
	ClientCertFile  string `json:"client_cert_file"`
	ClientKeyFile   string `json:"client_key_file"`
	BearerTokenFile string `json:"bearer_token_file"`
	ExpectedNodes   int    `json:"expected_nodes"`
	TimeoutSeconds  int64  `json:"timeout_seconds"`
	IntervalSeconds int64  `json:"interval_seconds"`
}

func loadPlan() (driverPlan, error) {
	path := os.Getenv("CONTROL_RECOVERY_DRIVER_PLAN")
	encoded, err := controlbackup.ReadTrustedFile(path)
	if err != nil {
		return driverPlan{}, errors.New("driver plan unavailable")
	}
	if err := controlbackup.ValidatePlanSecretFields(encoded); err != nil {
		return driverPlan{}, errors.New("driver plan contains secret material")
	}
	var plan driverPlan
	if err := controlbackup.DecodeStrictJSON(encoded, &plan); err != nil || plan.validate() != nil {
		return driverPlan{}, errors.New("driver plan invalid")
	}
	return plan, nil
}

func (plan driverPlan) validate() error {
	if plan.Schema != driverPlanSchema || validatePrivateDirectory(plan.StateDirectory) != nil ||
		validatePrivateDirectory(plan.ArtifactDirectory) != nil || plan.OperationTimeoutSeconds < 1 ||
		plan.OperationTimeoutSeconds > int64((24*time.Hour)/time.Second) || plan.Kubernetes.validate() != nil ||
		plan.JetStream.validate() != nil || plan.DNSProbe.validate() != nil || plan.AgentProbe.validate() != nil {
		return errors.New("invalid driver plan")
	}
	for _, component := range []string{"postgresql", "clickhouse"} {
		configured, found := plan.Components[component]
		if !found || configured.validate() != nil {
			return errors.New("invalid component plan")
		}
	}
	if len(plan.Components) != 2 {
		return errors.New("unexpected component plan")
	}
	return nil
}

func (plan kubernetesPlan) validate() error {
	if !strings.HasPrefix(plan.APIServer, "https://") || plan.SettleTimeoutSeconds < 1 ||
		plan.SettleTimeoutSeconds > 3600 || len(plan.Workloads) < 2 || len(plan.Workloads) > 16 ||
		validateTrustedPath(plan.NamespaceFile) != nil || validateTrustedPath(plan.TokenFile) != nil ||
		validateTrustedPath(plan.CAFile) != nil {
		return errors.New("invalid kubernetes freeze plan")
	}
	seen := map[string]bool{}
	for _, workload := range plan.Workloads {
		if !safeName.MatchString(workload.Name) || seen[workload.Name] {
			return errors.New("invalid kubernetes workload")
		}
		seen[workload.Name] = true
	}
	return nil
}

func (plan componentPlan) validate() error {
	return errors.Join(plan.Preflight.validate(), plan.Capture.validate(), plan.Restore.validate(), plan.Compensate.validate())
}

func (plan commandPlan) validate() error {
	if !filepath.IsAbs(plan.Path) || filepath.Clean(plan.Path) != plan.Path || len(plan.Arguments) > 64 || len(plan.Environment) > 32 {
		return errors.New("invalid command plan")
	}
	for _, argument := range plan.Arguments {
		lower := strings.ToLower(argument)
		if strings.ContainsAny(argument, "\x00\r\n") || strings.Contains(lower, "password=") ||
			strings.Contains(lower, "token=") || strings.Contains(lower, "secret=") || strings.Contains(lower, "private-key=") {
			return errors.New("sensitive command argument")
		}
	}
	for key, value := range plan.Environment {
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(key) || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("invalid command environment")
		}
		lower := strings.ToLower(key)
		if (strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret")) &&
			!strings.HasSuffix(lower, "_file") && key != "PGPASSFILE" {
			return errors.New("inline secret environment forbidden")
		}
	}
	return nil
}

func (plan jetStreamPlan) validate() error {
	if !(strings.HasPrefix(plan.URL, "tls://") || strings.HasPrefix(plan.URL, "nats://")) ||
		plan.RequestTimeoutSeconds < 1 || plan.RequestTimeoutSeconds > 300 {
		return errors.New("invalid JetStream plan")
	}
	for _, path := range []string{plan.CredentialsFile, plan.CAFile, plan.ClientCertFile, plan.ClientKeyFile} {
		if validateTrustedPath(path) != nil {
			return errors.New("invalid JetStream secret file")
		}
	}
	if validateTrustedPath(plan.TopologyFile) != nil || !safeName.MatchString(plan.NodeID) ||
		!safeName.MatchString(plan.NodeIDUnderscore) {
		return errors.New("invalid JetStream topology authority")
	}
	return nil
}

func (plan dnsProbePlan) validate() error {
	if plan.Hostname == "" || strings.ContainsAny(plan.Hostname, "/:@?#\r\n\t ") || len(plan.ExpectedAddresses) == 0 ||
		plan.TimeoutSeconds < 1 || plan.TimeoutSeconds > 1800 || plan.IntervalSeconds < 1 || plan.IntervalSeconds > plan.TimeoutSeconds {
		return errors.New("invalid DNS probe plan")
	}
	seen := map[string]bool{}
	for _, address := range plan.ExpectedAddresses {
		if canonicalIP(address) == "" || seen[address] {
			return errors.New("invalid DNS probe address")
		}
		seen[address] = true
	}
	return nil
}

func (plan agentProbePlan) validate() error {
	if !strings.HasPrefix(plan.URL, "https://") || plan.ExpectedNodes < 1 || plan.ExpectedNodes > 100000 ||
		plan.TimeoutSeconds < 1 || plan.TimeoutSeconds > 1800 || plan.IntervalSeconds < 1 || plan.IntervalSeconds > plan.TimeoutSeconds {
		return errors.New("invalid Agent probe plan")
	}
	for _, path := range []string{plan.CAFile, plan.ClientCertFile, plan.ClientKeyFile, plan.BearerTokenFile} {
		if validateTrustedPath(path) != nil {
			return errors.New("invalid Agent probe secret file")
		}
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory must be private")
	}
	return nil
}

func validateTrustedPath(path string) error {
	_, err := controlbackup.ReadTrustedFile(path)
	return err
}
