package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
)

func TestPluginRuntimeCompositionEnvironmentIsAllOrNothing(t *testing.T) {
	names := []string{"PLUGIN_RUNTIME_PROVIDER_URL", "PLUGIN_RUNTIME_PROJECTION_URL", "PLUGIN_RUNTIME_CLIENT_CERT_FILE",
		"PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", "PLUGIN_RUNTIME_LICENSE_CA_FILE", "PLUGIN_RUNTIME_CLIENT_STATE_FILE"}
	for _, name := range names {
		t.Setenv(name, "")
	}
	t.Setenv("PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE", "")
	if _, err := loadPluginRuntimeCompositionEnvironment(); err == nil {
		t.Fatal("empty plugin runtime composition environment was accepted")
	}
	directory := t.TempDir()
	setPluginRuntimeCompositionEnvironment(t, directory)
	loaded, err := loadPluginRuntimeCompositionEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProviderURL != "https://runtime.example.test" || loaded.ProjectionURL != "https://license.example.test" ||
		loaded.ClientCertFile != filepath.Join(directory, "runtime.crt") ||
		loaded.ClientKeyFile != filepath.Join(directory, "runtime.key") ||
		loaded.LicenseCAFile != filepath.Join(directory, "runtime-ca.crt") ||
		loaded.ClientStateFile != filepath.Join(directory, "runtime-state.json") || loaded.BootstrapServerCAFile != "" {
		t.Fatalf("environment = %+v", loaded)
	}
	bootstrapCA := filepath.Join(t.TempDir(), "bootstrap-ca.crt")
	t.Setenv("PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE", bootstrapCA)
	loaded, err = loadPluginRuntimeCompositionEnvironment()
	if err != nil || loaded.BootstrapServerCAFile != bootstrapCA {
		t.Fatalf("bootstrap environment = %+v, %v", loaded, err)
	}

	for _, test := range []struct {
		name, variable, value string
	}{
		{name: "missing state", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: ""},
		{name: "relative state", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: "runtime-state.json"},
		{name: "unclean state", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: directory + "/nested/../runtime-state.json"},
		{name: "state aliases certificate", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: filepath.Join(directory, "runtime.crt")},
		{name: "state aliases key", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: filepath.Join(directory, "runtime.key")},
		{name: "state aliases CA", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: filepath.Join(directory, "runtime-ca.crt")},
		{name: "key aliases certificate", variable: "PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", value: filepath.Join(directory, "runtime.crt")},
		{name: "CA aliases certificate", variable: "PLUGIN_RUNTIME_LICENSE_CA_FILE", value: filepath.Join(directory, "runtime.crt")},
		{name: "key aliases CA", variable: "PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", value: filepath.Join(directory, "runtime-ca.crt")},
		{name: "split key directory", variable: "PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE", value: filepath.Join(t.TempDir(), "runtime.key")},
		{name: "split CA directory", variable: "PLUGIN_RUNTIME_LICENSE_CA_FILE", value: filepath.Join(t.TempDir(), "runtime-ca.crt")},
		{name: "split state directory", variable: "PLUGIN_RUNTIME_CLIENT_STATE_FILE", value: filepath.Join(t.TempDir(), "runtime-state.json")},
		{name: "relative bootstrap CA", variable: "PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE", value: "bootstrap-ca.crt"},
		{name: "unclean bootstrap CA", variable: "PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE", value: directory + "/nested/../bootstrap-ca.crt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setPluginRuntimeCompositionEnvironment(t, directory)
			t.Setenv(test.variable, test.value)
			if _, err := loadPluginRuntimeCompositionEnvironment(); err == nil {
				t.Fatalf("%s=%q was accepted", test.variable, test.value)
			}
		})
	}
}

func TestPluginInstallationRuntimeIsOptionalWithoutProvider(t *testing.T) {
	t.Setenv("PLUGIN_RUNTIME_PROVIDER_URL", "")
	factory, err := buildPluginInstallationHandlerFactory(t.Context(), config.Config{LicenseServiceURL: "https://license.example.test"}, nil, nil, nil)
	if err != nil || factory != nil {
		t.Fatalf("buildPluginInstallationHandlerFactory() = (%v, %v), want disabled runtime", factory, err)
	}
}

func setPluginRuntimeCompositionEnvironment(t *testing.T, directory string) {
	t.Helper()
	for name, value := range map[string]string{
		"PLUGIN_RUNTIME_PROVIDER_URL":             "https://runtime.example.test",
		"PLUGIN_RUNTIME_PROJECTION_URL":           "https://license.example.test",
		"PLUGIN_RUNTIME_CLIENT_CERT_FILE":         filepath.Join(directory, "runtime.crt"),
		"PLUGIN_RUNTIME_CLIENT_PRIVATE_KEY_FILE":  filepath.Join(directory, "runtime.key"),
		"PLUGIN_RUNTIME_LICENSE_CA_FILE":          filepath.Join(directory, "runtime-ca.crt"),
		"PLUGIN_RUNTIME_CLIENT_STATE_FILE":        filepath.Join(directory, "runtime-state.json"),
		"PLUGIN_RUNTIME_BOOTSTRAP_SERVER_CA_FILE": "",
	} {
		t.Setenv(name, value)
	}
}

func TestPluginRuntimeCompositionBootstrapsRotatingCredentialBeforeClients(t *testing.T) {
	encoded, err := os.ReadFile("plugin_runtime_composition.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(encoded)
	for _, fragment := range []string{
		"pluginruntimecomposition.NewCertificateManager(",
		"pluginruntimecomposition.CertificateManagerConfig{",
		"BaseURL: cfg.LicenseServiceURL",
		"InstallationID: installationID",
		"ActivationPrivateKey: installationKey",
		"CertificateFile: environment.ClientCertFile",
		"PrivateKeyFile: environment.ClientKeyFile",
		"RuntimeCAFile: environment.LicenseCAFile",
		"StateFile: environment.ClientStateFile",
		"BootstrapServerCAFile: environment.BootstrapServerCAFile",
		"certificateManager.Ensure(",
		"RootCAs: initialCredential.RootCAs",
		"Certificates: []tls.Certificate{initialCredential.TLSCertificate}",
		"Credentials: certificateManager",
		"defer clear(installationKey)",
	} {
		if !strings.Contains(source, fragment) {
			t.Errorf("plugin runtime certificate bootstrap lacks %q", fragment)
		}
	}
	if !strings.Contains(source, "GetClientCertificate: certificateManager.GetClientCertificate") &&
		!strings.Contains(source, "GetClientCertificate = certificateManager.GetClientCertificate") {
		t.Error("provider and projection TLS do not use the rotating manager certificate callback")
	}
	if !strings.Contains(source, "clear(initialCredential.PrivateKey)") {
		t.Error("initial runtime credential private-key copy is not cleared")
	}
	manager := strings.Index(source, "pluginruntimecomposition.NewCertificateManager(")
	ensure := strings.Index(source, "certificateManager.Ensure(")
	provider := strings.Index(source, "pluginruntimeprovider.New(")
	projection := strings.Index(source, "pluginruntimecomposition.NewProjectionClient(")
	if manager < 0 || ensure < manager || provider < ensure || projection < ensure {
		t.Errorf("credential bootstrap ordering manager=%d ensure=%d provider=%d projection=%d", manager, ensure, provider, projection)
	}
	if strings.Count(source, "Credentials: certificateManager") != 1 {
		t.Errorf("projection credential source count=%d, want exactly one", strings.Count(source, "Credentials: certificateManager"))
	}
}

func TestPluginRuntimeCompositionBuildsWorkloadAuthorizer(t *testing.T) {
	encoded, err := os.ReadFile("plugin_runtime_composition.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(encoded)
	if !strings.Contains(source, "pluginworkloadidentity.NewAuthorizer(") ||
		!strings.Contains(source, "Authorizer: workloadAuthorizer") {
		t.Fatal("plugin runtime composition does not build and inject the workload authorizer")
	}
	start := strings.Index(source, "pluginruntimecomposition.WebhookDelivererConfig{")
	if start < 0 {
		t.Fatal("webhook deliverer config not found")
	}
	configSource := source[start:]
	if end := strings.Index(configSource, "})"); end >= 0 {
		configSource = configSource[:end]
	}
	if strings.Contains(configSource, "Provider:") || strings.Contains(configSource, "Verifier:") {
		t.Fatal("webhook deliverer bypasses the workload authorizer")
	}
}

func TestRunServerPassesAuthorizedDelivererToPluginWebhookRuntime(t *testing.T) {
	path := filepath.Join("main.go")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), path, encoded, parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	foundFactory, foundDependency, foundFanout := false, false, false
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			selector, selectorOK := call.Fun.(*ast.Ident)
			foundFactory = foundFactory || selectorOK && selector.Name == "newPluginRuntimeWebhookDeliverer"
		}
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, keyOK := field.Key.(*ast.Ident)
			value, valueOK := field.Value.(*ast.Ident)
			if keyOK && valueOK && key.Name == "Deliverer" && value.Name == "authorizedDeliverer" {
				foundDependency = true
			}
			if keyOK && key.Name == "Fanout" {
				foundFanout = true
			}
		}
		return true
	})
	if !foundFactory || !foundDependency || !foundFanout ||
		!strings.Contains(string(encoded), "pluginwebhookruntime.Dependencies{") ||
		!strings.Contains(string(encoded), "domaineventfanout.New(") ||
		!strings.Contains(string(encoded), "pluginwebhook.NewDomainEventProducer(") {
		t.Fatalf("main composition missing: factory=%t dependency=%t fanout=%t", foundFactory, foundDependency, foundFanout)
	}
}
