package nodesshinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestInstallCommandQuotesAndSudo(t *testing.T) {
	const key = "nrk1.0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	root, err := InstallCommand("https://console.example.com", key, "203.0.113.7", "edge 'a'", true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"umask 077; d=$(mktemp -d) || exit 1; trap 'rm -rf -- \"$d\"' EXIT; IFS= read -r k || exit 1; ",
		"curl --proto '=https' -fsSL -o \"$d/install-node.sh\" 'https://console.example.com/downloads/install-node.sh' && ",
		"printf '%s\\n' \"$k\" | bash \"$d/install-node.sh\" ",
		"--control-plane 'https://console.example.com'", "--registration-key-stdin",
		"--public-ip '203.0.113.7'", `--node-name 'edge '"'"'a'"'"''`, " -y",
	} {
		if !strings.Contains(root, want) {
			t.Errorf("root command missing %q:\n%s", want, root)
		}
	}
	if strings.Contains(root, "--node-region") {
		t.Fatalf("the node takes its region from the control plane (fz-x12): %s", root)
	}
	sudo, _ := InstallCommand("https://console.example.com", key, "edge.example.net", "", false, true)
	if !strings.Contains(sudo, "&& sudo -S -p '' -v && printf '%s\\n' \"$k\" | sudo -n bash \"$d/install-node.sh\"") ||
		strings.Contains(sudo, "--public-ip") {
		t.Fatalf("sudo command: %s", sudo)
	}
	keyOnly, _ := InstallCommand("https://console.example.com", key, "203.0.113.7", "", false, false)
	if strings.Contains(keyOnly, "sudo -S") || !strings.Contains(keyOnly, "| sudo -n bash") {
		t.Fatalf("key login command: %s", keyOnly)
	}
	// The registration key never reaches a process argument list.
	for _, command := range []string{root, sudo, keyOnly} {
		if strings.Contains(command, key) || strings.Contains(command, "--registration-key ") {
			t.Fatalf("registration key on the command line: %s", command)
		}
	}
	for _, bad := range []string{"http://console.example.com", "https://console.example.com/path", "https://a@b.example.com"} {
		if _, err := InstallCommand(bad, key, "203.0.113.7", "", true, false); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("control plane %q accepted", bad)
		}
	}
	for _, bad := range []string{"", key + "\n", "x'y"} {
		if _, err := InstallCommand("https://console.example.com", bad, "203.0.113.7", "", true, false); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("registration key %q accepted", bad)
		}
	}
}

// Stdin carries line 1 = registration key, line 2 = sudo password (only
// for a non-root password login).
func TestInstallInput(t *testing.T) {
	const key = "nrk1.0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if got := string(InstallInput(key, "")); got != key+"\n" {
		t.Fatalf("root input = %q", got)
	}
	if got := string(InstallInput(key, "p@ss word")); got != key+"\np@ss word\n" {
		t.Fatalf("sudo input = %q", got)
	}
}

func TestNormalizeCreate(t *testing.T) {
	base := func() CreateRequest {
		return CreateRequest{Targets: []Target{{Host: " 203.0.113.7 "}, {Host: "EDGE.example.net", Port: 2222, Name: "b"}},
			Credential: Credential{Username: "root", Password: "secret"}, ControlPlane: "https://console.example.com"}
	}
	request := base()
	if err := normalizeCreate(&request, defaultBlocked); err != nil {
		t.Fatal(err)
	}
	if request.Targets[0].Host != "203.0.113.7" || request.Targets[0].Port != 22 || request.Targets[1].Host != "edge.example.net" {
		t.Fatalf("normalized = %+v", request)
	}
	for name, mutate := range map[string]func(*CreateRequest){
		"loopback":     func(r *CreateRequest) { r.Targets[0].Host = "127.0.0.1" },
		"metadata":     func(r *CreateRequest) { r.Targets[0].Host = "169.254.169.254" },
		"localhost":    func(r *CreateRequest) { r.Targets[0].Host = "localhost" },
		"duplicate":    func(r *CreateRequest) { r.Targets[1] = Target{Host: "203.0.113.7"} },
		"both secrets": func(r *CreateRequest) { r.Credential.PrivateKey = "x" },
		"no secret":    func(r *CreateRequest) { r.Credential.Password = "" },
		"bad user":     func(r *CreateRequest) { r.Credential.Username = "root;id" },
		"bad key":      func(r *CreateRequest) { r.Credential.Password, r.Credential.PrivateKey = "", "not a key" },
		"http origin":  func(r *CreateRequest) { r.ControlPlane = "http://console.example.com" },
		"quote name":   func(r *CreateRequest) { r.Targets[0].Name = "a'b" },
		"newline pass": func(r *CreateRequest) { r.Credential.Password = "a\nb" },
		"return pass":  func(r *CreateRequest) { r.Credential.Password = "a\rb" },
		"too many": func(r *CreateRequest) {
			r.Targets = make([]Target, MaxBatch+1)
			for index := range r.Targets {
				r.Targets[index] = Target{Host: "203.0.113." + string(rune('0'+index%10))}
			}
		},
	} {
		request := base()
		mutate(&request)
		if err := normalizeCreate(&request, defaultBlocked); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s accepted", name)
		}
	}
}
