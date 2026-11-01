package main

// `edge-agent set-gateway` points an installed node at a new control plane
// Gateway address after a control plane migration or a restore onto another
// host: the node identity, the Gateway CA and every other
// setting stay; only gateway.address, gateway.enrollment_address and
// gateway.server_name in the configuration and the persisted active endpoint
// change. A node that was offline during a migration (it never learned the
// new address from GatewayHello) or a restore of a lost control plane needs
// it. The new Gateway must present a certificate from the same Gateway CA
// (the migrated PKI) naming --server-name. Run as root, then restart
// cdnca-edge-agent.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

const setGatewayUsage = `usage: edge-agent set-gateway --address HOST:PORT [--server-name NAME] [--enrollment-address HOST:PORT]
                          [--config /etc/cdnca-edge-agent/config.json]
then: systemctl restart cdnca-edge-agent`

func setGatewayCommand(args []string, lookupEnv func(string) (string, bool), stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("edge-agent set-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := defaultConfigPath
	if lookupEnv != nil {
		if value, exists := lookupEnv(configPathEnv); exists && value != "" {
			configPath = value
		}
	}
	flags.StringVar(&configPath, "config", configPath, "")
	address := flags.String("address", "", "")
	serverName := flags.String("server-name", "", "")
	enrollmentAddress := flags.String("enrollment-address", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *address == "" {
		fmt.Fprintln(stderr, setGatewayUsage)
		return 2
	}
	changed, err := setGateway(configPath, *address, *serverName, *enrollmentAddress)
	if err != nil {
		fmt.Fprintf(stderr, "set-gateway: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintln(stdout, "gateway address unchanged")
		return 0
	}
	fmt.Fprintf(stdout, "gateway address set to %s; run: systemctl restart cdnca-edge-agent\n", *address)
	return 0
}

// setGateway rewrites the configuration and the active endpoint record.
// serverName defaults to the address host; enrollmentAddress defaults to the
// address host on the configured enrollment port (DefaultEnrollmentPort when
// none is configured).
func setGateway(configPath, address, serverName, enrollmentAddress string) (bool, error) {
	if err := validateGatewayAddress(address); err != nil {
		return false, err
	}
	host, _, _ := net.SplitHostPort(address)
	if serverName == "" {
		serverName = host
	}
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if serverName == "" || len(serverName) > 253 || strings.ContainsAny(serverName, ":/ []") && net.ParseIP(serverName) == nil {
		return false, errors.New("--server-name must be a host name or IP address")
	}
	physical, err := canonicalConfigPath(configPath)
	if err != nil {
		return false, err
	}
	content, err := readConfigFile(physical)
	if err != nil {
		return false, err
	}
	// The current configuration must be valid: this never repairs a broken one.
	current, _, err := decodeConfigAtPath(content, physical)
	if err != nil {
		return false, fmt.Errorf("current configuration is invalid: %w", err)
	}
	if enrollmentAddress == "" {
		port := DefaultEnrollmentPort
		if current.Gateway.EnrollmentAddress != "" {
			if _, configured, err := net.SplitHostPort(current.Gateway.EnrollmentAddress); err == nil {
				port = configured
			}
		}
		enrollmentAddress = net.JoinHostPort(host, port)
	}
	if err := validateGatewayAddress(enrollmentAddress); err != nil {
		return false, errors.New("--enrollment-address must be a host:port pair")
	}
	if current.Gateway.Transport == "ws" {
		return false, errors.New("this node reaches the Gateway through a ws entry (CDN); change gateway.address in the configuration by hand")
	}
	updated, err := rewriteGatewayFields(content, map[string]string{
		"address": address, "server_name": serverName, "enrollment_address": enrollmentAddress})
	if err != nil {
		return false, err
	}
	if _, _, err := decodeConfigAtPath(updated, physical); err != nil {
		return false, fmt.Errorf("updated configuration is invalid: %w", err)
	}
	configChanged := !bytes.Equal(updated, content)
	// The daemon dials the persisted active endpoint (port transitions and
	// signed address changes move it), not gateway.address, once it exists.
	stateChanged, err := changeActiveEndpoint(filepath.Join(current.JournalDir, "gateway-endpoint"), address, serverName)
	if err != nil {
		return false, err
	}
	if configChanged {
		if err := replaceConfigFile(physical, updated); err != nil {
			return false, err
		}
	}
	return configChanged || stateChanged, nil
}

// rewriteGatewayFields replaces gateway.<name> values and keeps every other
// field (and their order) byte for byte as JSON values.
func rewriteGatewayFields(content []byte, values map[string]string) ([]byte, error) {
	var root orderedObject
	if err := json.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("invalid configuration JSON: %w", err)
	}
	raw, ok := root.get("gateway")
	if !ok {
		return nil, errors.New("configuration has no gateway object")
	}
	var gateway orderedObject
	if err := json.Unmarshal(raw, &gateway); err != nil {
		return nil, errors.New("gateway configuration is invalid")
	}
	for _, name := range []string{"address", "server_name", "enrollment_address"} {
		encoded, _ := json.Marshal(values[name])
		gateway.set(name, encoded)
	}
	encodedGateway, err := json.Marshal(gateway)
	if err != nil {
		return nil, err
	}
	root.set("gateway", encodedGateway)
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, encoded, "", "  "); err != nil {
		return nil, err
	}
	indented.WriteByte('\n')
	return indented.Bytes(), nil
}

func changeActiveEndpoint(directory, address, serverName string) (bool, error) {
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return false, nil // never started: the daemon seeds it from the configuration
	}
	store, err := gatewayclient.NewFileGatewayEndpointStateStore(directory, gatewayclient.GatewayEndpointState{Address: address, ServerName: serverName})
	if err != nil {
		return false, fmt.Errorf("open the active gateway endpoint: %w", err)
	}
	before := store.Active()
	if err := store.ChangeAddress(address, serverName); err != nil {
		return false, fmt.Errorf("change the active gateway endpoint: %w", err)
	}
	if err := chownLike(directory, filepath.Join(directory, "gateway-endpoint-active.json")); err != nil {
		return false, err
	}
	return before.Address != address || before.ServerName != serverName, nil
}

// replaceConfigFile writes atomically, keeping mode and owner.
func replaceConfigFile(path string, content []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".config.json.set-gateway."+strconv.Itoa(os.Getpid()))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(temporary, int(stat.Uid), int(stat.Gid)); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// chownLike gives file the owner of directory (the Agent user owns its
// journal; set-gateway runs as root).
func chownLike(directory, file string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Lchown(file, int(stat.Uid), int(stat.Gid))
}

// orderedObject is a JSON object that keeps its key order.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func (object *orderedObject) get(name string) (json.RawMessage, bool) {
	value, ok := object.values[name]
	return value, ok
}

func (object *orderedObject) set(name string, value json.RawMessage) {
	if object.values == nil {
		object.values = map[string]json.RawMessage{}
	}
	if _, ok := object.values[name]; !ok {
		object.keys = append(object.keys, name)
	}
	object.values[name] = value
}

func (object *orderedObject) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	object.values = map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid object key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		object.set(name, value)
	}
	_, err = decoder.Token()
	return err
}

func (object orderedObject) MarshalJSON() ([]byte, error) {
	var output bytes.Buffer
	output.WriteByte('{')
	for index, name := range object.keys {
		if index > 0 {
			output.WriteByte(',')
		}
		key, _ := json.Marshal(name)
		output.Write(key)
		output.WriteByte(':')
		output.Write(object.values[name])
	}
	output.WriteByte('}')
	return output.Bytes(), nil
}
