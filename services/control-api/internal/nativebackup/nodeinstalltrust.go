package nativebackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

// Node install trust (cdnca.edge-upgrade-trust/v1): the control and edge
// upgrade execution public keys, the artifact download policy, the artifact
// keys and the optional signer revocation offline root. install-node.sh
// downloads it pinned by the SHA-256 in node-install-defaults (the copied
// install command reads that file) and runtime-config.js. fix-btenv4: one
// implementation for the fresh installer (publish_upgrade_trust) and the
// restore of a migration (verify-migration), built only from control.env so
// the document follows what btenv3 RetargetPorts wrote for this host.
const (
	NodeInstallTrustFile    = DownloadDirectory + "/edge-agent/upgrade-trust.json"
	NodeInstallDefaultsFile = DownloadDirectory + "/node-install-defaults"
	WebRuntimeConfigFile    = DataDirectory + "/runtime-config.js"
	nodeArtifactTrustFile   = DownloadDirectory + "/edge-agent/artifacts.json"
	nodeInstallTrustSchema  = "cdnca.edge-upgrade-trust/v1"
)

type nodeTrustKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
}

type nodeTrustKeys struct {
	Version int            `json:"version"`
	Keys    []nodeTrustKey `json:"keys"`
}

type nodeSignerTrustRoot struct {
	KeyID      string `json:"key_id"`
	Generation uint64 `json:"generation"`
	PublicKey  string `json:"public_key"`
}

type nodeInstallTrustDocument struct {
	Schema           string                            `json:"schema"`
	InstallationID   string                            `json:"installation_id"`
	ControlExecution nodeTrustKeys                     `json:"control_execution"`
	EdgeExecution    nodeTrustKeys                     `json:"edge_execution"`
	Download         entitlement.UpgradeDownloadPolicy `json:"download"`
	ArtifactTrust    nodeTrustKeys                     `json:"artifact_trust"`
	SignerTrustRoot  *nodeSignerTrustRoot              `json:"signer_trust_root,omitempty"`
}

// NodeInstallTrust is a published document: its SHA-256, whether this call
// changed it, and the download endpoint it names.
type NodeInstallTrust struct {
	SHA256   string
	Changed  bool
	Download entitlement.UpgradeDownloadPolicy
}

var (
	canonicalUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	trustKeyID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	executionKeyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	offlineRootKey = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	defaultsSHA    = regexp.MustCompile(`(?m)^upgrade_trust_sha256=[0-9a-f]{64}$`)
	runtimeSHA     = regexp.MustCompile(`(?m)^window\.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "[0-9a-f]{64}";$`)
)

// PublishNodeInstallTrust (re)builds the document from control.env, writes
// it when it changed and points node-install-defaults and runtime-config.js
// at its SHA-256 when they exist (the fresh installer writes them later with
// the printed digest). Download addresses are resolved now with lookup
// (net.DefaultResolver when nil), the same policy that is signed into every
// upgrade execution (controlupgrade.DownloadPolicySource).
func PublishNodeInstallTrust(ctx context.Context, layout Layout, lookup func(context.Context, string) ([]string, error)) (NodeInstallTrust, error) {
	environment, err := ReadEnvironmentFile(layout.Path(ConfigDirectory + "/control.env"))
	if err != nil {
		return NodeInstallTrust{}, fmt.Errorf("read control.env: %w", err)
	}
	document, err := buildNodeInstallTrust(ctx, layout, environment, lookup)
	if err != nil {
		return NodeInstallTrust{}, err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return NodeInstallTrust{}, err
	}
	sum := sha256.Sum256(encoded.Bytes())
	result := NodeInstallTrust{SHA256: hex.EncodeToString(sum[:]), Download: document.Download}
	pins := []struct {
		path    string
		pattern *regexp.Regexp
		line    string
	}{
		{NodeInstallDefaultsFile, defaultsSHA, "upgrade_trust_sha256=" + result.SHA256},
		{WebRuntimeConfigFile, runtimeSHA, `window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "` + result.SHA256 + `";`},
	}
	// Check every pin before writing, so a failure never leaves a document
	// that the published digests do not name.
	present := make([]bool, len(pins))
	for index, pin := range pins {
		content, err := os.ReadFile(layout.Path(pin.path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return NodeInstallTrust{}, fmt.Errorf("read %s: %w", pin.path, err)
		}
		if len(pin.pattern.FindAllIndex(content, -1)) != 1 {
			return NodeInstallTrust{}, fmt.Errorf("%s does not carry exactly one node upgrade trust digest", pin.path)
		}
		present[index] = true
	}
	path := layout.Path(NodeInstallTrustFile)
	if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, encoded.Bytes()) {
		if err := writeFileAtomic(path, encoded.Bytes(), 0o644); err != nil {
			return NodeInstallTrust{}, fmt.Errorf("write the node upgrade trust: %w", err)
		}
		result.Changed = true
	}
	for index, pin := range pins {
		if !present[index] {
			continue
		}
		err := rewriteRegularFile(layout.Path(pin.path), func(content []byte) []byte {
			return pin.pattern.ReplaceAllLiteral(content, []byte(pin.line))
		})
		if err != nil {
			return NodeInstallTrust{}, fmt.Errorf("update %s: %w", pin.path, err)
		}
	}
	return result, nil
}

func buildNodeInstallTrust(ctx context.Context, layout Layout, environment map[string]string,
	lookup func(context.Context, string) ([]string, error)) (nodeInstallTrustDocument, error) {
	document := nodeInstallTrustDocument{Schema: nodeInstallTrustSchema, InstallationID: environment["CONTROL_INSTALLATION_ID"]}
	if !canonicalUUID.MatchString(document.InstallationID) {
		return document, errors.New("control.env CONTROL_INSTALLATION_ID is not a canonical UUID")
	}
	var err error
	if document.ControlExecution, err = executionKey(layout, environment, "CONTROL"); err != nil {
		return document, err
	}
	if document.EdgeExecution, err = executionKey(layout, environment, "EDGE"); err != nil {
		return document, err
	}
	if document.ControlExecution.Keys[0].PublicKeyPEM == document.EdgeExecution.Keys[0].PublicKeyPEM {
		return document, errors.New("control and edge upgrade signing keys must be distinct")
	}
	baseURL := environment["CONTROL_UPGRADE_ARTIFACT_BASE_URL"]
	if baseURL == "" {
		return document, errors.New("control.env has no CONTROL_UPGRADE_ARTIFACT_BASE_URL (node upgrade runtime is not configured)")
	}
	source := controlupgrade.DownloadPolicySource{LookupHost: lookup}
	if root := environment["CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE"]; root != "" {
		source.RootCAFile = layout.Path(root)
	}
	policy, err := source.Resolve(ctx, baseURL)
	if err != nil {
		return document, err
	}
	document.Download = *policy
	if document.ArtifactTrust, err = artifactTrust(layout); err != nil {
		return document, err
	}
	// The offline root pin of install-control.sh --signer-revocation-offline-root-*
	// (signer_revocation_environment writes it only when it was given).
	id, generation := environment["SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID"], environment["SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION"]
	if key := environment["SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64"]; id+generation+key != "" {
		root := &nodeSignerTrustRoot{KeyID: id, PublicKey: key}
		root.Generation, err = strconv.ParseUint(generation, 10, 63)
		if err != nil || root.Generation == 0 || !trustKeyID.MatchString(root.KeyID) || !offlineRootKey.MatchString(root.PublicKey) {
			return document, errors.New("control.env signer revocation offline root is invalid")
		}
		document.SignerTrustRoot = root
	}
	return document, nil
}

// executionKey derives the public half of an upgrade signing key named in
// control.env (CONTROL_UPGRADE_<role>_SIGNING_KEY_ID / _PRIVATE_KEY_FILE).
func executionKey(layout Layout, environment map[string]string, role string) (nodeTrustKeys, error) {
	prefix := "CONTROL_UPGRADE_" + role + "_SIGNING_"
	id, file := environment[prefix+"KEY_ID"], environment[prefix+"PRIVATE_KEY_FILE"]
	if !executionKeyID.MatchString(id) || file == "" {
		return nodeTrustKeys{}, fmt.Errorf("control.env %sKEY_ID/PRIVATE_KEY_FILE are missing", prefix)
	}
	encoded, err := readPrivateFile(layout.Path(file), 16<<10)
	if err != nil {
		return nodeTrustKeys{}, fmt.Errorf("read the %s upgrade signing key: %w", strings.ToLower(role), err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nodeTrustKeys{}, fmt.Errorf("the %s upgrade signing key is not a PKCS#8 PEM key", strings.ToLower(role))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nodeTrustKeys{}, fmt.Errorf("the %s upgrade signing key is not an Ed25519 key", strings.ToLower(role))
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return nodeTrustKeys{}, err
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return nodeTrustKeys{Version: 1, Keys: []nodeTrustKey{{KeyID: id, PublicKeyPEM: public}}}, nil
}

// artifactTrust pins the artifacts.json keys as they stand (package keys,
// the publisher key and keys added by edge signer trust sync).
func artifactTrust(layout Layout) (nodeTrustKeys, error) {
	encoded, err := os.ReadFile(layout.Path(nodeArtifactTrustFile))
	if err != nil {
		return nodeTrustKeys{}, fmt.Errorf("cannot read the edge artifact trust keys for the node upgrade trust: %w", err)
	}
	var store nodeTrustKeys
	if err := json.Unmarshal(encoded, &store); err != nil || store.Version != 1 || len(store.Keys) == 0 || len(store.Keys) > 64 {
		return nodeTrustKeys{}, errors.New("cannot read the edge artifact trust keys for the node upgrade trust")
	}
	seen := map[string]bool{}
	for _, key := range store.Keys {
		if !trustKeyID.MatchString(key.KeyID) || seen[key.KeyID] || !strings.HasPrefix(key.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----\n") {
			return nodeTrustKeys{}, errors.New("cannot read the edge artifact trust keys for the node upgrade trust")
		}
		seen[key.KeyID] = true
	}
	return store, nil
}
