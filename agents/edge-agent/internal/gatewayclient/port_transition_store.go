package gatewayclient

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

const (
	gatewayEndpointActiveFile    = "gateway-endpoint-active.json"
	gatewayEndpointCandidateFile = "gateway-endpoint-candidate.json"
)

type FileGatewayEndpointStateStore struct {
	mu        sync.RWMutex
	directory string
	active    GatewayEndpointState
}

func NewFileGatewayEndpointStateStore(directory string, initial GatewayEndpointState) (*FileGatewayEndpointStateStore, error) {
	if err := validateSecureDirectory(directory, true); err != nil {
		return nil, err
	}
	store := &FileGatewayEndpointStateStore{directory: directory}
	activePath := filepath.Join(directory, gatewayEndpointActiveFile)
	loaded, err := readGatewayEndpointState(activePath)
	if err == nil {
		if err := syncDirectory(directory); err != nil {
			return nil, err
		}
		store.active = loaded
		return store, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !validGatewayEndpointState(initial) {
		return nil, fmt.Errorf("%w: initial gateway endpoint is invalid", ErrInvalidConfiguration)
	}
	if err := writeGatewayEndpointState(directory, gatewayEndpointActiveFile, initial); err != nil {
		return nil, err
	}
	store.active = initial
	return store, nil
}

func (s *FileGatewayEndpointStateStore) Active() GatewayEndpointState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *FileGatewayEndpointStateStore) Stage(value GatewayEndpointState) error {
	if s == nil || !validGatewayEndpointState(value) || value.TransitionID == "" {
		return fmt.Errorf("%w: gateway endpoint candidate is invalid", ErrInvalidConfiguration)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value.Revision <= s.active.Revision || value.Address == s.active.Address || value.ServerName != s.active.ServerName {
		return fmt.Errorf("%w: gateway endpoint candidate conflicts with active state", ErrCommandConflict)
	}
	return writeGatewayEndpointState(s.directory, gatewayEndpointCandidateFile, value)
}

func (s *FileGatewayEndpointStateStore) Activate(value GatewayEndpointState) error {
	if s == nil || !validGatewayEndpointState(value) || value.TransitionID == "" {
		return fmt.Errorf("%w: gateway endpoint activation is invalid", ErrInvalidConfiguration)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := readGatewayEndpointState(filepath.Join(s.directory, gatewayEndpointCandidateFile))
	if err != nil || candidate != value || value.Revision <= s.active.Revision {
		return fmt.Errorf("%w: gateway endpoint candidate changed before activation", ErrCommandConflict)
	}
	return s.replaceActive(value)
}

func (s *FileGatewayEndpointStateStore) Finalize(value GatewayEndpointState) error {
	if s == nil || !validGatewayEndpointState(value) || value.TransitionID != "" {
		return fmt.Errorf("%w: gateway endpoint finalization is invalid", ErrInvalidConfiguration)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active.TransitionID == "" && s.active == value {
		return nil
	}
	if s.active.TransitionID == "" || s.active.Revision != value.Revision || s.active.Address != value.Address || s.active.ServerName != value.ServerName {
		return fmt.Errorf("%w: gateway endpoint finalization conflicts with active state", ErrCommandConflict)
	}
	return s.replaceActive(value)
}

func (s *FileGatewayEndpointStateStore) Rollback(value GatewayEndpointState) error {
	if s == nil || !validGatewayEndpointState(value) || value.TransitionID != "" {
		return fmt.Errorf("%w: gateway endpoint rollback is invalid", ErrInvalidConfiguration)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active.TransitionID == "" && s.active == value {
		return nil
	}
	if s.active.Revision != value.Revision || s.active.ServerName != value.ServerName ||
		(s.active.TransitionID == "" && (s.active.LastStatus == "" || s.active.Address != value.Address)) {
		return fmt.Errorf("%w: gateway endpoint rollback conflicts with active state", ErrCommandConflict)
	}
	return s.replaceActive(value)
}

// ChangeAddress replaces the active endpoint with a probed Gateway address
// and server name (signed address change, fix-nodegw). It is refused while a
// port transition is open (TransitionID set). The revision is kept (a later
// port transition must still be newer); the closed transition's stored
// status is dropped because it names the old address (storedStatus would
// refuse every later port transition otherwise).
func (s *FileGatewayEndpointStateStore) ChangeAddress(address, serverName string) error {
	if s == nil {
		return ErrInvalidConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active.TransitionID != "" {
		return fmt.Errorf("%w: a gateway port transition is in progress", ErrCommandConflict)
	}
	if s.active.Address == address && s.active.ServerName == serverName {
		return nil
	}
	value := GatewayEndpointState{Address: address, ServerName: serverName, Revision: s.active.Revision}
	if !validGatewayEndpointState(value) {
		return fmt.Errorf("%w: gateway address change is invalid", ErrInvalidConfiguration)
	}
	return s.replaceActive(value)
}

func (s *FileGatewayEndpointStateStore) replaceActive(value GatewayEndpointState) error {
	if err := writeGatewayEndpointState(s.directory, gatewayEndpointActiveFile, value); err != nil {
		return err
	}
	s.active = value
	// The active receipt is durable. Candidate cleanup cannot reverse the committed outcome.
	if err := os.Remove(filepath.Join(s.directory, gatewayEndpointCandidateFile)); err == nil {
		_ = syncDirectory(s.directory)
	}
	return nil
}

func (s *FileGatewayEndpointStateStore) RecordFailure(value GatewayEndpointState) error {
	if s == nil || !validGatewayEndpointState(value) || value.TransitionID != "" || value.LastStatus == "" || value.LastCommandSHA256 == "" {
		return ErrInvalidConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value.Address != s.active.Address || value.ServerName != s.active.ServerName || value.Revision <= s.active.Revision {
		return ErrCommandConflict
	}
	return s.replaceActive(value)
}

func (s *FileGatewayEndpointStateStore) Recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := readGatewayEndpointState(filepath.Join(s.directory, gatewayEndpointActiveFile))
	if err != nil {
		return err
	}
	if err := syncDirectory(s.directory); err != nil {
		return err
	}
	s.active = value
	return nil
}

func validGatewayEndpointState(value GatewayEndpointState) bool {
	return validGatewayEndpointStateFields(value)
}

func readGatewayEndpointState(path string) (GatewayEndpointState, error) {
	content, err := readSecureRegularFile(path, false)
	if err != nil {
		return GatewayEndpointState{}, err
	}
	var value GatewayEndpointState
	if err := json.Unmarshal(content, &value); err != nil || !validGatewayEndpointStateFields(value) {
		return GatewayEndpointState{}, fmt.Errorf("%w: stored gateway endpoint is invalid", ErrInvalidConfiguration)
	}
	return value, nil
}

func validGatewayEndpointStateFields(value GatewayEndpointState) bool {
	if value.Address == "" || value.ServerName == "" || value.TransitionID != "" && value.Revision == 0 {
		return false
	}
	if _, _, err := net.SplitHostPort(value.Address); err != nil {
		return false
	}
	if value.TransitionID == "" {
		return true
	}
	parsed, err := uuid.Parse(value.TransitionID)
	return err == nil && parsed.String() == value.TransitionID
}

func writeGatewayEndpointState(directory, name string, value GatewayEndpointState) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporaryName := "." + name + "." + uuid.NewString() + ".tmp"
	temporaryPath := filepath.Join(directory, temporaryName)
	file, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create gateway endpoint state: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return fmt.Errorf("write gateway endpoint state: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync gateway endpoint state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close gateway endpoint state: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, name)); err != nil {
		return fmt.Errorf("activate gateway endpoint state: %w", err)
	}
	remove = false
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("%w: %v", ErrPortTransitionPersistenceUnknown, err)
	}
	return nil
}

type EndpointMTLSDialerFactory struct {
	base MTLSDialerConfig
}

func NewEndpointMTLSDialerFactory(base MTLSDialerConfig) (*EndpointMTLSDialerFactory, error) {
	if _, err := NewMTLSDialer(base); err != nil {
		return nil, err
	}
	factory := &EndpointMTLSDialerFactory{base: base}
	if factory.CertificateSHA256() == "" {
		return nil, fmt.Errorf("%w: client certificate is invalid", ErrInvalidConfiguration)
	}
	return factory, nil
}

func (f *EndpointMTLSDialerFactory) New(state GatewayEndpointState) (Dialer, error) {
	if f == nil || !validGatewayEndpointStateFields(state) {
		return nil, fmt.Errorf("%w: gateway endpoint is invalid", ErrInvalidConfiguration)
	}
	config := f.base
	config.Address = state.Address
	config.ServerName = state.ServerName
	return NewMTLSDialer(config)
}

func (f *EndpointMTLSDialerFactory) CertificateSHA256() string {
	if f == nil {
		return ""
	}
	pemBytes, err := readSecureRegularFile(f.base.ClientCertificateFile, false)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

type SwitchingDialer struct {
	store   GatewayEndpointStateStore
	factory *EndpointMTLSDialerFactory
}

func NewSwitchingDialer(store GatewayEndpointStateStore, factory *EndpointMTLSDialerFactory) (*SwitchingDialer, error) {
	if store == nil || factory == nil {
		return nil, fmt.Errorf("%w: switching dialer dependencies are required", ErrInvalidConfiguration)
	}
	if _, err := factory.New(store.Active()); err != nil {
		return nil, err
	}
	return &SwitchingDialer{store: store, factory: factory}, nil
}

func (d *SwitchingDialer) Dial(ctx context.Context) (Connection, error) {
	dialer, err := d.factory.New(d.store.Active())
	if err != nil {
		return nil, err
	}
	return dialer.Dial(ctx)
}

type clientCandidateProber struct {
	client  *Client
	factory *EndpointMTLSDialerFactory
}

func NewClientCandidateProber(client *Client, factory *EndpointMTLSDialerFactory) (GatewayCandidateDialer, error) {
	if client == nil || factory == nil {
		return nil, fmt.Errorf("%w: candidate prober dependencies are required", ErrInvalidConfiguration)
	}
	return &clientCandidateProber{client: client, factory: factory}, nil
}

func (p *clientCandidateProber) Probe(ctx context.Context, state GatewayEndpointState, certificateSHA string) error {
	if certificateSHA != p.factory.CertificateSHA256() {
		return ErrPortTransitionIdentityMismatch
	}
	dialer, err := p.factory.New(state)
	if err != nil {
		return err
	}
	connection, err := dialer.Dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	return p.client.probePortTransition(ctx, connection.Client(), state)
}
