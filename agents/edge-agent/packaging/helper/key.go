package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	privateKeyMode os.FileMode = 0o400
	publicPinMode  os.FileMode = 0o440
	journalMode    os.FileMode = 0o600
	stateDirMode   os.FileMode = 0o700
	maxKeyFileSize             = 16 << 10
)

var (
	ErrKeyPolicy  = errors.New("receipt key file policy violation")
	ErrKeyCorrupt = errors.New("corrupt receipt key")
)

// KeyConfig is authority supplied by the fixed root helper command. Production
// callers should use ProductionKeyConfig; explicit values support unprivileged
// filesystem-policy tests without weakening production defaults.
type KeyConfig struct {
	PrivatePath string
	PublicPath  string
	OwnerUID    uint32
	OwnerGID    uint32
	AgentGID    uint32
}

type KeyMaterial struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (KeyMaterial) String() string   { return "receipt key material [REDACTED]" }
func (KeyMaterial) GoString() string { return "receipt key material [REDACTED]" }

func (KeyMaterial) MarshalJSON() ([]byte, error) {
	return nil, errors.New("receipt key material cannot be serialized")
}

type PublicPin struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

type privateKeyFile struct {
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"key_id"`
	PrivateKey    string `json:"private_key"`
}

type publicPinFile struct {
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
}

func ProductionKeyConfig(agentGID uint32) (KeyConfig, error) {
	if os.Geteuid() != 0 {
		return KeyConfig{}, fmt.Errorf("%w: root key initialization required", ErrKeyPolicy)
	}
	return KeyConfig{
		PrivatePath: "/var/lib/cdnca-edge-agent-helper/receipt-key.json",
		PublicPath:  "/etc/cdnca-edge-agent/helper-receipt-public.json",
		OwnerUID:    0,
		OwnerGID:    0,
		AgentGID:    agentGID,
	}, nil
}

func EnsureReceiptKey(config KeyConfig, keyID string) (KeyMaterial, error) {
	if err := validateKeyConfig(config); err != nil || !validHelperIdentifier(keyID) {
		return KeyMaterial{}, fmt.Errorf("%w: invalid configuration", ErrKeyPolicy)
	}
	key, err := LoadReceiptKey(config)
	if err == nil {
		if key.KeyID != keyID {
			return KeyMaterial{}, fmt.Errorf("%w: key id differs", ErrKeyPolicy)
		}
		pin, pinErr := LoadReceiptPublicPin(config)
		if errors.Is(pinErr, os.ErrNotExist) {
			if writeErr := writePublicPin(config, key); writeErr != nil {
				return KeyMaterial{}, writeErr
			}
			return key, nil
		}
		if pinErr != nil {
			return KeyMaterial{}, pinErr
		}
		if !publicPinMatches(pin, key) {
			if writeErr := writePublicPin(config, key); writeErr != nil {
				return KeyMaterial{}, writeErr
			}
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return KeyMaterial{}, err
	}
	if _, pinErr := LoadReceiptPublicPin(config); pinErr == nil || !errors.Is(pinErr, os.ErrNotExist) {
		if pinErr != nil {
			return KeyMaterial{}, pinErr
		}
		return KeyMaterial{}, fmt.Errorf("%w: public pin exists without private key", ErrKeyPolicy)
	}
	return provisionReceiptKey(config, keyID, false)
}

func RotateReceiptKey(config KeyConfig, keyID string) (KeyMaterial, error) {
	if err := validateKeyConfig(config); err != nil || !validHelperIdentifier(keyID) {
		return KeyMaterial{}, fmt.Errorf("%w: invalid configuration", ErrKeyPolicy)
	}
	current, err := LoadReceiptKey(config)
	if err != nil {
		return KeyMaterial{}, err
	}
	pin, err := LoadReceiptPublicPin(config)
	if err != nil || !publicPinMatches(pin, current) {
		return KeyMaterial{}, fmt.Errorf("%w: current key pair differs", ErrKeyPolicy)
	}
	if current.KeyID == keyID {
		return KeyMaterial{}, fmt.Errorf("%w: rotation key id must be new", ErrKeyPolicy)
	}
	return provisionReceiptKey(config, keyID, true)
}

func LoadReceiptKey(config KeyConfig) (KeyMaterial, error) {
	if err := validateKeyConfig(config); err != nil {
		return KeyMaterial{}, err
	}
	content, err := readOwnedCanonicalFile(config.PrivatePath, privateKeyMode, config.OwnerUID, config.OwnerGID, maxKeyFileSize)
	if err != nil {
		return KeyMaterial{}, err
	}
	var encoded privateKeyFile
	if err := decodeCanonicalJSON(content, &encoded); err != nil || encoded.SchemaVersion != 1 || !validHelperIdentifier(encoded.KeyID) {
		return KeyMaterial{}, ErrKeyCorrupt
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(encoded.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return KeyMaterial{}, ErrKeyCorrupt
	}
	return KeyMaterial{KeyID: encoded.KeyID, PrivateKey: ed25519.PrivateKey(privateKey)}, nil
}

func LoadReceiptPublicPin(config KeyConfig) (PublicPin, error) {
	if err := validateKeyConfig(config); err != nil {
		return PublicPin{}, err
	}
	content, err := readOwnedCanonicalFile(config.PublicPath, publicPinMode, config.OwnerUID, config.AgentGID, maxKeyFileSize)
	if err != nil {
		return PublicPin{}, err
	}
	var encoded publicPinFile
	if err := decodeCanonicalJSON(content, &encoded); err != nil || encoded.SchemaVersion != 1 || !validHelperIdentifier(encoded.KeyID) {
		return PublicPin{}, ErrKeyCorrupt
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(encoded.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return PublicPin{}, ErrKeyCorrupt
	}
	return PublicPin{KeyID: encoded.KeyID, PublicKey: ed25519.PublicKey(publicKey)}, nil
}

func LoadReceiptKeyPair(config KeyConfig) (KeyMaterial, error) {
	key, err := LoadReceiptKey(config)
	if err != nil {
		return KeyMaterial{}, err
	}
	pin, err := LoadReceiptPublicPin(config)
	if err != nil {
		return KeyMaterial{}, err
	}
	if !publicPinMatches(pin, key) {
		return KeyMaterial{}, fmt.Errorf("%w: receipt key pair differs", ErrKeyPolicy)
	}
	return key, nil
}

func provisionReceiptKey(config KeyConfig, keyID string, replace bool) (KeyMaterial, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate receipt key: %w", err)
	}
	key := KeyMaterial{KeyID: keyID, PrivateKey: privateKey}
	privateContent, err := json.Marshal(privateKeyFile{
		SchemaVersion: 1,
		KeyID:         keyID,
		PrivateKey:    base64.RawStdEncoding.EncodeToString(privateKey),
	})
	if err != nil {
		return KeyMaterial{}, ErrKeyCorrupt
	}
	if err := writeOwnedAtomic(config.PrivatePath, privateKeyMode, config.OwnerUID, config.OwnerGID, privateContent, replace); err != nil {
		return KeyMaterial{}, err
	}
	if !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return KeyMaterial{}, ErrKeyCorrupt
	}
	if err := writePublicPin(config, key); err != nil {
		return KeyMaterial{}, err
	}
	return key, nil
}

func writePublicPin(config KeyConfig, key KeyMaterial) error {
	content, err := json.Marshal(publicPinFile{
		SchemaVersion: 1,
		KeyID:         key.KeyID,
		PublicKey:     base64.RawStdEncoding.EncodeToString(key.PrivateKey.Public().(ed25519.PublicKey)),
	})
	if err != nil {
		return ErrKeyCorrupt
	}
	_, statErr := os.Lstat(config.PublicPath)
	replace := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return writeOwnedAtomic(config.PublicPath, publicPinMode, config.OwnerUID, config.AgentGID, content, replace)
}

func publicPinMatches(pin PublicPin, key KeyMaterial) bool {
	return pin.KeyID == key.KeyID && bytes.Equal(pin.PublicKey, key.PrivateKey.Public().(ed25519.PublicKey))
}

func validateKeyConfig(config KeyConfig) error {
	if !validAbsoluteFilePath(config.PrivatePath) || !validAbsoluteFilePath(config.PublicPath) || config.PrivatePath == config.PublicPath {
		return fmt.Errorf("%w: invalid key path", ErrKeyPolicy)
	}
	if err := requireOwnedDirectory(filepath.Dir(config.PrivatePath), stateDirMode, config.OwnerUID, config.OwnerGID, true); err != nil {
		return err
	}
	if err := requireOwnedDirectory(filepath.Dir(config.PublicPath), 0, config.OwnerUID, 0, false); err != nil {
		return err
	}
	return nil
}

func readOwnedCanonicalFile(path string, mode os.FileMode, uid, gid uint32, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("%w: open protected file", ErrKeyPolicy)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrKeyPolicy
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 || info.Size() < 2 || info.Size() > limit {
		return nil, fmt.Errorf("%w: protected file metadata", ErrKeyPolicy)
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) != info.Size() || int64(len(content)) > limit {
		return nil, fmt.Errorf("%w: protected file content", ErrKeyPolicy)
	}
	return content, nil
}

func writeOwnedAtomic(path string, mode os.FileMode, uid, gid uint32, content []byte, replace bool) error {
	if len(content) == 0 || !validAbsoluteFilePath(path) {
		return ErrKeyPolicy
	}
	if _, err := os.Lstat(path); err == nil {
		if !replace {
			return fmt.Errorf("%w: protected file already exists", ErrKeyPolicy)
		}
		if _, err := readOwnedCanonicalFile(path, mode, uid, gid, int64(maxJournalFileSize)); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, ".helper-state-"+randomKeySuffix())
	fd, err := unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode))
	if err != nil {
		return fmt.Errorf("create protected temporary file: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(temporary))
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set protected file mode: %w", err)
	}
	if uint32(os.Geteuid()) != uid || uint32(os.Getegid()) != gid {
		if err := file.Chown(int(uid), int(gid)); err != nil {
			return fmt.Errorf("set protected file owner: %w", err)
		}
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write protected file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync protected file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close protected file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish protected file: %w", err)
	}
	remove = false
	if err := syncHelperDirectory(directory); err != nil {
		return err
	}
	return nil
}

func requireOwnedDirectory(path string, exactMode os.FileMode, uid, gid uint32, exactGroup bool) error {
	info, err := os.Lstat(path)
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uid {
		return fmt.Errorf("%w: protected directory metadata", ErrKeyPolicy)
	}
	if exactMode != 0 && info.Mode().Perm() != exactMode {
		return fmt.Errorf("%w: protected directory mode", ErrKeyPolicy)
	}
	if exactMode == 0 && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: writable protected directory", ErrKeyPolicy)
	}
	if exactGroup && stat.Gid != gid {
		return fmt.Errorf("%w: protected directory group", ErrKeyPolicy)
	}
	return nil
}

func syncHelperDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open protected directory: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync protected directory: %w", err)
	}
	return nil
}

func decodeCanonicalJSON(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, content) {
		return errors.New("non-canonical JSON")
	}
	return nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func validAbsoluteFilePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func randomKeySuffix() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(value)
}
