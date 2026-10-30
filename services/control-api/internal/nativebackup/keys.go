package nativebackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

// KeyRing is this installation's backup identity: an Ed25519 key that signs
// every manifest and an age X25519 identity every artifact is encrypted to.
// Both live root-only in /etc/cdnca-control/keys/backup, so they travel with
// the configuration of a migrated host.
type KeyRing struct {
	Signing  ed25519.PrivateKey
	Identity *age.X25519Identity
}

func (ring KeyRing) Fingerprint() string {
	return Fingerprint(ring.Signing.Public().(ed25519.PublicKey))
}
func (ring KeyRing) Recipient() string { return ring.Identity.Recipient().String() }

func keyPaths(layout Layout) (signing, identity string) {
	directory := layout.Path(BackupKeyDirectory)
	return filepath.Join(directory, "signing.pem"), filepath.Join(directory, "identity.age-key")
}

// LoadOrCreateKeys reads the backup identity, creating it once on first use.
func LoadOrCreateKeys(layout Layout) (KeyRing, error) {
	ring, err := LoadKeys(layout)
	if !errors.Is(err, os.ErrNotExist) {
		return ring, err
	}
	signingPath, identityPath := keyPaths(layout)
	directory := filepath.Dir(signingPath)
	if err := ensurePrivateDirectory(directory); err != nil {
		return KeyRing{}, err
	}
	// The installer and the backup timer's agent can both get here on first
	// use. Serialize creation on the key directory and re-check under the lock
	// so the loser reads the winner's ring instead of failing on "file exists".
	unlock, err := lockDirectory(directory)
	if err != nil {
		return KeyRing{}, err
	}
	defer unlock()
	ring, err = LoadKeys(layout)
	if !errors.Is(err, os.ErrNotExist) {
		return ring, err
	}
	// A creation interrupted between the two writes leaves one file behind.
	// Keep it and create only the missing one; LoadKeys above has already
	// rejected a present but invalid signing key.
	if _, err := readIdentityFile(identityPath); errors.Is(err, os.ErrNotExist) {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return KeyRing{}, err
		}
		if err := writeExclusive(identityPath, []byte(identity.String()+"\n")); err != nil {
			return KeyRing{}, err
		}
	} else if err != nil {
		return KeyRing{}, err
	}
	if _, err := os.Lstat(signingPath); errors.Is(err, os.ErrNotExist) {
		_, signing, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyRing{}, err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(signing)
		if err != nil {
			return KeyRing{}, err
		}
		if err := writeExclusive(signingPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})); err != nil {
			return KeyRing{}, err
		}
	} else if err != nil {
		return KeyRing{}, err
	}
	return LoadKeys(layout)
}

func LoadKeys(layout Layout) (KeyRing, error) {
	signingPath, identityPath := keyPaths(layout)
	signingPEM, err := readPrivateFile(signingPath, 16<<10)
	if err != nil {
		return KeyRing{}, err
	}
	if info, statErr := os.Stat(signingPath); statErr != nil || info.Mode().Perm()&0o077 != 0 {
		return KeyRing{}, errors.New("backup signing key must be owner-only")
	}
	block, rest := pem.Decode(signingPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return KeyRing{}, errors.New("backup signing key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	signing, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return KeyRing{}, errors.New("backup signing key is invalid")
	}
	identity, err := readIdentityFile(identityPath)
	if err != nil {
		return KeyRing{}, err
	}
	return KeyRing{Signing: signing, Identity: identity}, nil
}

func readIdentityFile(path string) (*age.X25519Identity, error) {
	encoded, err := readPrivateFile(path, 16<<10)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(path); statErr != nil || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("backup identity must be owner-only")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, errors.New("backup identity is invalid")
	}
	return identity, nil
}

// NewEphemeralIdentity creates the one-time identity a migration target uses
// to receive a bundle; it is written owner-only and removed after restore.
func NewEphemeralIdentity(path string) (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := writeExclusive(path, []byte(identity.String()+"\n")); err != nil {
		return nil, err
	}
	return identity, nil
}

func ReadIdentity(path string) (*age.X25519Identity, error) { return readIdentityFile(path) }

// writeExclusive creates path owner-only and never replaces an existing file.
// The content is written and synced to a temporary file first and published
// with link(2), which fails if path exists, so a reader never sees a partial
// file.
func writeExclusive(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

// lockDirectory takes a blocking exclusive flock on directory itself, so no
// lock file is left among the keys that travel with configuration backups.
func lockDirectory(directory string) (func(), error) {
	handle, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(handle.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(handle.Fd()), syscall.LOCK_UN)
		_ = handle.Close()
	}, nil
}

const RecoveryKitSchema = "cdnca.control-native-backup.recovery-kit/v1"

// RecoveryKit lets an operator restore an off-site bundle after the original
// host is gone: the age identity sealed with a passphrase (scrypt) and the
// signer fingerprint to pin. Store it apart from the backups.
type RecoveryKit struct {
	Schema           string    `json:"schema"`
	InstallationID   string    `json:"installation_id"`
	SignerFinger     string    `json:"signer_fingerprint"`
	Recipient        string    `json:"recipient"`
	CreatedAt        time.Time `json:"created_at"`
	SealedIdentity   string    `json:"sealed_identity"`
	PassphraseHintCN string    `json:"note"`
}

var ErrWeakPassphrase = errors.New("recovery passphrase must be 12 to 1024 characters")

func validPassphrase(passphrase string) bool {
	count := utf8.RuneCountInString(passphrase)
	return utf8.ValidString(passphrase) && count >= 12 && count <= 1024 && !strings.ContainsRune(passphrase, 0)
}

func ExportRecoveryKit(ring KeyRing, installationID, passphrase string, now time.Time) (RecoveryKit, error) {
	if !validPassphrase(passphrase) {
		return RecoveryKit{}, ErrWeakPassphrase
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return RecoveryKit{}, err
	}
	recipient.SetWorkFactor(18)
	var sealed bytes.Buffer
	writer, err := age.Encrypt(&sealed, recipient)
	if err != nil {
		return RecoveryKit{}, err
	}
	if _, err := io.WriteString(writer, ring.Identity.String()); err != nil {
		return RecoveryKit{}, err
	}
	if err := writer.Close(); err != nil {
		return RecoveryKit{}, err
	}
	return RecoveryKit{Schema: RecoveryKitSchema, InstallationID: installationID, SignerFinger: ring.Fingerprint(),
		Recipient: ring.Recipient(), CreatedAt: now.UTC(), SealedIdentity: encodeBase64(sealed.Bytes()),
		PassphraseHintCN: "恢复口令不保存在任何地方；请与本文件分开保管。恢复时：control-api native-backup restore --recovery-kit 本文件"}, nil
}

func OpenRecoveryKit(encoded []byte, passphrase string) (*age.X25519Identity, RecoveryKit, error) {
	var kit RecoveryKit
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&kit); err != nil || kit.Schema != RecoveryKitSchema || !fingerprintPattern.MatchString(kit.SignerFinger) {
		return nil, RecoveryKit{}, errors.New("recovery kit is invalid")
	}
	sealed, err := decodeBase64(kit.SealedIdentity)
	if err != nil {
		return nil, RecoveryKit{}, errors.New("recovery kit is invalid")
	}
	scrypt, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, RecoveryKit{}, err
	}
	reader, err := age.Decrypt(bytes.NewReader(sealed), scrypt)
	if err != nil {
		return nil, RecoveryKit{}, errors.New("recovery passphrase is wrong or the kit is damaged")
	}
	plain, err := io.ReadAll(io.LimitReader(reader, 4096))
	if err != nil {
		return nil, RecoveryKit{}, errors.New("recovery kit is damaged")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	clear(plain)
	if err != nil || identity.Recipient().String() != kit.Recipient {
		return nil, RecoveryKit{}, errors.New("recovery kit is damaged")
	}
	return identity, kit, nil
}
