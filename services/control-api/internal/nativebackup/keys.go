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

const (
	recoveryNoteSealed = "恢复口令不保存在任何地方；请与本文件分开保管。恢复时：control-api native-backup restore --recovery-kit 本文件 / " +
		"The passphrase is not stored anywhere; keep it apart from this file. Restore: control-api native-backup restore --recovery-kit FILE"
	recoveryNotePlain = "这个文件就是恢复凭据，任何拿到它的人都能解开备份，请离线妥善保管。恢复时：control-api native-backup restore --recovery-kit 本文件 / " +
		"This file is the recovery credential: anyone holding it can decrypt the backups. Keep it offline and safe. Restore: control-api native-backup restore --recovery-kit FILE"
)

// RecoveryKit lets an operator restore an off-site bundle after the original
// host is gone: the age identity and the signer fingerprint to pin. By
// default the identity is stored as is and the file itself is the
// credential; with a passphrase it is sealed (scrypt) instead. A kit without
// has_passphrase predates the choice and is always sealed.
type RecoveryKit struct {
	Schema           string    `json:"schema"`
	InstallationID   string    `json:"installation_id"`
	SignerFinger     string    `json:"signer_fingerprint"`
	Recipient        string    `json:"recipient"`
	CreatedAt        time.Time `json:"created_at"`
	HasPassphrase    *bool     `json:"has_passphrase,omitempty"`
	Identity         string    `json:"identity,omitempty"`
	SealedIdentity   string    `json:"sealed_identity,omitempty"`
	PassphraseHintCN string    `json:"note"`
}

// NeedsPassphrase reports whether opening the kit asks for a passphrase.
func (kit RecoveryKit) NeedsPassphrase() bool { return kit.HasPassphrase == nil || *kit.HasPassphrase }

var ErrWeakPassphrase = errors.New("recovery passphrase must be 12 to 1024 characters")

func validPassphrase(passphrase string) bool {
	count := utf8.RuneCountInString(passphrase)
	return utf8.ValidString(passphrase) && count >= 12 && count <= 1024 && !strings.ContainsRune(passphrase, 0)
}

// ExportRecoveryKit writes the identity as is when passphrase is empty, and
// sealed under the passphrase (12 to 1024 characters) otherwise.
func ExportRecoveryKit(ring KeyRing, installationID, passphrase string, now time.Time) (RecoveryKit, error) {
	kit := RecoveryKit{Schema: RecoveryKitSchema, InstallationID: installationID, SignerFinger: ring.Fingerprint(),
		Recipient: ring.Recipient(), CreatedAt: now.UTC()}
	sealed := passphrase != ""
	kit.HasPassphrase = &sealed
	if !sealed {
		kit.Identity = ring.Identity.String()
		kit.PassphraseHintCN = recoveryNotePlain
		return kit, nil
	}
	if !validPassphrase(passphrase) {
		return RecoveryKit{}, ErrWeakPassphrase
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return RecoveryKit{}, err
	}
	recipient.SetWorkFactor(18)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return RecoveryKit{}, err
	}
	if _, err := io.WriteString(writer, ring.Identity.String()); err != nil {
		return RecoveryKit{}, err
	}
	if err := writer.Close(); err != nil {
		return RecoveryKit{}, err
	}
	kit.SealedIdentity = encodeBase64(ciphertext.Bytes())
	kit.PassphraseHintCN = recoveryNoteSealed
	return kit, nil
}

// ParseRecoveryKit decodes a kit without opening it, so a caller can tell
// whether a passphrase is needed before asking for one.
func ParseRecoveryKit(encoded []byte) (RecoveryKit, error) {
	var kit RecoveryKit
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&kit); err != nil || kit.Schema != RecoveryKitSchema || !fingerprintPattern.MatchString(kit.SignerFinger) {
		return RecoveryKit{}, errors.New("recovery kit is invalid")
	}
	if kit.NeedsPassphrase() != (kit.SealedIdentity != "") || kit.NeedsPassphrase() == (kit.Identity != "") {
		return RecoveryKit{}, errors.New("recovery kit is invalid")
	}
	return kit, nil
}

// OpenRecoveryKit returns the identity; passphrase is ignored for a kit
// exported without one.
func OpenRecoveryKit(encoded []byte, passphrase string) (*age.X25519Identity, RecoveryKit, error) {
	kit, err := ParseRecoveryKit(encoded)
	if err != nil {
		return nil, RecoveryKit{}, err
	}
	var plain []byte
	if !kit.NeedsPassphrase() {
		plain = []byte(kit.Identity)
	} else {
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
		if plain, err = io.ReadAll(io.LimitReader(reader, 4096)); err != nil {
			return nil, RecoveryKit{}, errors.New("recovery kit is damaged")
		}
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	clear(plain)
	if err != nil || identity.Recipient().String() != kit.Recipient {
		return nil, RecoveryKit{}, errors.New("recovery kit is damaged")
	}
	return identity, kit, nil
}
