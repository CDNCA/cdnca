package originauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"
)

func compileKey(provider string, ref KeyRef) (CompiledKey, error) {
	if !validIdentifier(ref.KeyID, 64) {
		return CompiledKey{}, reject("KEY_REFERENCE_INVALID")
	}
	raw, err := readSecretFile(ref.SecretFile)
	if err != nil {
		return CompiledKey{}, err
	}
	defer clear(raw)
	credential, err := decodeCredential(raw, provider)
	if err != nil {
		return CompiledKey{}, err
	}
	clearCredential(&credential)
	digest := sha256.Sum256(raw)
	return CompiledKey{KeyID: ref.KeyID, SecretFile: ref.SecretFile, SHA256: hex.EncodeToString(digest[:])}, nil
}

func loadCredential(provider string, ref CompiledKey, nowUnix int64) (Credential, error) {
	raw, err := readSecretFile(ref.SecretFile)
	if err != nil {
		return Credential{}, err
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	if !constantTimeHexEqual(hex.EncodeToString(digest[:]), ref.SHA256) {
		return Credential{}, reject("CREDENTIAL_BINDING_MISMATCH")
	}
	credential, err := decodeCredential(raw, provider)
	if err != nil {
		return Credential{}, err
	}
	if nowUnix < credential.NotBeforeUnix {
		clearCredential(&credential)
		return Credential{}, reject("CREDENTIAL_NOT_YET_VALID")
	}
	if nowUnix >= credential.ExpiresAtUnix {
		clearCredential(&credential)
		return Credential{}, reject("CREDENTIAL_EXPIRED")
	}
	return credential, nil
}

func decodeCredential(raw []byte, provider string) (Credential, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Credential{}, reject("CREDENTIAL_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var credential Credential
	if err := decoder.Decode(&credential); err != nil {
		return Credential{}, reject("CREDENTIAL_INVALID")
	}
	if err := requireEOF(decoder); err != nil {
		return Credential{}, reject("CREDENTIAL_INVALID")
	}
	if credential.SchemaVersion != CredentialVersion || credential.Provider != provider ||
		!validSecretField(credential.AccessKeyID, 256) || !validSecretField(credential.SecretAccessKey, 512) ||
		(credential.SessionToken != "" && !validSecretField(credential.SessionToken, 4096)) ||
		credential.NotBeforeUnix < 0 || credential.ExpiresAtUnix <= credential.NotBeforeUnix {
		clearCredential(&credential)
		return Credential{}, reject("CREDENTIAL_INVALID")
	}
	return credential, nil
}

func readSecretFile(path string) ([]byte, error) {
	if len(path) < 2 || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || hasControl(path) {
		return nil, reject("SECRET_FILE_UNSAFE")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	parentStat, parentOK := infoSys(parent)
	if err != nil || !parentOK || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 || parentStat.Uid != uint32(os.Geteuid()) {
		return nil, reject("SECRET_FILE_UNSAFE")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject("SECRET_FILE_UNAVAILABLE")
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, reject("SECRET_FILE_UNSAFE")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxCredentialBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxCredentialBytes {
		clear(raw)
		return nil, reject("SECRET_FILE_INVALID")
	}
	return raw, nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func validSecretField(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearCredential(value *Credential) {
	value.AccessKeyID = ""
	value.SecretAccessKey = ""
	value.SessionToken = ""
}

func constantTimeHexEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("trailing JSON")
}
