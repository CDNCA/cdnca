package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

const (
	operationIntentSchema  = "cdnca.control-recovery-driver.intent/v1"
	operationReceiptSchema = "cdnca.control-recovery-driver.receipt/v1"
	uncertainCode          = "operation_outcome_uncertain"
)

type operationIntent struct {
	Schema      string    `json:"schema"`
	Operation   string    `json:"operation"`
	Identity    string    `json:"identity"`
	InputSHA256 string    `json:"input_sha256"`
	StartedAt   time.Time `json:"started_at"`
}

type operationReceipt struct {
	Schema      string          `json:"schema"`
	Operation   string          `json:"operation"`
	Identity    string          `json:"identity"`
	InputSHA256 string          `json:"input_sha256"`
	State       string          `json:"state"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	CompletedAt time.Time       `json:"completed_at"`
}

type operationStore struct {
	directory string
}

func newOperationStore(root string) (*operationStore, error) {
	directory := filepath.Join(root, "operations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("create operation state directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil || validatePrivateDirectory(directory) != nil {
		return nil, errors.New("secure operation state directory")
	}
	return &operationStore{directory: directory}, nil
}

func (store *operationStore) execute(operation, identity string, input any, reconcileUncertain bool, mutate func() (any, string)) (json.RawMessage, string) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, "invalid_operation_input"
	}
	digest := sha256.Sum256(encoded)
	inputSHA := hex.EncodeToString(digest[:])
	base := safeStateName(operation + "-" + identity)
	intentPath := filepath.Join(store.directory, base+".intent.json")
	receiptPath := filepath.Join(store.directory, base+".receipt.json")

	if receipt, found, valid := readOperationReceipt(receiptPath); found {
		if !valid {
			return nil, uncertainCode
		}
		if receipt.Operation != operation || receipt.Identity != identity || receipt.InputSHA256 != inputSHA {
			return nil, "idempotency_conflict"
		}
		return append(json.RawMessage(nil), receipt.Output...), receipt.ErrorCode
	}
	intent := operationIntent{
		Schema: operationIntentSchema, Operation: operation, Identity: identity,
		InputSHA256: inputSHA, StartedAt: time.Now().UTC(),
	}
	if existing, found, valid := readOperationIntent(intentPath); found {
		if !valid {
			return nil, uncertainCode
		}
		if existing.Operation != operation || existing.Identity != identity || existing.InputSHA256 != inputSHA {
			return nil, "idempotency_conflict"
		}
		if !reconcileUncertain {
			return nil, uncertainCode
		}
	} else if err := writeExclusiveJSON(intentPath, intent); err != nil {
		return nil, uncertainCode
	}
	output, code := mutate()
	outputJSON, marshalErr := json.Marshal(output)
	if output == nil {
		outputJSON = nil
	}
	if marshalErr != nil {
		return nil, uncertainCode
	}
	state := "succeeded"
	if code != "" {
		state = "failed"
	}
	receipt := operationReceipt{
		Schema: operationReceiptSchema, Operation: operation, Identity: identity,
		InputSHA256: inputSHA, State: state, ErrorCode: code, Output: outputJSON, CompletedAt: time.Now().UTC(),
	}
	if err := writeExclusiveJSON(receiptPath, receipt); err != nil {
		return nil, uncertainCode
	}
	return outputJSON, code
}

func readOperationIntent(path string) (operationIntent, bool, bool) {
	encoded, err := controlbackup.ReadTrustedFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return operationIntent{}, false, false
	}
	var value operationIntent
	if err != nil || controlbackup.DecodeStrictJSON(encoded, &value) != nil || value.Schema != operationIntentSchema {
		return operationIntent{}, true, false
	}
	return value, true, true
}

func readOperationReceipt(path string) (operationReceipt, bool, bool) {
	encoded, err := controlbackup.ReadTrustedFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return operationReceipt{}, false, false
	}
	var value operationReceipt
	if err != nil || controlbackup.DecodeStrictJSON(encoded, &value) != nil || value.Schema != operationReceiptSchema ||
		(value.State != "succeeded" && value.State != "failed") {
		return operationReceipt{}, true, false
	}
	return value, true, true
}

func writeExclusiveJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("persist operation state")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func safeStateName(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func canonicalJSONEqual(left, right []byte) bool {
	return bytes.Equal(bytes.TrimSpace(left), bytes.TrimSpace(right))
}
