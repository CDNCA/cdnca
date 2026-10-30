package ccadaptive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type Mode string

const (
	ModeSimple Mode = "simple"
	ModeExpert Mode = "expert"
)

type Policy struct {
	SchemaVersion string          `json:"schema_version"`
	Revision      uint64          `json:"revision"`
	Enabled       bool            `json:"enabled"`
	Mode          Mode            `json:"mode"`
	Static        Limit           `json:"static"`
	Adaptive      *AdaptiveConfig `json:"adaptive,omitempty"`
}

func CompileJSON(raw []byte) ([]byte, *Policy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, invalidPolicy("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, nil, invalidPolicy("decode: %v", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, nil, err
	}
	if err := validatePolicy(policy); err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal canonical CC adaptive policy: %w", err)
	}
	canonical = append(canonical, '\n')
	if len(canonical) > MaxPolicyBytes {
		return nil, nil, invalidPolicy("canonical policy exceeds %d bytes", MaxPolicyBytes)
	}
	return canonical, &policy, nil
}

func PreserveDisabledBaseline(baseline []byte) []byte {
	return append([]byte(nil), baseline...)
}

func validatePolicy(policy Policy) error {
	if policy.SchemaVersion != SchemaVersion {
		return invalidPolicy("schema_version must be %q", SchemaVersion)
	}
	if policy.Revision < 1 || policy.Revision > MaxRevision {
		return invalidPolicy("revision must be between 1 and %d", MaxRevision)
	}
	if !policy.Enabled {
		return invalidPolicy("published enhancement policy must be enabled")
	}
	if !policy.Static.valid() {
		return invalidPolicy("static GCRA limit is invalid")
	}
	switch policy.Mode {
	case ModeSimple:
		if policy.Adaptive != nil {
			return invalidPolicy("simple mode must not contain adaptive settings")
		}
	case ModeExpert:
		if policy.Adaptive == nil {
			return invalidPolicy("expert mode requires adaptive settings")
		}
		if err := policy.Adaptive.validate(); err != nil {
			return invalidPolicy("adaptive: %v", err)
		}
	default:
		return invalidPolicy("mode must be simple or expert")
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return invalidPolicy("ambiguous JSON: %v", err)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalidPolicy("multiple JSON values are not allowed")
		}
		return invalidPolicy("trailing JSON: %v", err)
	}
	return nil
}

func invalidPolicy(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}
