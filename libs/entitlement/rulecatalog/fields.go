package rulecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// Shared helpers of the rule content format and the custom rule report; the
// signed delivery of system rules is libs/entitlement/artifactcatalog.

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DigestFields hashes length-prefixed fields (same construction as the
// platform policy, artifact catalog and report proofs).
func DigestFields(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}

func ValidUUID(value string) bool { return uuidPattern.MatchString(value) }

// RejectDuplicateKeys walks the JSON token stream and fails on a repeated
// object key at any depth.
func RejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	type frame struct {
		object bool
		keys   map[string]struct{}
		expect bool
	}
	stack := []*frame{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.object {
					top.expect = true
				}
				stack = append(stack, &frame{object: delim == '{', keys: map[string]struct{}{}, expect: true})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top != nil && top.object && top.expect {
			key, ok := token.(string)
			if !ok {
				return ErrInvalidReport
			}
			if _, exists := top.keys[key]; exists {
				return ErrInvalidReport
			}
			top.keys[key] = struct{}{}
			top.expect = false
			continue
		}
		if top != nil && top.object {
			top.expect = true
		}
	}
}
