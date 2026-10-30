package sitegroup

import (
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

var writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func normalizeRemark(value *string) (string, error) {
	if value == nil {
		return "", nil
	}
	if !utf8.ValidString(*value) {
		return "", fielderr.New(ErrInvalidInput, "remark", fielderr.Invalid)
	}
	if utf8.RuneCountInString(*value) > 1024 {
		return "", fielderr.New(ErrInvalidInput, "remark", fielderr.TooLong)
	}
	for _, character := range *value {
		if unicode.IsControl(character) && character != '\t' && character != '\n' && character != '\r' {
			return "", fielderr.New(ErrInvalidInput, "remark", fielderr.Invalid)
		}
	}
	return *value, nil
}

func normalizeName(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fielderr.New(ErrInvalidInput, "name", fielderr.Invalid)
	}
	value = strings.TrimSpace(value)
	if count := utf8.RuneCountInString(value); count < 1 {
		return "", fielderr.New(ErrInvalidInput, "name", fielderr.Required)
	} else if count > 128 {
		return "", fielderr.New(ErrInvalidInput, "name", fielderr.TooLong)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", fielderr.New(ErrInvalidInput, "name", fielderr.Invalid)
		}
	}
	return value, nil
}

func validWriteMetadata(metadata WriteMetadata) bool {
	return writeMetadataPattern.MatchString(metadata.IdempotencyKey) &&
		writeMetadataPattern.MatchString(metadata.RequestID)
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
