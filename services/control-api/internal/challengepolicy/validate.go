package challengepolicy

import (
	"crypto/sha256"
	"encoding/json"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxConfigBytes = 32 << 10
	maxCursorBytes = 1024
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var keyReferencePattern = regexp.MustCompile(`^(keyref|vault|kms):[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$`)
var appReferencePattern = regexp.MustCompile(`^appref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,120}$`)

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func normalizeConfig(config *Config) error {
	config.Mode = strings.TrimSpace(config.Mode)
	config.IPBinding = strings.TrimSpace(config.IPBinding)
	config.KeyReference = strings.TrimSpace(config.KeyReference)
	if config.Priority < 1 || config.Priority > 1_000_000 ||
		config.ChallengeTTLSeconds < 10 || config.ChallengeTTLSeconds > 300 ||
		config.PassTTLSeconds < 1 || config.PassTTLSeconds > 3600 ||
		config.ClockSkewSeconds < 0 || config.ClockSkewSeconds > 30 ||
		config.AttemptsPerNonce != 1 ||
		config.FailureWindowSeconds < 1 || config.FailureWindowSeconds > 3600 ||
		config.MaxFailuresPerWindow < 1 || config.MaxFailuresPerWindow > 20 ||
		(config.IPBinding != IPBindingNone && config.IPBinding != IPBindingExact) ||
		!keyReferencePattern.MatchString(config.KeyReference) {
		return ErrValidation
	}
	switch config.Mode {
	case ModeDelay:
		if config.MinDelaySeconds < 5 || config.MinDelaySeconds > 10 {
			return ErrValidation
		}
	case ModeClick, ModeSlider, ModeCaptcha:
		if config.MinDelaySeconds != 0 || config.ExternalProvider != nil {
			return ErrValidation
		}
	case ModeExternal:
		if config.MinDelaySeconds != 0 || config.ExternalProvider == nil {
			return ErrValidation
		}
		config.ExternalProvider.Provider = strings.TrimSpace(config.ExternalProvider.Provider)
		config.ExternalProvider.AppReference = strings.TrimSpace(config.ExternalProvider.AppReference)
		if (config.ExternalProvider.Provider != ProviderTencent && config.ExternalProvider.Provider != ProviderGeetest4) ||
			!appReferencePattern.MatchString(config.ExternalProvider.AppReference) {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	if config.Mode == ModeDelay && config.ExternalProvider != nil {
		return ErrValidation
	}
	if config.ChallengeTTLSeconds <= config.MinDelaySeconds+config.ClockSkewSeconds ||
		len(config.BypassRoutes) > 32 {
		return ErrValidation
	}
	if config.BypassRoutes == nil {
		config.BypassRoutes = []BypassRoute{}
	}
	seen := make(map[string]struct{}, len(config.BypassRoutes))
	for index := range config.BypassRoutes {
		route := &config.BypassRoutes[index]
		route.Kind = strings.TrimSpace(route.Kind)
		if (route.Kind != BypassExact && route.Kind != BypassPrefix) || !validBypassPath(route.Path, route.Kind) {
			return ErrValidation
		}
		if _, duplicate := seen[route.Path]; duplicate {
			return ErrValidation
		}
		seen[route.Path] = struct{}{}
	}
	sort.Slice(config.BypassRoutes, func(left, right int) bool {
		if config.BypassRoutes[left].Path != config.BypassRoutes[right].Path {
			return config.BypassRoutes[left].Path < config.BypassRoutes[right].Path
		}
		return config.BypassRoutes[left].Kind < config.BypassRoutes[right].Kind
	})
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) > maxConfigBytes {
		return ErrValidation
	}
	return nil
}

func normalizeHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(host) < 1 || len(host) > 253 || !isASCII(host) || strings.ContainsAny(host, ":/\\%") {
		return "", ErrValidation
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrValidation
		}
		for index := range label {
			character := label[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", ErrValidation
		}
	}
	return host, nil
}

func validBypassPath(value, kind string) bool {
	if len(value) < 1 || len(value) > 512 || !isASCII(value) || hasControl(value) ||
		value[0] != '/' || strings.HasPrefix(value, "//") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, "\\?#%") {
		return false
	}
	if kind == BypassPrefix {
		return value != "/" && strings.HasSuffix(value, "/") && path.Clean(strings.TrimSuffix(value, "/")) == strings.TrimSuffix(value, "/")
	}
	return path.Clean(value) == value
}

func validWriteMetadata(metadata WriteMetadata) bool {
	return metadataPattern.MatchString(metadata.IdempotencyKey) &&
		metadataPattern.MatchString(metadata.RequestID) && metadataPattern.MatchString(metadata.TraceID)
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validateTarget(actor Actor, target uuid.UUID) error {
	if !validActor(actor) || target == uuid.Nil {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && actor.ScopeID != target {
		return ErrNotFound
	}
	return nil
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func isASCII(value string) bool {
	return utf8.ValidString(value) && strings.IndexFunc(value, func(character rune) bool { return character > 0x7f }) < 0
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0
}
