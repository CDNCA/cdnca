package diskguard

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

func ValidateConfig(config Config) error {
	return validateConfig(config)
}

func validateConfig(config Config) error {
	if config.SchemaVersion != ConfigSchemaVersion || !identifierPattern.MatchString(config.ConfigID) ||
		config.Revision == 0 || !safeAbsolutePath(config.LockPath) ||
		config.LowWatermark >= config.HighWatermark || config.HighWatermark > 10000 ||
		config.EvaluationPeriod < time.Second || config.EvaluationPeriod > 24*time.Hour ||
		config.MaxDeletedFiles < 1 || config.MaxDeletedFiles > 100000 ||
		config.MaxAllocatedBytes == 0 || len(config.Directories) == 0 || len(config.Directories) > 128 {
		return ErrInvalidConfig
	}
	seenIDs := make(map[string]struct{}, len(config.Directories))
	seenPaths := make(map[string]struct{}, len(config.Directories))
	protectedPaths := make([]string, 0, len(config.ProtectedPaths))
	for _, protectedPath := range config.ProtectedPaths {
		if !safeAbsolutePath(protectedPath) || protectedPath == "/" {
			return ErrInvalidConfig
		}
		protectedPaths = append(protectedPaths, filepath.Clean(protectedPath))
	}
	for _, directory := range config.Directories {
		if !identifierPattern.MatchString(directory.ID) || !safeAbsolutePath(directory.Path) ||
			directory.Path == "/" || directory.MinimumAge < 0 || directory.MinimumRemain < 0 ||
			directory.MinimumRemain > 100000 || len(directory.Patterns) == 0 || len(directory.Patterns) > 128 ||
			(directory.Kind != DirectoryRotatedLogs && directory.Kind != DirectoryCacheTemp) {
			return ErrInvalidConfig
		}
		if _, exists := seenIDs[directory.ID]; exists {
			return ErrInvalidConfig
		}
		cleanPath := filepath.Clean(directory.Path)
		for _, protectedPath := range protectedPaths {
			if pathsOverlap(cleanPath, protectedPath) {
				return ErrInvalidConfig
			}
		}
		if _, exists := seenPaths[cleanPath]; exists {
			return ErrInvalidConfig
		}
		seenIDs[directory.ID] = struct{}{}
		seenPaths[cleanPath] = struct{}{}
		for _, pattern := range directory.Patterns {
			if !validPattern(pattern) {
				return ErrInvalidConfig
			}
		}
		active := make(map[string]struct{}, len(directory.ActiveNames))
		for _, name := range directory.ActiveNames {
			if !safeBaseName(name) {
				return ErrInvalidConfig
			}
			if _, exists := active[name]; exists {
				return ErrInvalidConfig
			}
			active[name] = struct{}{}
		}
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	for _, pair := range [][2]string{{left, right}, {right, left}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func safeAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}

func safeBaseName(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value &&
		!strings.ContainsRune(value, '\\') && !strings.ContainsRune(value, '\x00')
}

func validPattern(pattern string) bool {
	if !safeBaseName(pattern) || pattern == "*" {
		return false
	}
	_, err := path.Match(pattern, "candidate")
	return err == nil
}

func matchesPattern(patterns []string, name string) bool {
	for _, pattern := range patterns {
		matched, _ := path.Match(pattern, name)
		if matched {
			return true
		}
	}
	return false
}

var protectedNameTokens = []string{
	"active", "audit", "identity", "certificate", "cert", "config", "credential",
	"entitlement", "key", "lease", "license", "private", "rollback", "secret", "upgrade", "version",
}

func protectedName(name string, activeNames map[string]struct{}) bool {
	if _, exists := activeNames[name]; exists {
		return true
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, quarantinePrefix) {
		return true
	}
	for _, token := range protectedNameTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func rotatedLogName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, ".log.") || strings.Contains(lower, ".log-")
}

func compressedLogName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".gz", ".zst", ".xz", ".bz2"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
