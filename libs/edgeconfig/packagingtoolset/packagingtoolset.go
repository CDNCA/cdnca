// Package packagingtoolset is the EdgeRuntimeStatus.packaging_toolset contract
// (CAPABILITY_NAME_PACKAGING_TOOLSET_REPORT v1) shared by the
// edge Agent, agent-gateway and control-api.
package packagingtoolset

import "regexp"

// APIVersion is the CAPABILITY_NAME_PACKAGING_TOOLSET_REPORT version.
const APIVersion = 1

const (
	// MaxReasonBytes matches the 200 printable bytes install.sh records.
	MaxReasonBytes = 200
	MaxVersionLen  = 128
)

// RefreshStatuses: none (no record), unknown (unreadable or unknown format),
// and the status= values of the toolset-refresh record.
var RefreshStatuses = map[string]bool{"none": true, "unknown": true, "ok": true, "failed": true, "skipped": true}

// HelperStatuses: helper_status= values; "" when the record predates them.
var HelperStatuses = map[string]bool{"": true, "ok": true, "unchanged": true, "failed": true, "skipped": true}

var (
	version = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	digest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidVersion is the release version grammar of the record.
func ValidVersion(value string) bool {
	return len(value) <= MaxVersionLen && version.MatchString(value)
}

// ValidReason: printable ASCII, at most MaxReasonBytes.
func ValidReason(value string) bool {
	if len(value) > MaxReasonBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// Valid checks one reported status. none and unknown carry no version, time,
// reasons or helper result; a record status carries a version.
func Valid(refreshStatus, refreshVersion, refreshReason string, hasTime bool, helperStatus, helperReason, scriptsSHA256, helperSHA256 string) bool {
	if !RefreshStatuses[refreshStatus] || !HelperStatuses[helperStatus] || !ValidReason(refreshReason) || !ValidReason(helperReason) {
		return false
	}
	if (scriptsSHA256 != "" && !digest.MatchString(scriptsSHA256)) || (helperSHA256 != "" && !digest.MatchString(helperSHA256)) {
		return false
	}
	if refreshStatus == "none" || refreshStatus == "unknown" {
		return refreshVersion == "" && refreshReason == "" && !hasTime && helperStatus == "" && helperReason == ""
	}
	if !ValidVersion(refreshVersion) || !hasTime {
		return false
	}
	return helperStatus != "" || helperReason == ""
}
