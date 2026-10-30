package httpapi

import "github.com/cdnca/cdnca/services/control-api/internal/site"

const (
	compatibilitySiteNormal          = 200
	compatibilitySitePackageExpired  = 512
	compatibilitySiteTrafficExceeded = 513
	compatibilitySiteLocked          = 514
)

func statusStateFromCompatibilityCode(code int) (site.OperationalStatus, bool) {
	switch code {
	case compatibilitySiteNormal:
		return site.OperationalStatusNormal, true
	case compatibilitySitePackageExpired:
		return site.OperationalStatusPackageExpired, true
	case compatibilitySiteTrafficExceeded:
		return site.OperationalStatusTrafficExceeded, true
	case compatibilitySiteLocked:
		return site.OperationalStatusLocked, true
	default:
		return "", false
	}
}

func compatibilityCodeFromStatusState(state site.OperationalStatus) (int, bool) {
	switch state {
	case site.OperationalStatusNormal:
		return compatibilitySiteNormal, true
	case site.OperationalStatusPackageExpired:
		return compatibilitySitePackageExpired, true
	case site.OperationalStatusTrafficExceeded:
		return compatibilitySiteTrafficExceeded, true
	case site.OperationalStatusLocked:
		return compatibilitySiteLocked, true
	default:
		return 0, false
	}
}

func storedStatusFromOperationalState(state site.OperationalStatus) string {
	switch state {
	case site.OperationalStatusNormal:
		return site.StatusActive
	case site.OperationalStatusPackageExpired:
		return site.StatusPackageExpired
	case site.OperationalStatusTrafficExceeded:
		return site.StatusTrafficExceeded
	case site.OperationalStatusLocked:
		return site.StatusLocked
	default:
		return ""
	}
}
