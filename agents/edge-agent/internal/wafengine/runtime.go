package wafengine

// CheckSummary is the deployment status check of the engine.
func (status Status) CheckSummary() (string, bool) {
	switch status.State {
	case StateActive:
		return "waf crs engine active " + status.Version, true
	case StateDegraded:
		return "waf crs engine degraded: " + status.Reason + " (crs sites run self-developed detection only)", false
	default:
		return "waf crs engine not required", true
	}
}
