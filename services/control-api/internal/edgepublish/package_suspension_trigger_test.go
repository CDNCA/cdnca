package edgepublish

import "testing"

// bb03 (migration 555): a suspension stop or restore goes out at once and
// changes content.
func TestSystemTriggerPackageSuspensionIsImmediateContent(t *testing.T) {
	if SystemTriggerPackageSuspension != "package_suspension" || !validSystemTrigger(SystemTriggerPackageSuspension) ||
		!SystemTriggerImmediate(SystemTriggerPackageSuspension) ||
		!systemContentTrigger([]string{SystemTriggerPackageSuspension}) {
		t.Fatal("package_suspension must be a valid, immediate content trigger")
	}
}
