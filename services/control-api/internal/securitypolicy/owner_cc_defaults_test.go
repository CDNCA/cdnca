package securitypolicy

import "testing"

// fp-site4：默认设置 > 黑名单时间 / 白名单时间只填新 CC 策略没写的时长，按 custom 带入。
func TestWithOwnerCCDurations(t *testing.T) {
	fields := PolicyFields{Kind: KindCC}
	if err := withOwnerCCDurations(&fields, 1200, 0); err != nil {
		t.Fatal(err)
	}
	if got := fields.CCSettings; got == nil || got.BanSeconds == nil || *got.BanSeconds != (CCDuration{Mode: CCSettingCustom, Seconds: 1200}) ||
		got.PassSeconds != nil {
		t.Fatalf("settings %+v", got)
	}
	named := PolicyFields{Kind: KindCC, CCSettings: &CCSettings{BanSeconds: &CCDuration{Mode: CCSettingCustom, Seconds: 60}}}
	if err := withOwnerCCDurations(&named, 1200, 3600); err != nil {
		t.Fatal(err)
	}
	if named.CCSettings.BanSeconds.Seconds != 60 || named.CCSettings.PassSeconds == nil || named.CCSettings.PassSeconds.Seconds != 3600 {
		t.Fatalf("named %+v %+v", named.CCSettings.BanSeconds, named.CCSettings.PassSeconds)
	}
	none := PolicyFields{Kind: KindCC}
	if err := withOwnerCCDurations(&none, 0, 0); err != nil || none.CCSettings != nil {
		t.Fatalf("no defaults: %+v %v", none.CCSettings, err)
	}
}
