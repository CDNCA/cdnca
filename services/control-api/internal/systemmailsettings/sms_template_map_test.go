package systemmailsettings

import "testing"

// TestParseSMSTemplateMapEnglishCode: an entry may name the
// English provider template; it is optional and validated like code.
func TestParseSMSTemplateMapEnglishCode(t *testing.T) {
	templates, err := ParseSMSTemplateMap(`{"node.offline.zh-cn":{"code":"SMS_1","code_en":"SMS_2","variables":{"name":"n"}},` +
		`"account_login_verification":{"code":"SMS_3","variables":{"code":"code"}}}`)
	if err != nil || templates["node.offline.zh-cn"].CodeEN != "SMS_2" || templates["account_login_verification"].CodeEN != "" {
		t.Fatalf("templates=%+v err=%v", templates, err)
	}
	for _, raw := range []string{
		`{"node.offline.zh-cn":{"code":"SMS_1","code_en":" SMS_2","variables":{}}}`,
		`{"node.offline.zh-cn":{"code":"SMS_1","code_en":"SMS\n2","variables":{}}}`,
	} {
		if _, err := ParseSMSTemplateMap(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
