package notificationcontrol

import "testing"

// 订阅响应带出本人邮箱/手机号是否可用于投递，
// 判定与投递端 recipient_unavailable 一致：空或格式无效都算未绑定。
func TestContactBound(t *testing.T) {
	email := func(value string) *string { return &value }
	for _, item := range []struct {
		email, phone *string
		wantEmail    bool
		wantPhone    bool
	}{
		{nil, nil, false, false},
		{email(""), email(""), false, false},
		{email("ops@example.test"), email("+8613800000000"), true, true},
		{email("Ops <ops@example.test>"), email("138-0000"), false, false},
		{email("no-at-sign"), email("+"), false, false},
		{email("ops@example.test\r\n"), email(" 13800000000"), false, false},
	} {
		gotEmail, gotPhone := contactBound(item.email, item.phone)
		if gotEmail != item.wantEmail || gotPhone != item.wantPhone {
			t.Errorf("contactBound(%v,%v)=(%v,%v), want (%v,%v)", deref(item.email), deref(item.phone), gotEmail, gotPhone, item.wantEmail, item.wantPhone)
		}
	}
}

func deref(value *string) string {
	if value == nil {
		return "<nil>"
	}
	return *value
}
