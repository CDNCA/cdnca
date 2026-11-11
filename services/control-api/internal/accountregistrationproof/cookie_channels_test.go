package accountregistrationproof

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// one proof cookie per channel; the legacy one still reads.
func TestResolveProofReferencesPerChannel(t *testing.T) {
	email := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, ReferenceBytes))
	sms := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, ReferenceBytes))
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	for channel, reference := range map[string]string{"email": email, "sms": sms} {
		cookie, err := NewChannelReferenceCookie(channel, reference, time.Now().Add(time.Minute))
		if err != nil || cookie.Name != ChannelCookieName(channel) || !cookie.HttpOnly || !cookie.Secure {
			t.Fatalf("cookie %#v err=%v", cookie, err)
		}
		request.AddCookie(cookie)
	}
	legacy, channels, err := CookieReferenceResolver{}.ResolveProofReferences(request)
	if err != nil || legacy != "" || channels["email"] != email || channels["sms"] != sms {
		t.Fatalf("legacy=%q channels=%v err=%v", legacy, channels, err)
	}
	old := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	old.AddCookie(&http.Cookie{Name: CookieName, Value: email})
	if legacy, channels, err := (CookieReferenceResolver{}).ResolveProofReferences(old); err != nil || legacy != email || len(channels) != 0 {
		t.Fatalf("legacy cookie: %q %v %v", legacy, channels, err)
	}
	duplicate := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	duplicate.Header.Add("Cookie", ChannelCookieName("email")+"="+email+"; "+ChannelCookieName("email")+"="+email)
	if _, _, err := (CookieReferenceResolver{}).ResolveProofReferences(duplicate); err == nil {
		t.Fatal("duplicate channel cookie accepted")
	}
	if _, _, err := (CookieReferenceResolver{}).ResolveProofReferences(httptest.NewRequest(http.MethodPost, "/", nil)); err == nil {
		t.Fatal("no cookie accepted")
	}
	if _, err := NewChannelReferenceCookie("fax", email, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("unknown channel accepted")
	}
}
