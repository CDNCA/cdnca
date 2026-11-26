package accountregistrationproof

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// one proof cookie per channel; the legacy one still reads.
// and per challenge, the registration names it.
func TestResolveProofReferencesPerChannel(t *testing.T) {
	reference := func(fill byte) string {
		return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, ReferenceBytes))
	}
	email, sms, otherEmail := reference(0x11), reference(0x22), reference(0x33)
	emailID, smsID, otherEmailID := uuid.New(), uuid.New(), uuid.New()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	for _, proof := range []struct {
		channel   string
		id        uuid.UUID
		reference string
	}{{"email", emailID, email}, {"sms", smsID, sms}} {
		cookie, err := NewChannelReferenceCookie(proof.channel, proof.id, proof.reference, time.Now().Add(time.Minute))
		if err != nil || cookie.Name != ChannelCookieName(proof.channel, proof.id) || !cookie.HttpOnly || !cookie.Secure {
			t.Fatalf("cookie %#v err=%v", cookie, err)
		}
		request.AddCookie(cookie)
	}
	// one proof per channel: found with or without the challenge named
	for _, named := range []map[string]uuid.UUID{nil, {"email": emailID, "sms": smsID}} {
		legacy, channels, err := CookieReferenceResolver{}.ResolveProofReferences(request, named)
		if err != nil || legacy != "" || channels["email"] != email || channels["sms"] != sms {
			t.Fatalf("named=%v legacy=%q channels=%v err=%v", named, legacy, channels, err)
		}
	}
	// another tab's email proof: the named challenge decides, unnamed is ambiguous
	request.AddCookie(&http.Cookie{Name: ChannelCookieName("email", otherEmailID), Value: otherEmail})
	for named, want := range map[uuid.UUID]string{emailID: email, otherEmailID: otherEmail, uuid.New(): ""} {
		_, channels, err := CookieReferenceResolver{}.ResolveProofReferences(request, map[string]uuid.UUID{"email": named})
		if err != nil || channels["email"] != want || channels["sms"] != sms {
			t.Fatalf("named %s: channels=%v err=%v", named, channels, err)
		}
	}
	if _, channels, err := (CookieReferenceResolver{}).ResolveProofReferences(request, nil); err != nil || channels["email"] != "" {
		t.Fatalf("two email proofs, none named: %v %v", channels, err)
	}
	old := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	old.AddCookie(&http.Cookie{Name: CookieName, Value: email})
	old.AddCookie(&http.Cookie{Name: CookieName + "_sms", Value: sms})
	if legacy, channels, err := (CookieReferenceResolver{}).ResolveProofReferences(old, nil); err != nil || legacy != email ||
		len(channels) != 1 || channels["sms"] != sms {
		t.Fatalf("legacy cookies: %q %v %v", legacy, channels, err)
	}
	duplicate := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	name := ChannelCookieName("email", emailID)
	duplicate.Header.Add("Cookie", name+"="+email+"; "+name+"="+email)
	if _, _, err := (CookieReferenceResolver{}).ResolveProofReferences(duplicate, nil); err == nil {
		t.Fatal("duplicate channel cookie accepted")
	}
	if _, _, err := (CookieReferenceResolver{}).ResolveProofReferences(httptest.NewRequest(http.MethodPost, "/", nil), nil); err == nil {
		t.Fatal("no cookie accepted")
	}
	if _, err := NewChannelReferenceCookie("fax", emailID, email, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("unknown channel accepted")
	}
	if _, err := NewChannelReferenceCookie("email", uuid.Nil, email, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("no challenge accepted")
	}
	if ValidChallengeIDs(map[string]uuid.UUID{"fax": emailID}) || ValidChallengeIDs(map[string]uuid.UUID{"email": uuid.Nil}) ||
		!ValidChallengeIDs(map[string]uuid.UUID{"email": emailID, "sms": smsID}) || !ValidChallengeIDs(nil) {
		t.Fatal("ValidChallengeIDs")
	}
}
