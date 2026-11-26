package accountregistration

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// a QQ number is stored when given, required when the platform asks
// for it, and must be 5–12 digits without a leading zero.
func TestBuiltInRegistrationQQ(t *testing.T) {
	cases := []struct {
		name     string
		required bool
		qq       string
		want     error
		stored   string
	}{
		{"optional, empty", false, "", nil, ""},
		{"optional, given", false, " 123456789 ", nil, "123456789"},
		{"required, empty", true, "", ErrInvalidInput, ""},
		{"required, given", true, "10001", nil, "10001"},
		{"too short", false, "1234", ErrInvalidInput, ""},
		{"too long", false, "1234567890123", ErrInvalidInput, ""},
		{"leading zero", false, "012345", ErrInvalidInput, ""},
		{"not digits", false, "12345a", ErrInvalidInput, ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			service, store, _ := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true, QQRequired: item.required})
			input := builtInInput()
			input.QQ = item.qq
			_, err := service.Register(context.Background(), input)
			if !errors.Is(err, item.want) {
				t.Fatalf("err=%v want %v", err, item.want)
			}
			if item.want == nil && (len(store.calls) != 1 || store.calls[0].QQ != item.stored) {
				t.Fatalf("stored=%#v", store.calls)
			}
		})
	}
}

// built-in registration accepts the current terms version only.
func TestBuiltInRegistrationRefusesOutdatedTerms(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true, TermsVersion: "terms-0123456789ab"})
	if _, err := service.Register(context.Background(), builtInInput()); !errors.Is(err, ErrTermsOutdated) {
		t.Fatalf("outdated terms: %v", err)
	}
	if len(store.calls) != 0 || len(captcha.calls) != 0 {
		t.Fatalf("an outdated acceptance spent the CAPTCHA or reached the store")
	}
	input := builtInInput()
	input.TermsVersion = "terms-0123456789ab"
	if result, err := service.Register(context.Background(), input); err != nil || !result.Accepted {
		t.Fatalf("current terms: %#v %v", result, err)
	}
}

// a registration completed under terms A whose answer was lost
// replays its receipt after the terms become B; the same key with another
// request is still a conflict, and a first submission of A is still refused
// without spending the CAPTCHA.
func TestBuiltInRegistrationReplaysAfterTermsChange(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	if _, err := service.Register(context.Background(), builtInInput()); err != nil {
		t.Fatal(err)
	}
	store.completed = map[string][32]byte{store.calls[0].IdempotencyKey: store.calls[0].RequestDigest}
	service.policy.(*registrationPolicyStub).settings.TermsVersion = "terms-2026-11"

	result, err := service.Register(context.Background(), builtInInput())
	if err != nil || !result.Accepted || !result.Replayed || len(captcha.calls) != 1 || len(store.calls) != 1 {
		t.Fatalf("replay after terms change: %#v %v captcha=%d store=%d", result, err, len(captcha.calls), len(store.calls))
	}
	other := builtInInput()
	other.DisplayName = "Mallory"
	if _, err := service.Register(context.Background(), other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key, other request: %v", err)
	}
	fresh := builtInInput()
	fresh.IdempotencyKey = "registration-builtin-2"
	if _, err := service.Register(context.Background(), fresh); !errors.Is(err, ErrTermsOutdated) {
		t.Fatalf("first submission of outdated terms: %v", err)
	}
	if len(captcha.calls) != 1 || len(store.calls) != 1 {
		t.Fatalf("an outdated acceptance spent the CAPTCHA or reached the store: captcha=%d store=%d", len(captcha.calls), len(store.calls))
	}
}

// unpublished terms (empty body) have a version a sign-up
// accepts; publishing A and changing to B are new versions each time, and
// the registration accepted while unpublished still replays its receipt.
func TestBuiltInRegistrationReplaysAcrossTermsPublishing(t *testing.T) {
	title := systemusersettings.DefaultSettings().TermsTitle
	unpublished := systemusersettings.TermsVersion(title, "")
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true, TermsVersion: unpublished})
	input := builtInInput()
	input.TermsVersion = unpublished
	if _, err := service.Register(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	store.completed = map[string][32]byte{store.calls[0].IdempotencyKey: store.calls[0].RequestDigest}
	seen := map[string]bool{unpublished: true}
	for _, body := range []string{"第一条 协议 A", "第一条 协议 B"} {
		version := systemusersettings.TermsVersion(title, body)
		if seen[version] {
			t.Fatalf("terms %q kept an earlier version %s", body, version)
		}
		seen[version] = true
		service.policy.(*registrationPolicyStub).settings.TermsVersion = version
		if result, err := service.Register(context.Background(), input); err != nil || !result.Replayed {
			t.Fatalf("replay under %q: %#v %v", body, result, err)
		}
	}
	if len(store.calls) != 1 || len(captcha.calls) != 1 {
		t.Fatalf("a replay reached the store or spent the CAPTCHA: store=%d captcha=%d", len(store.calls), len(captcha.calls))
	}
}

// with no readable terms (no site terms page, none published)
// sign-up neither checks nor records an acceptance; once terms are required
// the same request still replays its receipt, and a new one must accept them.
func TestBuiltInRegistrationWithoutRequiredTerms(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	required := false
	service.RequireTermsWhen(func(context.Context) (bool, error) { return required, nil })
	input := builtInInput()
	input.TermsAccepted, input.TermsVersion = false, ""
	result, err := service.Register(context.Background(), input)
	if err != nil || !result.Accepted || result.Replayed {
		t.Fatalf("no terms required: %#v %v", result, err)
	}
	if len(store.calls) != 1 || store.calls[0].TermsVersion != "" {
		t.Fatalf("an acceptance was recorded: %#v", store.calls)
	}
	// a page still sending a version records none either
	sent := builtInInput()
	sent.IdempotencyKey, sent.Username, sent.Email = "registration-builtin-sent", "sent-terms", "sent@example.com"
	if _, err := service.Register(context.Background(), sent); err != nil || store.calls[1].TermsVersion != "" {
		t.Fatalf("sent version recorded: %#v %v", store.calls[1], err)
	}
	store.completed = map[string][32]byte{store.calls[0].IdempotencyKey: store.calls[0].RequestDigest}
	required = true
	if replay, err := service.Register(context.Background(), input); err != nil || !replay.Replayed {
		t.Fatalf("replay once terms are required: %#v %v", replay, err)
	}
	fresh := input
	fresh.IdempotencyKey = "registration-builtin-fresh"
	if _, err := service.Register(context.Background(), fresh); !errors.Is(err, ErrTermsOutdated) {
		t.Fatalf("terms required, none accepted: %v", err)
	}
	if len(store.calls) != 2 || len(captcha.calls) != 2 {
		t.Fatalf("store=%d captcha=%d", len(store.calls), len(captcha.calls))
	}
	required = false
	service.RequireTermsWhen(func(context.Context) (bool, error) { return false, errors.New("site unreadable") })
	if _, err := service.Register(context.Background(), fresh); !errors.Is(err, ErrRegistrationPolicyUnavailable) {
		t.Fatalf("requirement unreadable: %v", err)
	}
}

// verified contact: the replay re-reads the proof consumed
// under the key; a first submission of outdated terms spends no proof.
func TestBuiltInVerifiedRegistrationReplaysAfterTermsChange(t *testing.T) {
	proofs := &channelProofStub{}
	service, store, _ := newBuiltInWithProofs(t, policyFor(true, false), proofs)
	input := builtInInput()
	input.Captcha.ID, input.Captcha.Answer = uuid.Nil, ""
	input.ProofReferences = map[string]string{VerificationEmail: testEmailReference}
	if _, err := service.Register(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	store.completed = map[string][32]byte{store.calls[0].IdempotencyKey: store.calls[0].RequestDigest}
	service.policy.(*registrationPolicyStub).settings.TermsVersion = "terms-2026-11"

	result, err := service.Register(context.Background(), input)
	if err != nil || !result.Replayed || len(store.calls) != 1 || len(proofs.calls) != 2 {
		t.Fatalf("replay after terms change: %#v %v store=%d proofs=%d", result, err, len(store.calls), len(proofs.calls))
	}
	other := input
	other.DisplayName = "Mallory"
	if _, err := service.Register(context.Background(), other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key, other request: %v", err)
	}
	fresh := input
	fresh.IdempotencyKey = "registration-builtin-2"
	spent := len(proofs.calls)
	if _, err := service.Register(context.Background(), fresh); !errors.Is(err, ErrTermsOutdated) {
		t.Fatalf("first submission of outdated terms: %v", err)
	}
	if len(proofs.calls) != spent || len(store.calls) != 1 {
		t.Fatalf("an outdated acceptance spent a proof or reached the store: proofs=%d store=%d", len(proofs.calls)-spent, len(store.calls))
	}
}

var generatedUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*-[0-9a-f]{8}$`)

// a username left empty is generated while not required,
// the same for the same contacts (a retry replays and returns it), and the
// display name follows it; required, the empty username is refused.
func TestBuiltInRegistrationGeneratesUsername(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	input := builtInInput()
	input.Username, input.DisplayName = "", ""
	result, err := service.Register(context.Background(), input)
	if err != nil || !result.Accepted || !generatedUsername.MatchString(result.Username) ||
		result.Username[:len("builtin-alice-")] != "builtin-alice-" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	record := store.calls[0]
	if record.Username != result.Username || record.DisplayName != result.Username {
		t.Fatalf("record=%#v", record)
	}
	store.completed = map[string][32]byte{record.IdempotencyKey: record.RequestDigest}
	replay, err := service.Register(context.Background(), input)
	if err != nil || !replay.Replayed || replay.Username != result.Username || len(captcha.calls) != 1 {
		t.Fatalf("replay=%#v err=%v captcha=%d", replay, err, len(captcha.calls))
	}
	// a username given by hand is kept and not returned
	given, store2, _ := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	if result, err := given.Register(context.Background(), builtInInput()); err != nil || result.Username != "" ||
		store2.calls[0].Username != "builtin-alice" {
		t.Fatalf("given username: %#v %v", result, err)
	}
	required, store3, _ := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true, UsernameRequired: true})
	if _, err := required.Register(context.Background(), input); !errors.Is(err, ErrInvalidInput) || len(store3.calls) != 0 {
		t.Fatalf("required username left empty: %v", err)
	}
}

func TestDerivedUsername(t *testing.T) {
	key := make([]byte, 32)
	for _, item := range []struct{ email, phone, prefix string }{
		{"alice.smith+cdn@example.com", "", "alice.smithcdn-"},
		{"", "+8613812345678", "u8613812345678-"},
		{"__@example.com", "", "user-"},
		{"bob@example.com", "+8613812345678", "bob-"},
		{"abcdefghijklmnopqrstuvwxyz0123456789@example.com", "", "abcdefghijklmnopqrstuvwxyz012345-"},
	} {
		name := DerivedUsername(key, item.email, item.phone)
		if !generatedUsername.MatchString(name) || len(name) != len(item.prefix)+8 || name[:len(item.prefix)] != item.prefix {
			t.Errorf("DerivedUsername(%q,%q)=%q, want prefix %q", item.email, item.phone, name, item.prefix)
		}
		if DerivedUsername(key, item.email, item.phone) != name {
			t.Errorf("not deterministic for %q %q", item.email, item.phone)
		}
	}
	if DerivedUsername(key, "a@example.com", "") == DerivedUsername(key, "a@example.org", "") {
		t.Error("two emails with the same local part share a username")
	}
	if DerivedUsername(key, "a@example.com", "") == DerivedUsername([]byte("another-registration-digest-key-32"), "a@example.com", "") {
		t.Error("the key does not change the suffix")
	}
}

// The Turnstile flow applies the same QQ and username rules, and the
// generated username is the one the proof subject is bound to.
func TestRegisterQQAndGeneratedUsername(t *testing.T) {
	scopeID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	limiter := &registrationLimiterStub{allowed: true}
	proofs := &registrationProofStub{}
	policy := &registrationPolicyStub{settings: systemusersettings.PublicSettings{RegistrationEnabled: true, QQRequired: true}}
	service := newRegistrationPolicyTestService(t, store, limiter, proofs, policy)
	input := validRegistrationInput()
	input.ScopeID = scopeID
	if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrInvalidInput) || len(store.calls) != 0 {
		t.Fatalf("required QQ left empty: %v", err)
	}
	input.QQ, input.Username, input.DisplayName = "123456", "", ""
	result, err := service.Register(t.Context(), input)
	if err != nil || !generatedUsername.MatchString(result.Username) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	record := store.calls[0]
	want, generated := ResolveUsername(service.digestKey, policy.settings, "", input.Email, input.Phone, "")
	if !generated || record.Username != want || record.QQ != "123456" {
		t.Fatalf("record=%#v want username %q", record, want)
	}
	digest, _ := service.subjectDigest(RegisterInput{Username: want, Email: record.Email, Phone: record.Phone})
	if len(proofs.calls) == 0 || proofs.calls[0].SubjectDigest != digest {
		t.Fatal("the proof is not bound to the generated username")
	}
}
