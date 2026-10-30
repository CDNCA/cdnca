package ccadaptive

import (
	"encoding/json"
	"os"
	"testing"
)

type parityVectors struct {
	Policy          Policy `json:"policy"`
	IdentifierCases []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"identifier_cases"`
	GCRACases []struct {
		Name string `json:"name"`
		Key  struct {
			TenantID  string `json:"tenant_id"`
			SiteID    string `json:"site_id"`
			RuleID    string `json:"rule_id"`
			KeyScope  string `json:"key_scope"`
			KeyDigest string `json:"key_digest"`
			Revision  uint64 `json:"revision"`
		} `json:"key"`
		Limit Limit `json:"limit"`
		Steps []struct {
			NowMicros          int64      `json:"now_micros"`
			Cost               uint64     `json:"cost"`
			Outcome            Outcome    `json:"outcome"`
			RetryAfterMicros   int64      `json:"retry_after_micros"`
			Remaining          uint64     `json:"remaining"`
			NextEligibleMicros int64      `json:"next_eligible_micros"`
			Reason             ReasonCode `json:"reason"`
		} `json:"steps"`
	} `json:"gcra_cases"`
	AdaptiveCase struct {
		Key      ModelKey `json:"key"`
		Samples  []Sample `json:"samples"`
		Expected struct {
			RatePerSecond      uint64     `json:"rate_per_second"`
			Burst              uint64     `json:"burst"`
			ConfidencePermille uint32     `json:"confidence_permille"`
			Reason             ReasonCode `json:"reason"`
			Apply              bool       `json:"apply"`
		} `json:"expected"`
	} `json:"adaptive_case"`
	AdaptiveAutoCase struct {
		Key      ModelKey `json:"key"`
		Samples  []Sample `json:"samples"`
		Expected struct {
			RatePerSecond      uint64     `json:"rate_per_second"`
			Burst              uint64     `json:"burst"`
			ConfidencePermille uint32     `json:"confidence_permille"`
			Reason             ReasonCode `json:"reason"`
			Apply              bool       `json:"apply"`
		} `json:"expected"`
	} `json:"adaptive_auto_case"`
	AdaptiveExactIntegerCase struct {
		Config   AdaptiveConfig `json:"config"`
		Baseline Limit          `json:"baseline"`
		Key      ModelKey       `json:"key"`
		Samples  []Sample       `json:"samples"`
		Expected struct {
			RatePerSecond      uint64     `json:"rate_per_second"`
			Burst              uint64     `json:"burst"`
			ConfidencePermille uint32     `json:"confidence_permille"`
			Reason             ReasonCode `json:"reason"`
			Apply              bool       `json:"apply"`
			StateCapped        bool       `json:"state_capped"`
		} `json:"expected"`
	} `json:"adaptive_exact_integer_case"`
}

func TestGoDecisionParityVectors(t *testing.T) {
	vectors := loadParityVectors(t)
	for _, testCase := range vectors.IdentifierCases {
		t.Run("identifier-"+testCase.Name, func(t *testing.T) {
			key := NewKey(testCase.Value, "site-a", "rule-a", "scope-a", 7, nil)
			modelKey := ModelKey{TenantID: testCase.Value, SiteID: "site-a", RuleID: "rule-a", Revision: 7}
			if got := validIdentifier(testCase.Value); got != testCase.Valid {
				t.Fatalf("validIdentifier(%q) = %t, want %t", testCase.Value, got, testCase.Valid)
			}
			if got := key.valid(); got != testCase.Valid {
				t.Fatalf("Key.valid(%q) = %t, want %t", testCase.Value, got, testCase.Valid)
			}
			if got := modelKey.valid(); got != testCase.Valid {
				t.Fatalf("ModelKey.valid(%q) = %t, want %t", testCase.Value, got, testCase.Valid)
			}
		})
	}
	for _, testCase := range vectors.GCRACases {
		t.Run(testCase.Name, func(t *testing.T) {
			key, err := NewDigestKey(testCase.Key.TenantID, testCase.Key.SiteID, testCase.Key.RuleID, testCase.Key.KeyScope, testCase.Key.Revision, testCase.Key.KeyDigest)
			if err != nil {
				t.Fatal(err)
			}
			store := NewStore()
			for index, step := range testCase.Steps {
				got := store.Decide(Request{Key: key, Limit: testCase.Limit, Cost: step.Cost, NowMicros: step.NowMicros})
				if got.Outcome != step.Outcome || got.RetryAfterMicros != step.RetryAfterMicros ||
					got.Remaining != step.Remaining || got.NextEligibleMicros != step.NextEligibleMicros ||
					got.Reason != step.Reason {
					t.Fatalf("step %d = %+v, want %+v", index, got, step)
				}
			}
		})
	}

	analyzer, err := NewAnalyzer(*vectors.Policy.Adaptive)
	if err != nil {
		t.Fatal(err)
	}
	var got Suggestion
	for _, sample := range vectors.AdaptiveCase.Samples {
		got = analyzer.Observe(vectors.AdaptiveCase.Key, sample, vectors.Policy.Static)
	}
	want := vectors.AdaptiveCase.Expected
	if got.RatePerSecond != want.RatePerSecond || got.Burst != want.Burst ||
		got.ConfidencePermille != want.ConfidencePermille || got.Reason != want.Reason || got.Apply != want.Apply {
		t.Fatalf("adaptive parity = %+v, want %+v", got, want)
	}

	autoConfig := *vectors.Policy.Adaptive
	autoConfig.Mode = AdaptiveAuto
	autoConfig.AutoApproved = true
	autoAnalyzer, err := NewAnalyzer(autoConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range vectors.AdaptiveAutoCase.Samples {
		got = autoAnalyzer.Observe(vectors.AdaptiveAutoCase.Key, sample, vectors.Policy.Static)
	}
	autoWant := vectors.AdaptiveAutoCase.Expected
	if got.RatePerSecond != autoWant.RatePerSecond || got.Burst != autoWant.Burst ||
		got.ConfidencePermille != autoWant.ConfidencePermille || got.Reason != autoWant.Reason || got.Apply != autoWant.Apply {
		t.Fatalf("adaptive auto parity = %+v, want %+v", got, autoWant)
	}

	exact := vectors.AdaptiveExactIntegerCase
	exactAnalyzer, err := NewAnalyzer(exact.Config)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range exact.Samples {
		got = exactAnalyzer.Observe(exact.Key, sample, exact.Baseline)
	}
	exactWant := exact.Expected
	if got.RatePerSecond != exactWant.RatePerSecond || got.Burst != exactWant.Burst ||
		got.ConfidencePermille != exactWant.ConfidencePermille || got.Reason != exactWant.Reason ||
		got.Apply != exactWant.Apply || exactAnalyzer.groups[exact.Key].capped != exactWant.StateCapped {
		t.Fatalf("adaptive exact-integer parity = %+v state=%+v, want %+v", got, exactAnalyzer.groups[exact.Key], exactWant)
	}
}

func loadParityVectors(t *testing.T) parityVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/parity-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors parityVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}
