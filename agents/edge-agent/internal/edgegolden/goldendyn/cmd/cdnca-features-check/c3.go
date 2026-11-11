package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	extHost   = "ext.feat.test"
	clickHost = "click.feat.test"
	verifyURL = "/.cdnca/challenge/verify"
	maxFail   = 3
)

var nonceRe = regexp.MustCompile(`name="nonce" value="([^"]*)"`)

// challengeNode is shared by the c3 and install parts: one policy with an
// external rule (provider unreachable: nothing listens on the agent's
// verifier port) and a click rule, installed by the production installer.
var challengeNode *node

func ensureChallengeNode() *node {
	if challengeNode != nil {
		return challengeNode
	}
	ext, click := baseSite(11, extHost), baseSite(12, clickHost)
	ref := &edgesite.Ref{Kind: edgesite.RefChallenge, ID: policyID, Revision: policyRev}
	ext.Security.Challenge, click.Security.Challenge = ref, ref
	root := *state + "/challenge"
	install := func() error {
		if err := os.MkdirAll(filepath.Join(root, "challenge", "keys"), 0o700); err != nil {
			return err
		}
		installer, err := challenge.NewArtifactInstaller(root)
		if err != nil {
			return err
		}
		binding := challenge.ArtifactBinding{
			EventID: "0f3a0000-0000-7000-8000-000000000011", DeploymentID: "0f3a0000-0000-7000-8000-000000000012",
			Attempt: 1, ConfigVersionID: "0f3a0000-0000-7000-8000-000000000013", ArtifactID: "0f3a0000-0000-7000-8000-000000000014",
			RecipientKeyID: "x25519:" + strings.Repeat("a", 64), PolicyID: policyID, TenantID: tenant, PolicyVersion: policyRev}
		rule := func(id, site, host string, mode challenge.Mode) challenge.Rule {
			return challenge.Rule{RuleID: id, Priority: 10, TenantID: tenant, SiteID: site, Host: host, Mode: mode,
				ChallengeTTLSeconds: 120, PassTTLSeconds: 300, ClockSkewSeconds: 10, AttemptsPerNonce: 1,
				FailureWindowSeconds: 60, MaxFailuresPerWindow: maxFail, IPBinding: challenge.IPBindingExact, BindUserAgent: true}
		}
		external := rule(policyID, siteID(11), extHost, challenge.ModeExternal)
		external.ExternalProvider = &challenge.ExternalProviderConfig{Provider: "turnstile", AppID: "feat-app", Unavailable: "builtin"}
		document := challenge.ArtifactDocument{SchemaVersion: challenge.ArtifactSchemaVersion,
			Activation: challenge.ArtifactActivation{SchemaVersion: challenge.ActivationSchemaVersion, EventID: binding.EventID,
				DeploymentID: binding.DeploymentID, Attempt: 1, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
				RecipientKeyID: binding.RecipientKeyID, PolicyID: policyID, TenantID: tenant, PolicyVersion: policyRev},
			Policy: challenge.Policy{SchemaVersion: challenge.SchemaVersion, PolicyVersion: policyRev, Algorithm: challenge.AlgorithmHMACSHA256,
				CookieName: "__Host-cdnca_challenge", TrustedProxies: []string{}, BypassRoutes: []challenge.BypassRoute{},
				CurrentKey: challenge.KeyRef{KeyID: "key-1"},
				Rules: []challenge.Rule{external, rule("0f3a0000-0000-4000-8000-0000000000a2", siteID(12), clickHost, challenge.ModeClick)}},
			Keys: []challenge.ArtifactKey{{KeyID: "key-1", Secret: []byte(strings.Repeat("k", 48))}},
			ExternalCredentials: []challenge.ArtifactExternalCredential{{TenantID: tenant, SiteID: siteID(11), Provider: "turnstile",
				AppID: "feat-app", Secret: []byte(strings.Repeat("s", 32)), Environment: challenge.ExternalSandbox}}}
		raw, err := json.Marshal(document)
		if err != nil {
			return err
		}
		_, err = installer.InstallJSON(raw, binding)
		return err
	}
	answer := fmt.Sprintf(`  server {
    listen %d;
    location = /answer {
      content_by_lua_block {
        local cjson, dict, best = require("cjson.safe"), ngx.shared.%s, nil
        for _, key in ipairs(dict:get_keys(0)) do
          if key:find(":pending:", 1, true) then
            local s = cjson.decode(dict:get(key) or "")
            if s and (not best or s.issued_at >= best.issued_at) then best = s end
          end
        end
        if not best then ngx.exit(404) end
        ngx.say(best.answer, " ", best.pow)
      }
    }
  }
`, answerPort, edgeskeleton.ChallengeStateDictionary)
	n, err := start(root, []edgesite.Site{ext, click}, false, edgeskeleton.ChallengesFromSites([]edgesite.Site{ext, click}), install, answer)
	if err != nil {
		check("CHALLENGE-start", false, "%v", err)
		os.Exit(1)
	}
	challengeNode = n
	return n
}

func nonceOf(page string) string {
	if m := nonceRe.FindStringSubmatch(page); m != nil {
		return m[1]
	}
	return ""
}

func form(nonce, response, pow string) string {
	body := "nonce=" + nonce + "&response=" + response
	if pow != "" {
		body += "&pow=" + pow
	}
	return body
}

func post(v *visitor, host, body string) reply {
	time.Sleep(600 * time.Millisecond)
	return v.send("POST", host, verifyURL, body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

// fallbackNonce: ask the external rule, report the widget as unavailable,
// return the built-in click page's nonce.
func fallbackNonce(v *visitor) (string, reply) {
	first := v.get(extHost, "/p", nil)
	r := post(v, extHost, form(nonceOf(first.body), "widget_unavailable", ""))
	return nonceOf(r.body), r
}

func c3Run() {
	n := ensureChallengeNode()
	v := newVisitor("127.0.0.31")
	first := v.get(extHost, "/p", nil)
	check("external-external-page", strings.Contains(first.body, "external-widget") && nonceOf(first.body) != "", "status=%d", first.status)
	// unavailable more often than the failure limit: never a refusal
	ok := true
	for i := 0; i < maxFail+2; i++ {
		next, r := fallbackNonce(v)
		if next == "" || strings.Contains(r.body, "external-widget") || r.status == 403 || r.status == 429 {
			ok = false
			check("external-unavailable-fallback", false, "round %d status=%d", i, r.status)
			break
		}
	}
	check("external-unavailable-fallback", ok, "%d widget_unavailable answers each got the built-in page", maxFail+2)
	// a real proof while the verifier is unreachable (connection refused)
	page := v.get(extHost, "/p", nil)
	r := post(v, extHost, form(nonceOf(page.body), "tok-abc", ""))
	check("external-verifier-down-fallback", nonceOf(r.body) != "" && !strings.Contains(r.body, "external-widget") && r.status != 403 && r.status != 429, "status=%d", r.status)
	// wrong answers on the fallback do count: the last one reaches the limit
	codes := []int{}
	for i := 0; i < maxFail; i++ {
		nonce, _ := fallbackNonce(v)
		codes = append(codes, post(v, extHost, form(nonce, "wrong", "1")).status)
	}
	check("external-wrong-counts", fmt.Sprint(codes) == fmt.Sprint([]int{403, 403, 429}), "statuses=%v (the unavailable ones before did not count)", codes)
	// a visitor solving the built-in page gets through
	time.Sleep(1100 * time.Millisecond) // /answer picks the newest pending state by whole seconds
	w := newVisitor("127.0.0.32")
	nonce, _ := fallbackNonce(w)
	pair := strings.Fields(answerLine())
	if len(pair) != 2 || nonce == "" {
		check("external-solve", false, "answer %v nonce=%q", pair, nonce)
	} else {
		done := post(w, extHost, form(nonce, pair[0], pair[1]))
		check("external-solve", done.status/100 == 3 && w.get(extHost, "/p", nil).body == "origin-ok\n", "verify status=%d", done.status)
	}
	if line := unexpectedError(n.errorLog()); line != "" {
		check("external-error-log", false, "%s", line)
	}
}

func answerLine() string {
	v := newVisitor("127.0.0.1")
	request, _ := v.http.Get(fmt.Sprintf("http://127.0.0.1:%d/answer", answerPort))
	if request == nil {
		return ""
	}
	defer request.Body.Close()
	buf := make([]byte, 256)
	k, _ := request.Body.Read(buf)
	return strings.TrimSpace(string(buf[:k]))
}

// installRun: the policy the production installer wrote is what the node
// preloaded: the click host intercepts, a solved visitor passes.
func installRun() {
	n := ensureChallengeNode()
	if _, err := os.Stat(filepath.Join(n.root, "challenge", "policies", policyID, "versions")); err != nil {
		check("INSTALL-files", false, "%v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	v := newVisitor("127.0.0.33")
	first := v.get(clickHost, "/p", nil)
	check("INSTALL-intercept", first.body != "origin-ok\n" && nonceOf(first.body) != "", "status=%d", first.status)
	pair := strings.Fields(answerLine())
	if len(pair) != 2 {
		check("INSTALL-solve", false, "answer %v", pair)
		return
	}
	done := post(v, clickHost, form(nonceOf(first.body), pair[0], pair[1]))
	check("INSTALL-verify", done.status/100 == 3, "status=%d", done.status)
	check("INSTALL-pass", v.get(clickHost, "/p", nil).body == "origin-ok\n", "solved visitor reaches the origin")
	other := newVisitor("127.0.0.34")
	check("INSTALL-others-stay-out", other.get(clickHost, "/p", nil).body != "origin-ok\n", "unsolved visitor still intercepted")
	if line := unexpectedError(n.errorLog()); line != "" {
		check("INSTALL-error-log", false, "%s", line)
	}
}

// unexpectedError: the first [error] line other than the refused connection
// to the agent's verifier (the provider is unreachable on purpose).
func unexpectedError(log string) string {
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "[error]") && !strings.Contains(line, "connect() failed (111") {
			return line
		}
	}
	return ""
}
