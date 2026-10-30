package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
)

func main() {
	output := flag.String("out", "", "owner-only output directory")
	version := flag.String("version", "smoke-v1", "policy version")
	revision := flag.Uint64("revision", 1, "policy revision")
	variant := flag.String("variant", "v1", "response marker")
	invalidHash := flag.Bool("invalid-hash", false, "inject an invalid resource digest")
	themePages := flag.String("theme-pages", "", "directory of theme default pages (<category>-<status>.html); replaces the smoke rules")
	flag.Parse()
	if *output == "" || !filepath.IsAbs(*output) {
		fatalf("-out must be absolute")
	}

	policy := smokePolicy(*version, *revision, *variant)
	if *themePages != "" {
		policy = themePolicy(*version, *revision, *themePages)
	}
	if *invalidHash {
		policy.Global.Rules[0].Resource.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	artifact, err := errorpage.Compile(policy, "")
	if err != nil {
		fatalf("compile policy: %v", err)
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		fatalf("create output: %v", err)
	}
	if err := os.Chmod(*output, 0o700); err != nil {
		fatalf("secure output: %v", err)
	}
	for name, content := range map[string][]byte{
		"policy.json": artifact.CanonicalJSON,
		"policy.lua":  artifact.RuntimeLua,
	} {
		path := filepath.Join(*output, name)
		if err := os.WriteFile(path, content, 0o400); err != nil {
			fatalf("write %s: %v", name, err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			fatalf("secure %s: %v", name, err)
		}
	}
	if err := os.Chmod(*output, 0o500); err != nil {
		fatalf("seal output: %v", err)
	}
	fmt.Printf("version=%s revision=%d digest=%s bindings=%d resources=%d\n", artifact.Version, artifact.Revision, artifact.Digest, artifact.BindingCount, artifact.ResourceCount)
}

func smokePolicy(version string, revision uint64, variant string) errorpage.Policy {
	return errorpage.Policy{
		Schema: errorpage.SchemaV1, Version: version, Revision: revision,
		Global: errorpage.Scope{Rules: []errorpage.Rule{
			rule("origin-default", errorpage.CategoryOriginResponse, statusRange(400, 599), "text/plain", "global origin fallback "+variant+"\n"),
			rule("edge-403-global", errorpage.CategoryEdgeRoute, statusCodes(403), "text/plain", "global edge forbidden "+variant+"\n"),
			rule("edge-404-global", errorpage.CategoryEdgeRoute, statusCodes(404), "text/plain", "global edge missing "+variant+"\n"),
			rule("edge-500-global", errorpage.CategoryEdgeRoute, statusCodes(500), "text/plain", "global edge failure "+variant+"\n"),
			rule("connect-default", errorpage.CategoryEdgeConnect, statusRange(502, 504), "text/plain", "global connection failure "+variant+"\n"),
			rule("no-host", errorpage.CategoryNoHost, statusCodes(400), "text/plain", "host header required\n"),
			rule("unknown-site", errorpage.CategoryUnknownSite, statusCodes(404), "application/json", "{\"error\":\"unknown_site\"}\n"),
		}},
		Sites: []errorpage.SiteScope{{SiteKey: "site-a", Rules: []errorpage.Rule{
			rule("origin-403", errorpage.CategoryOriginResponse, statusCodes(403), "text/plain", "$request_uri <script>alert(1)</script> "+variant+"\n"),
			rule("origin-404", errorpage.CategoryOriginResponse, statusCodes(404), "text/html", "<!doctype html><html><head><title>Missing</title></head><body><h1>origin missing "+variant+"</h1></body></html>\n"),
			rule("origin-500", errorpage.CategoryOriginResponse, statusCodes(500), "application/json", "{\"error\":\"origin_failure\",\"variant\":\""+variant+"\"}\n"),
			rule("origin-502", errorpage.CategoryOriginResponse, statusCodes(502), "text/plain", "origin returned 502 "+variant+"\n"),
			rule("edge-403", errorpage.CategoryEdgeRoute, statusCodes(403), "text/plain", "edge forbidden "+variant+"\n"),
			rule("edge-404", errorpage.CategoryEdgeRoute, statusCodes(404), "text/html", "<!doctype html><title>Edge missing</title><h1>edge missing "+variant+"</h1>\n"),
			rule("edge-500", errorpage.CategoryEdgeRoute, statusCodes(500), "application/json", "{\"error\":\"edge_failure\",\"variant\":\""+variant+"\"}\n"),
			rule("connect-502", errorpage.CategoryEdgeConnect, statusCodes(502), "text/plain", "edge connection failed "+variant+"\n"),
		}}},
	}
}

// themePolicy publishes theme-rendered pages as global rules, as the control
// plane does for categories no platform rule covers (ADR 0007 §7.3).
func themePolicy(version string, revision uint64, directory string) errorpage.Policy {
	policy := errorpage.Policy{Schema: errorpage.SchemaV1, Version: version, Revision: revision}
	for _, page := range []struct {
		category errorpage.Category
		status   int
	}{
		{errorpage.CategoryEdgeConnect, 502}, {errorpage.CategoryEdgeConnect, 503}, {errorpage.CategoryEdgeConnect, 504},
		{errorpage.CategoryNoHost, 400}, {errorpage.CategoryUnknownSite, 404},
	} {
		name := fmt.Sprintf("%s-%d.html", page.category, page.status)
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			fatalf("read %s: %v", name, err)
		}
		policy.Global.Rules = append(policy.Global.Rules,
			rule(fmt.Sprintf("theme.%s.%d", page.category, page.status), page.category, statusCodes(page.status), "text/html", string(body)))
	}
	return policy
}

func rule(id string, category errorpage.Category, match errorpage.StatusMatch, mimeType, body string) errorpage.Rule {
	inline := body
	digest := sha256.Sum256([]byte(body))
	return errorpage.Rule{
		ID: id, Category: category, Match: match,
		Resource: errorpage.Resource{
			MIMEType: mimeType, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), Inline: &inline,
		},
	}
}

func statusCodes(codes ...int) errorpage.StatusMatch {
	return errorpage.StatusMatch{Codes: codes}
}

func statusRange(from, to int) errorpage.StatusMatch {
	return errorpage.StatusMatch{Ranges: []errorpage.StatusRange{{From: from, To: to}}}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
