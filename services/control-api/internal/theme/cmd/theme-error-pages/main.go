// Command theme-error-pages writes a built-in theme's node default error pages
// (<category>-<status>.html) for scripts/theme-error-page-openresty-smoke.sh.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/theme"
)

func main() {
	id := flag.String("theme", theme.DefaultThemeID, "built-in theme id")
	output := flag.String("out", "", "absolute output directory")
	flag.Parse()
	if *output == "" || !filepath.IsAbs(*output) {
		fatalf("-out must be absolute")
	}
	var raw []byte
	for _, entry := range theme.BuiltinCatalog() {
		if entry.ID == *id {
			raw = entry.Raw
		}
	}
	if raw == nil {
		fatalf("unknown built-in theme %q", *id)
	}
	rendered, err := theme.Render(raw)
	if err != nil {
		fatalf("render: %v", err)
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		fatalf("create output: %v", err)
	}
	for _, page := range rendered.ErrorPages {
		name := page.Category + "-" + strconv.Itoa(page.Status) + ".html"
		if err := os.WriteFile(filepath.Join(*output, name), page.Body, 0o600); err != nil {
			fatalf("write %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(*output, "style.css"), []byte(rendered.StyleText), 0o600); err != nil {
		fatalf("write style: %v", err)
	}
	fmt.Printf("theme=%s package=%s pages=%d\n", rendered.Package.ID, rendered.PackageSHA256, len(rendered.ErrorPages))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
