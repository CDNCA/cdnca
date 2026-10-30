package errorpage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
	"golang.org/x/net/html"
	"golang.org/x/sys/unix"
)

var forbiddenTemplateMarkers = [][]byte{
	[]byte("{{"), []byte("}}"), []byte("{%"), []byte("%}"),
	[]byte("<%"), []byte("%>"), []byte("${"), []byte("<!--#"),
}

func loadResource(resource Resource, resourceRoot string) (CompiledResource, error) {
	if resource.MIMEType != "text/html" && resource.MIMEType != "text/plain" && resource.MIMEType != "application/json" {
		return CompiledResource{}, invalidPolicy("unsupported MIME type %q", resource.MIMEType)
	}
	if resource.Size < 1 || resource.Size > MaxResourceBytes || !validDigest(resource.SHA256) {
		return CompiledResource{}, invalidPolicy("resource metadata is invalid")
	}
	if (resource.Inline == nil) == (resource.File == "") {
		return CompiledResource{}, invalidPolicy("resource must contain exactly one of inline or file")
	}

	var body []byte
	var err error
	if resource.Inline != nil {
		body = []byte(*resource.Inline)
	} else {
		body, err = readOwnerOnlyFile(resourceRoot, resource.File)
		if err != nil {
			return CompiledResource{}, err
		}
	}
	if len(body) != int(resource.Size) || len(body) > MaxResourceBytes || len(body) == 0 {
		return CompiledResource{}, invalidPolicy("resource size does not match metadata")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != resource.SHA256 {
		return CompiledResource{}, invalidPolicy("resource digest does not match metadata")
	}
	styleHash, err := validateStaticBody(resource.MIMEType, body)
	if err != nil {
		return CompiledResource{}, err
	}
	return CompiledResource{
		MIMEType:  resource.MIMEType,
		Size:      resource.Size,
		SHA256:    resource.SHA256,
		Body:      append([]byte(nil), body...),
		StyleHash: styleHash,
	}, nil
}

// validateStaticBody returns the CSP hash of an HTML page's theme style, or "".
func validateStaticBody(mimeType string, body []byte) (string, error) {
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return "", invalidPolicy("resource must be non-NUL UTF-8")
	}
	for _, marker := range forbiddenTemplateMarkers {
		if bytes.Contains(body, marker) {
			return "", invalidPolicy("resource contains a forbidden template or include marker")
		}
	}
	if mimeType == "application/json" && !json.Valid(body) {
		return "", invalidPolicy("JSON resource is invalid")
	}
	if mimeType == "text/html" {
		style, err := validateStaticHTML(body)
		if err != nil || style == "" {
			return "", err
		}
		return errorpagestyle.SourceHash(style), nil
	}
	return "", nil
}

// validateStaticHTML returns the text of the page's single theme <style>
// (ADR 0007 §7.2), or "" when it has none. That style must be in the
// errorpagestyle canonical grammar and sit directly in <head>; class
// attributes may only name classes it declares.
func validateStaticHTML(body []byte) (string, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	var style string
	var styles, headDepth int
	var classes []string
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			if tokenizer.Err() != io.EOF {
				return "", invalidPolicy("HTML resource cannot be parsed")
			}
			if len(classes) == 0 {
				return style, nil
			}
			sheet, err := errorpagestyle.Parse(style)
			if err != nil {
				return "", invalidPolicy("HTML resource class needs the page's theme style")
			}
			declared := sheet.Classes()
			for _, class := range classes {
				if errorpagestyle.CheckClassAttribute(class, declared) != nil {
					return "", invalidPolicy("HTML resource names an undeclared class")
				}
			}
			return style, nil
		case html.EndTagToken:
			if name, _ := tokenizer.TagName(); strings.EqualFold(string(name), "head") {
				headDepth = 0
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(token.Data)
			if tag == "head" {
				headDepth = 1
			}
			if tag == "style" {
				styles++
				if styles > 1 || headDepth != 1 || len(token.Attr) != 0 {
					return "", invalidPolicy("HTML resource style must be one attribute-free element in head")
				}
				if tokenizer.Next() != html.TextToken {
					return "", invalidPolicy("HTML resource style is empty")
				}
				style = string(tokenizer.Text())
				if _, err := errorpagestyle.Parse(style); err != nil {
					return "", invalidPolicy("HTML resource style is outside the theme grammar")
				}
				if tokenizer.Next() != html.EndTagToken {
					return "", invalidPolicy("HTML resource style is not closed")
				}
				continue
			}
			switch tag {
			case "script", "iframe", "object", "embed", "link", "base", "meta", "form", "input", "button", "template", "svg", "math":
				return "", invalidPolicy("HTML resource contains active element %q", tag)
			}
			for _, attribute := range token.Attr {
				name := strings.ToLower(attribute.Key)
				if name == "class" {
					classes = append(classes, attribute.Val)
					continue
				}
				if strings.HasPrefix(name, "on") {
					return "", invalidPolicy("HTML resource contains an event handler")
				}
				switch name {
				case "src", "srcset", "href", "action", "formaction", "data", "poster", "ping", "background":
					return "", invalidPolicy("HTML resource contains an external reference")
				case "style":
					value := strings.ToLower(attribute.Val)
					if strings.Contains(value, "url(") || strings.Contains(value, "@import") || strings.Contains(value, "expression(") {
						return "", invalidPolicy("HTML resource contains an external or executable style")
					}
				}
			}
		case html.CommentToken:
			if strings.HasPrefix(strings.TrimSpace(tokenizer.Token().Data), "#") {
				return "", invalidPolicy("HTML resource contains SSI")
			}
		}
	}
}

func readOwnerOnlyFile(root, relative string) ([]byte, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\x00\r\n") {
		return nil, unsafeResource("resource root must be an absolute clean path")
	}
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.Contains(relative, "\\") || strings.ContainsRune(relative, 0) {
		return nil, unsafeResource("resource path must be clean and relative")
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, unsafeResource("resource path contains traversal")
		}
	}

	current, err := openDirectoryWithoutSymlinkAncestors(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(current) }()
	if err := validateDirectoryFD(current); err != nil {
		return nil, err
	}

	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, unsafeResource("resource directory cannot be opened")
		}
		if err := validateDirectoryFD(next); err != nil {
			unix.Close(next)
			return nil, err
		}
		unix.Close(current)
		current = next
	}

	fileFD, err := unix.Openat(current, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, unsafeResource("resource file cannot be opened")
	}
	file := os.NewFile(uintptr(fileFD), relative)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil {
		return nil, unsafeResource("resource file cannot be inspected")
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) ||
		os.FileMode(stat.Mode)&os.ModePerm != 0o400 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, unsafeResource("resource file must be owner-owned mode 0400 with one hard link")
	}
	if stat.Size < 1 || stat.Size > MaxResourceBytes {
		return nil, unsafeResource("resource file size is outside the allowed range")
	}
	body, err := io.ReadAll(io.LimitReader(file, MaxResourceBytes+1))
	if err != nil || len(body) != int(stat.Size) {
		return nil, unsafeResource("resource file could not be read completely")
	}
	return body, nil
}

func openDirectoryWithoutSymlinkAncestors(root string) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	current, err := unix.Open("/", flags, 0)
	if err != nil {
		return -1, unsafeResource("resource root cannot be opened")
	}
	relative := strings.TrimPrefix(filepath.ToSlash(root), "/")
	if relative == "" {
		return current, nil
	}
	for _, part := range strings.Split(relative, "/") {
		next, openErr := unix.Openat(current, part, flags, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, unsafeResource("resource root cannot be opened")
		}
		current = next
	}
	return current, nil
}

func validateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return unsafeResource("resource directory cannot be inspected")
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) ||
		os.FileMode(stat.Mode)&os.ModePerm != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		return unsafeResource("resource directories must be owner-owned mode 0700")
	}
	return nil
}

func unsafeResource(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsafeResource, fmt.Sprintf(format, arguments...))
}
