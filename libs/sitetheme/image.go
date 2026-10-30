package sitetheme

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf8"
)

// ImageMaxBytes caps one embedded image (plugin illustration, auth_style
// image) and one uploaded website image.
const ImageMaxBytes = 2 << 20

// Image is a validated embedded image.
type Image struct {
	Slot, MIMEType, SHA256 string
	Body                   []byte
}

// imageTypes are the media types SniffImage accepts, in sniffing order.
var imageTypes = []string{"image/png", "image/jpeg", "image/webp", "image/x-icon", "image/svg+xml"}

// SniffImage returns the media type of an image body when it is one the
// website accepts and of the declared type, or "".
func SniffImage(declared string, body []byte) string {
	if len(body) == 0 || len(body) > ImageMaxBytes {
		return ""
	}
	switch declared {
	case "image/png":
		if bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
			return declared
		}
	case "image/jpeg":
		if len(body) >= 3 && body[0] == 0xff && body[1] == 0xd8 && body[2] == 0xff {
			return declared
		}
	case "image/webp":
		if len(body) >= 12 && string(body[:4]) == "RIFF" && string(body[8:12]) == "WEBP" {
			return declared
		}
	case "image/x-icon":
		if len(body) >= 4 && body[0] == 0 && body[1] == 0 && body[2] == 1 && body[3] == 0 {
			return declared
		}
	case "image/svg+xml":
		if SafeSVG(body) {
			return declared
		}
	}
	return ""
}

// detectImage returns the media type of an image whose type is not declared.
func detectImage(body []byte) string {
	for _, mime := range imageTypes {
		if SniffImage(mime, body) != "" {
			return mime
		}
	}
	return ""
}

// SafeSVG accepts a self-contained drawing: an <svg> root, no doctype or
// processing instructions beyond the XML declaration, no scripts, event
// handlers, foreign content, animation, or references outside the file.
func SafeSVG(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	depth, sawRoot := 0, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return sawRoot && depth == 0
		}
		if err != nil {
			return false
		}
		switch t := token.(type) {
		case xml.Directive:
			return false
		case xml.ProcInst:
			if t.Target != "xml" {
				return false
			}
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if depth == 0 && (sawRoot || name != "svg") {
				return false
			}
			sawRoot = true
			depth++
			switch name {
			case "script", "foreignobject", "iframe", "embed", "object", "audio", "video", "animate", "set",
				"animatemotion", "animatetransform", "handler", "listener":
				return false
			}
			for _, attribute := range t.Attr {
				key, value := strings.ToLower(attribute.Name.Local), strings.ToLower(strings.TrimSpace(attribute.Value))
				if strings.HasPrefix(key, "on") || strings.Contains(value, "javascript:") || strings.Contains(value, "@import") {
					return false
				}
				if (key == "href" || key == "src") && value != "" && !strings.HasPrefix(value, "#") {
					return false
				}
				if strings.Contains(value, "url(") && !onlyLocalURLs(value) {
					return false
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			text := strings.ToLower(string(t))
			if strings.Contains(text, "@import") || strings.Contains(text, "javascript:") ||
				(strings.Contains(text, "url(") && !onlyLocalURLs(text)) {
				return false
			}
		}
	}
}

func onlyLocalURLs(value string) bool {
	for rest := value; ; {
		index := strings.Index(rest, "url(")
		if index < 0 {
			return true
		}
		rest = strings.TrimLeft(rest[index+4:], " '\"")
		if !strings.HasPrefix(rest, "#") {
			return false
		}
	}
}
