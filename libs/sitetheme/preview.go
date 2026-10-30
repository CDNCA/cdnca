package sitetheme

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// The preview image (预览图) of a theme: a screenshot of the website home
// page (or of the console, for a user-only theme) that the market and the
// control plane show on the theme card. Optional in both schemas:
//
//	v1  images.preview {mime_type, body_base64}
//	v2  preview "<base64>"
//
// Only raster images (png, jpeg, webp), sniffed from the content, at most
// PreviewMaxBytes; 1200×750 is the suggested size.
const (
	PreviewSlot     = "preview"
	PreviewMaxBytes = 512 << 10
)

// previewTypes are the media types a preview may have.
var previewTypes = []string{"image/png", "image/jpeg", "image/webp"}

// PreviewType returns the media type of a preview image as the rules accept
// it (png, jpeg or webp sniffed from the bytes, at most PreviewMaxBytes), or
// "". Proxies use it to re-check an image they relay.
func PreviewType(body []byte) string {
	if len(body) > PreviewMaxBytes {
		return ""
	}
	return previewType(body)
}

// previewType returns the sniffed media type of a preview body, or "".
func previewType(body []byte) string {
	for _, mime := range previewTypes {
		if SniffImage(mime, body) != "" {
			return mime
		}
	}
	return ""
}

// checkPreview validates a decoded preview body; declared is the v1
// mime_type ("" for v2, where the type is only sniffed).
func checkPreview(body []byte, declared, field string) (*Image, error) {
	if len(body) > PreviewMaxBytes {
		return nil, invalid("preview_size", field)
	}
	mime := previewType(body)
	if mime == "" || declared != "" && declared != mime {
		return nil, invalid("preview", field)
	}
	sum := sha256.Sum256(body)
	return &Image{Slot: PreviewSlot, MIMEType: mime, SHA256: hex.EncodeToString(sum[:]), Body: body}, nil
}

// parsePreview decodes and validates the v2 preview field.
func parsePreview(encoded string) (*Image, error) {
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(body) == 0 {
		return nil, invalid("preview", "preview")
	}
	return checkPreview(body, "", "preview")
}

// ExtractPreview takes the preview out of a stored package of either schema
// (v2 top-level preview, v1 images.preview) and validates it exactly as Parse
// does, without validating the rest of the package. It returns nil, nil when
// the package carries no preview, and an *Error when it carries an invalid one
// or is not a website theme package.
func ExtractPreview(raw []byte) (*Image, error) {
	if err := checkEnvelope(raw); err != nil {
		return nil, err
	}
	var head struct {
		Schema  string                 `json:"schema"`
		Preview *string                `json:"preview"`
		Images  map[string]*ThemeImage `json:"images"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return nil, invalid("package_json", "")
	}
	switch head.Schema {
	case SchemaV2:
		if head.Preview == nil {
			return nil, nil
		}
		return parsePreview(*head.Preview)
	case SchemaV1:
		image := head.Images[PreviewSlot]
		if image == nil {
			return nil, nil
		}
		field := "images." + PreviewSlot
		body, err := base64.StdEncoding.Strict().DecodeString(image.BodyBase64)
		if err != nil || len(body) == 0 {
			return nil, invalid("preview", field)
		}
		return checkPreview(body, image.MIMEType, field)
	}
	return nil, invalid("schema", "schema")
}

// V1Preview returns the validated preview of a v1 package's images, or nil.
func V1Preview(images []Image) *Image {
	for index := range images {
		if images[index].Slot == PreviewSlot {
			return &images[index]
		}
	}
	return nil
}
