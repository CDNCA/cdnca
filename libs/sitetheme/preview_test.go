package sitetheme

import (
	"strings"
	"testing"
)

const webpBody = "RIFF\x00\x00\x00\x00WEBPVP8 rest"

func TestPreviewV2(t *testing.T) {
	pkg := fixtureV2()
	pkg["preview"] = b64(webpBody)
	theme, err := Parse(encode(t, pkg), thirdParty())
	if err != nil {
		t.Fatalf("v2 with preview rejected: %v", err)
	}
	if theme.Preview == nil || theme.Preview.Slot != PreviewSlot || theme.Preview.MIMEType != "image/webp" ||
		theme.Preview.SHA256 != sum(webpBody) || string(theme.Preview.Body) != webpBody {
		t.Fatalf("preview: %+v", theme.Preview)
	}
	if theme, err := Parse(encode(t, fixtureV2()), thirdParty()); err != nil || theme.Preview != nil {
		t.Fatalf("no preview: %+v %v", theme, err)
	}
	for name, value := range map[string]string{
		"svg":        b64(svgBody),
		"ico":        b64("\x00\x00\x01\x00rest"),
		"not image":  b64("hello"),
		"empty":      "",
		"not base64": "!!!",
		"padding":    "aGVsbG8",
	} {
		pkg := fixtureV2()
		pkg["preview"] = value
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, "preview")
	}
	pkg = fixtureV2()
	pkg["preview"] = b64(pngBody + strings.Repeat("x", PreviewMaxBytes))
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "too large", err, "preview_size")
	pkg = fixtureV2()
	pkg["auth_style"].(map[string]any)["images"] = map[string]any{PreviewSlot: b64(pngBody)}
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "auth_style slot preview reserved", err, "image_slot")
	pkg = fixtureV2()
	pkg["preview"] = 1
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "not a string", err, "package_json")
}

func TestExtractPreview(t *testing.T) {
	v2 := fixtureV2()
	v2["preview"] = b64(webpBody)
	v1 := v1Package()
	v1["images"].(map[string]any)[PreviewSlot] = map[string]any{"mime_type": "image/png", "body_base64": b64(pngBody)}
	for name, c := range map[string]struct {
		pkg  map[string]any
		mime string
	}{"v2": {v2, "image/webp"}, "v1": {v1, "image/png"}} {
		image, err := ExtractPreview(encode(t, c.pkg))
		if err != nil || image == nil || image.MIMEType != c.mime {
			t.Fatalf("%s: %+v %v", name, image, err)
		}
	}
	for name, pkg := range map[string]map[string]any{"v2 none": fixtureV2(), "v1 none": v1Package()} {
		if image, err := ExtractPreview(encode(t, pkg)); image != nil || err != nil {
			t.Fatalf("%s: %+v %v", name, image, err)
		}
	}
	bad := fixtureV2()
	bad["preview"] = b64(svgBody)
	_, err := ExtractPreview(encode(t, bad))
	expectCode(t, "svg", err, "preview")
	bad["preview"] = b64(pngBody + strings.Repeat("x", PreviewMaxBytes))
	_, err = ExtractPreview(encode(t, bad))
	expectCode(t, "big", err, "preview_size")
	bad = v1Package()
	bad["images"].(map[string]any)[PreviewSlot] = map[string]any{"mime_type": "image/jpeg", "body_base64": b64(pngBody)}
	_, err = ExtractPreview(encode(t, bad))
	expectCode(t, "v1 mismatch", err, "preview")
	_, err = ExtractPreview([]byte(`{"schema":"cdnca.theme/v1"}`))
	expectCode(t, "console theme", err, "schema")
	_, err = ExtractPreview([]byte(`not json`))
	expectCode(t, "garbage", err, "package_json")
}

func TestPreviewV1(t *testing.T) {
	pkg := v1Package()
	pkg["images"].(map[string]any)[PreviewSlot] = map[string]any{"mime_type": "image/png", "body_base64": b64(pngBody)}
	theme, err := Parse(encode(t, pkg), thirdParty())
	if err != nil {
		t.Fatalf("v1 with preview rejected: %v", err)
	}
	if theme.Preview == nil || theme.Preview.MIMEType != "image/png" || theme.Preview.SHA256 != sum(pngBody) {
		t.Fatalf("preview: %+v", theme.Preview)
	}
	if _, images, err := ParseV1(encode(t, pkg)); err != nil || len(images) != 2 || V1Preview(images) == nil {
		t.Fatalf("ParseV1 images: %d %v", len(images), err)
	}
	for name, image := range map[string]map[string]any{
		"svg":      {"mime_type": "image/svg+xml", "body_base64": b64(svgBody)},
		"mismatch": {"mime_type": "image/jpeg", "body_base64": b64(pngBody)},
		"garbage":  {"mime_type": "image/png", "body_base64": b64("x")},
	} {
		pkg := v1Package()
		pkg["images"].(map[string]any)[PreviewSlot] = image
		_, err := Parse(encode(t, pkg), thirdParty())
		expectCode(t, name, err, "preview")
	}
	pkg = v1Package()
	pkg["images"].(map[string]any)[PreviewSlot] = map[string]any{"mime_type": "image/png",
		"body_base64": b64(pngBody + strings.Repeat("x", PreviewMaxBytes))}
	_, err = Parse(encode(t, pkg), thirdParty())
	expectCode(t, "too large", err, "preview_size")
	if theme, err := Parse(encode(t, v1Package()), thirdParty()); err != nil || theme.Preview != nil {
		t.Fatalf("no preview: %+v %v", theme, err)
	}
}
