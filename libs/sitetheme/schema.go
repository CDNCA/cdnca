package sitetheme

import (
	"regexp"
	"strconv"
)

// FieldType is the kind of one editable website field.
type FieldType string

const (
	FieldText     FieldType = "text"
	FieldTextarea FieldType = "textarea"
	FieldRichtext FieldType = "richtext"
	FieldImage    FieldType = "image"
	FieldLink     FieldType = "link"
	FieldList     FieldType = "list"
)

const (
	// ContentSchemaMaxFields caps the top-level fields of content_schema.
	ContentSchemaMaxFields = 100
	// ContentSchemaMaxListFields caps the fields of one list item.
	ContentSchemaMaxListFields = 30
	maxFieldLength             = 20000
	maxListItems               = 200
)

// Field is one entry of content_schema: the admin console builds the
// "官网内容" form from it. A list holds items of Fields (one level only).
type Field struct {
	Key       string    `json:"key"`
	Type      FieldType `json:"type"`
	Label     I18nText  `json:"label"`
	Help      I18nText  `json:"help,omitempty"`
	Required  bool      `json:"required,omitempty"`
	MaxLength int       `json:"max_length,omitempty"` // text, textarea, richtext
	MaxItems  int       `json:"max_items,omitempty"`  // list
	Fields    []Field   `json:"fields,omitempty"`     // list only
}

var fieldKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validFieldType(t FieldType) bool {
	switch t {
	case FieldText, FieldTextarea, FieldRichtext, FieldImage, FieldLink, FieldList:
		return true
	}
	return false
}

// validateFields checks one level of content_schema; top is the root level,
// where list may appear.
func validateFields(fields []Field, field string, top bool) error {
	max := ContentSchemaMaxFields
	if !top {
		max = ContentSchemaMaxListFields
	}
	if len(fields) == 0 || len(fields) > max {
		return invalid("content_schema", field)
	}
	keys := map[string]bool{}
	for index, value := range fields {
		at := field + "[" + strconv.Itoa(index) + "]"
		switch {
		case !fieldKey.MatchString(value.Key):
			return invalid("content_key", at+".key")
		case keys[value.Key]:
			return invalid("content_key_duplicate", at+".key")
		case !validFieldType(value.Type):
			return invalid("content_type", at+".type")
		case value.Type == FieldList && !top:
			return invalid("content_nesting", at+".type")
		}
		keys[value.Key] = true
		if err := validI18n(value.Label, 64, true, at+".label"); err != nil {
			return err
		}
		if err := validI18n(value.Help, 256, false, at+".help"); err != nil {
			return err
		}
		textual := value.Type == FieldText || value.Type == FieldTextarea || value.Type == FieldRichtext
		if value.MaxLength < 0 || value.MaxLength > maxFieldLength || value.MaxLength != 0 && !textual {
			return invalid("content_max_length", at+".max_length")
		}
		if value.MaxItems < 0 || value.MaxItems > maxListItems || value.MaxItems != 0 && value.Type != FieldList {
			return invalid("content_max_items", at+".max_items")
		}
		if value.Type != FieldList {
			if value.Fields != nil {
				return invalid("content_fields", at+".fields")
			}
			continue
		}
		if err := validateFields(value.Fields, at+".fields", false); err != nil {
			return err
		}
	}
	return nil
}
