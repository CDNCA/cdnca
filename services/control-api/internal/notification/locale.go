package notification

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A template's English version is the same template ID with
// the suffix .en-us instead of .zh-cn (IDs without a suffix get .en-us
// appended), same version, channel and variables. The recipient's language
// picks it; the platform default and every missing translation stay Chinese.
const (
	LocaleZhCN = "zh-CN"
	LocaleZhTW = "zh-TW"
	LocaleEnUS = "en-US"

	templateSuffixZhCN = ".zh-cn"
	templateSuffixEnUS = ".en-us"
)

// ValidLocale reports a language the console offers (users.locale CHECK).
func ValidLocale(locale string) bool {
	return locale == LocaleZhCN || locale == LocaleZhTW || locale == LocaleEnUS
}

// LocaleFromAcceptLanguage maps a request's Accept-Language to the template
// language: English when the first preference is English, otherwise "" (the
// platform default).
func LocaleFromAcceptLanguage(header string) string {
	first, _, _ := strings.Cut(header, ",")
	first, _, _ = strings.Cut(first, ";")
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "en" || strings.HasPrefix(first, "en-") {
		return LocaleEnUS
	}
	return ""
}

// LocalizedTemplateID is the template ID of the locale's translation, or
// templateID itself for Chinese (zh-TW reads the simplified template).
func LocalizedTemplateID(templateID, locale string) string {
	if locale != LocaleEnUS || strings.HasSuffix(templateID, templateSuffixEnUS) {
		return templateID
	}
	return strings.TrimSuffix(templateID, templateSuffixZhCN) + templateSuffixEnUS
}

// BaseTemplateID is the Chinese template ID a translation belongs to; it
// lets per-template settings (e.g. SMS provider template codes) mapped on
// the Chinese ID keep working for translated messages.
func BaseTemplateID(templateID string) string {
	base, translated := strings.CutSuffix(templateID, templateSuffixEnUS)
	if !translated {
		return templateID
	}
	if strings.Contains(base, ".") {
		return base + templateSuffixZhCN
	}
	return base
}

// recipientLocale is the member's chosen language, "" when unset.
func recipientLocale(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, error) {
	var locale *string
	if err := tx.QueryRow(ctx, `SELECT locale FROM users WHERE id=$1`, userID).Scan(&locale); err != nil {
		return "", fmt.Errorf("read notification recipient locale: %w", err)
	}
	if locale == nil {
		return "", nil
	}
	return *locale, nil
}

// loadLocalizedTemplate reads the locale's translation of ref and falls back
// to ref itself when there is none or its variables differ (a translation
// must render the same context as the template it replaces).
func loadLocalizedTemplate(ctx context.Context, tx pgx.Tx, ref TemplateRef, locale string) (TemplateDefinition, error) {
	definition, err := loadTemplate(ctx, tx, ref)
	if err != nil {
		return TemplateDefinition{}, err
	}
	localized := ref
	localized.ID = LocalizedTemplateID(ref.ID, locale)
	if localized.ID == ref.ID {
		return definition, nil
	}
	translation, err := loadTemplate(ctx, tx, localized)
	if errors.Is(err, ErrTemplateNotFound) || err == nil && !slices.Equal(translation.Variables, definition.Variables) {
		return definition, nil
	}
	if err != nil {
		return TemplateDefinition{}, err
	}
	return translation, nil
}

// LocalizedValue is a public context value Go code generates in both
// languages: zh for the Chinese template (and the digest, inbox and every
// other reader), en when the recipient gets the English template.
func LocalizedValue(zh, en string) ContextValue {
	return ContextValue{value: zh, en: en}
}

// localizedContexts returns contexts with each English-template channel's
// LocalizedValue swapped to its English text; other channels are unchanged.
func localizedContexts(contexts map[Channel]TemplateContext, templates map[Channel]TemplateRef) map[Channel]TemplateContext {
	localized := make(map[Channel]TemplateContext, len(contexts))
	for channel, context := range contexts {
		if !strings.HasSuffix(templates[channel].ID, templateSuffixEnUS) {
			localized[channel] = context
			continue
		}
		english := make(TemplateContext, len(context))
		for name, value := range context {
			if value.en != "" {
				value = ContextValue{value: value.en}
			}
			english[name] = value
		}
		localized[channel] = english
	}
	return localized
}

// ChineseParamPrefix marks the Chinese copy of a value in an English SMS
// message's template parameters: a native provider without an
// English template code sends the Chinese template with these.
const ChineseParamPrefix = "zh-cn:"

// smsTemplateParams are the SMS template parameters: an English template gets
// the English values plus the Chinese copies under ChineseParamPrefix.
func smsTemplateParams(context TemplateContext, ref TemplateRef) map[string]string {
	english := strings.HasSuffix(ref.ID, templateSuffixEnUS)
	params := templateParams(context)
	if !english || params == nil {
		return params
	}
	for name, value := range context {
		if value.en != "" {
			params[name] = value.en
			params[ChineseParamPrefix+name] = value.value
		}
	}
	return params
}

// ChineseTemplateParams returns params with each value replaced by its
// Chinese copy when there is one.
func ChineseTemplateParams(params map[string]string) map[string]string {
	chinese := make(map[string]string, len(params))
	for name, value := range params {
		if _, copied := strings.CutPrefix(name, ChineseParamPrefix); !copied {
			chinese[name] = value
		}
	}
	for name, value := range params {
		if original, copied := strings.CutPrefix(name, ChineseParamPrefix); copied {
			chinese[original] = value
		}
	}
	return chinese
}
