package migrations

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Migration 704: every seeded template's current version gets an English copy named .en-us with the
// same version and channel; variables are copied from the Chinese row. The English text must use exactly the
// variables and template actions of the Chinese text it replaces, and English SMS stay within one segment of
// static text. Down refuses once an English template was used and drops users.locale.
func TestNotificationTemplatesEN704Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("704_notification_templates_en.up.sql")
	down := read("704_notification_templates_en.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 703", "(SELECT max(version) FROM schema_migrations) <> 703",
		"WHERE version=703 AND", "migration_id='703_site_origin_pool_site_revision'", "ERRCODE='P7040'",
		"ALTER TABLE users ADD COLUMN locale text CHECK (locale IN ('zh-CN', 'zh-TW', 'en-US'));",
		"source.variables, clock_timestamp()",
		"ON source.template_id = translation.source_id AND source.version = translation.version",
		"AND source.channel = translation.channel) <> 224 THEN",
		"ON CONFLICT (template_id, version, channel) DO NOTHING\n    RETURNING template_id, version, channel", "DROP TABLE notification_templates_en_704;",
		"CREATE TABLE notification_templates_seed_704 (", "INSERT INTO notification_templates_seed_704 (template_id, version, channel)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("704 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 704", "migration_id='704_notification_templates_en'",
		"EXISTS (SELECT 1 FROM notification_outbox outbox JOIN notification_templates_seed_704 seed",
		"ON seed.template_id = outbox.template_id AND seed.version = outbox.template_version\n        AND seed.channel = outbox.channel) THEN", "ERRCODE='P7041'",
		"DELETE FROM notification_templates template USING notification_templates_seed_704 seed",
		"DROP TABLE notification_templates_seed_704;",
		"ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;",
		"ALTER TABLE users DROP COLUMN locale;",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("704 down missing %q", fragment)
		}
	}

	rows := englishTemplateRows704(t, up)
	if len(rows) != 224 {
		t.Fatalf("704 has %d English rows, want 224", len(rows))
	}
	chinese := seededChineseTemplates704(t)
	action := regexp.MustCompile(`\{\{(.*?)\}\}`)
	variable := regexp.MustCompile(`\.([a-z][a-z0-9_]*)`)
	actions := func(text string) (names, controls []string) {
		for _, match := range action.FindAllStringSubmatch(text, -1) {
			for _, name := range variable.FindAllStringSubmatch(match[1], -1) {
				if !slices.Contains(names, name[1]) {
					names = append(names, name[1])
				}
			}
			if word := strings.Fields(match[1]); len(word) > 0 && slices.Contains([]string{"if", "else", "end"}, word[0]) {
				controls = append(controls, strings.TrimSpace(match[1]))
			}
		}
		slices.Sort(names)
		slices.Sort(controls)
		return names, controls
	}
	for _, row := range rows {
		key := row.source + "/" + row.version + "/" + row.channel
		source, ok := chinese[key]
		if !ok {
			t.Errorf("704 row %s has no seeded Chinese template", key)
			continue
		}
		wantID := strings.TrimSuffix(row.source, ".zh-cn") + ".en-us"
		if row.id != wantID {
			t.Errorf("704 row %s is named %s, want %s", key, row.id, wantID)
		}
		zhNames, zhControls := actions(source)
		enNames, enControls := actions(row.subject + row.body)
		if !slices.Equal(zhNames, enNames) || !slices.Equal(zhControls, enControls) {
			t.Errorf("704 %s placeholders %v %v, Chinese %v %v", key, enNames, enControls, zhNames, zhControls)
		}
		if row.channel == "sms" {
			for _, branch := range strings.Split(row.body, "{{else}}") {
				if static := len(action.ReplaceAllString(branch, "")); static > 140 {
					t.Errorf("704 SMS %s has %d static characters, want at most 140", key, static)
				}
			}
		}
	}
}

type englishTemplateRow704 struct {
	id, version, channel, subject, body, source string
}

func englishTemplateRows704(t *testing.T, sql string) []englishTemplateRow704 {
	t.Helper()
	literal := `'((?:[^']|'')*)'`
	row := regexp.MustCompile(`(?m)^    \(` + literal + `, (\d+), '(email|sms)', ` + literal + `, ` + literal + `, ` + literal + `\),?$`)
	unquote := func(value string) string { return strings.ReplaceAll(value, "''", "'") }
	var rows []englishTemplateRow704
	for _, match := range row.FindAllStringSubmatch(sql, -1) {
		rows = append(rows, englishTemplateRow704{
			id: unquote(match[1]), version: match[2], channel: match[3],
			subject: unquote(match[4]), body: unquote(match[5]), source: unquote(match[6]),
		})
	}
	return rows
}

// seededChineseTemplates704 maps template/version/channel to subject+body of every template a migration before
// 704 inserts as literal rows ('id', version, 'channel', 'subject', 'body', ...).
func seededChineseTemplates704(t *testing.T) map[string]string {
	t.Helper()
	literal := `'((?:[^']|'')*)'`
	row := regexp.MustCompile(`\(\s*'([a-z][a-z0-9._-]*)'\s*,\s*(\d+)\s*,\s*'(email|sms)'\s*,\s*` + literal + `\s*,\s*` + literal)
	files, err := fs.Glob(FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, name := range files {
		if name >= "704_" {
			continue
		}
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "notification_templates") {
			continue
		}
		for _, match := range row.FindAllStringSubmatch(string(body), -1) {
			out[match[1]+"/"+match[2]+"/"+match[3]] = strings.ReplaceAll(match[4]+match[5], "''", "'")
		}
	}
	return out
}
