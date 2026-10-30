package auditlog

import (
	"context"
	"encoding/csv"
	"io"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

var exportHeader = map[audit.Locale][]string{
	audit.LocaleZH: {"时间", "分类", "操作人", "来源 IP", "对象类型", "对象", "结果", "原因", "详情", "改动", "请求 ID", "事件"},
	audit.LocaleEN: {"Time", "Category", "Actor", "Source IP", "Object type", "Object", "Result", "Reason", "Summary", "Changes", "Request ID", "Action"},
}

// Export writes up to MaxExportRows rows matching filter as CSV and returns
// how many were written. filter.Cursor/Limit are managed here.
func (store *Store) Export(ctx context.Context, filter Filter, locale audit.Locale, location *time.Location, out io.Writer) (int, error) {
	writer := csv.NewWriter(out)
	if err := writer.Write(exportHeader[locale]); err != nil {
		return 0, err
	}
	filter.Cursor, filter.Limit = "", MaxLimit
	written := 0
	for written < MaxExportRows {
		page, err := store.List(ctx, filter, locale, location)
		if err != nil {
			return written, err
		}
		for _, item := range page.Items {
			if written >= MaxExportRows {
				break
			}
			if err := writer.Write(exportRow(item, locale)); err != nil {
				return written, err
			}
			written++
		}
		if page.NextCursor == "" {
			break
		}
		filter.Cursor = page.NextCursor
	}
	writer.Flush()
	return written, writer.Error()
}

func exportRow(item audit.Rendered, locale audit.Locale) []string {
	changes := make([]string, 0, len(item.Changes))
	for _, change := range item.Changes {
		if locale == audit.LocaleEN {
			changes = append(changes, change.Label+": "+change.Before+" -> "+change.After)
		} else {
			changes = append(changes, change.Label+"："+change.Before+" → "+change.After)
		}
	}
	row := []string{item.Time, item.CategoryLabel, item.Actor, item.SourceIP, item.ResourceType, item.Resource,
		item.ResultLabel, item.Reason, item.Summary, strings.Join(changes, "; "), item.RequestID, item.Action}
	for index, cell := range row {
		row[index] = safeCell(cell)
	}
	return row
}

// safeCell stops spreadsheet formula injection: a cell starting with
// = + - @ (or a tab / carriage return) is prefixed with an apostrophe.
func safeCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}
	return value
}
