package statuspage

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Auditor interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Service struct {
	pool    *pgxpool.Pool
	auditor Auditor
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, auditor Auditor, now func() time.Time) (*Service, error) {
	if pool == nil || auditor == nil {
		return nil, errors.New("status page dependencies are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{pool: pool, auditor: auditor, now: now}, nil
}

func (s *Service) clock() time.Time { return s.now().UTC().Truncate(time.Microsecond) }

// Admin returns the editor's view: settings, components with their
// automatic and effective status, incidents of the last 14 days and open
// ones, and the line groups a component can follow.
func (s *Service) Admin(ctx context.Context, actor Actor) (AdminView, error) {
	var view AdminView
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, PermissionRead); err != nil {
			return err
		}
		now := s.clock()
		if err := tx.QueryRow(ctx, `SELECT revision, enabled, title, description, show_logo, updated_at
			FROM status_page_settings WHERE id = 1`).Scan(&view.Revision, &view.Settings.Enabled, &view.Settings.Title,
			&view.Settings.Description, &view.Settings.ShowLogo, &view.UpdatedAt); err != nil {
			return err
		}
		components, err := componentStates(ctx, tx, now)
		if err != nil {
			return err
		}
		view.Components = components
		if view.Incidents, err = loadIncidents(ctx, tx, `resolved_at IS NULL OR resolved_at > $1`, now.AddDate(0, 0, -RecentDays)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, name FROM node_line_groups
			WHERE tenant_scope_id = $1 AND deleted_at IS NULL AND purpose = 'general' ORDER BY lower(name), id`, actor.ScopeID)
		if err != nil {
			return err
		}
		view.LineGroups, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (LineGroupOption, error) {
			var option LineGroupOption
			return option, row.Scan(&option.ID, &option.Name)
		})
		return err
	})
	return view, err
}

func validText(value string, min, max int, multiline bool) bool {
	if value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	if count < min || count > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && !(multiline && r == '\n') {
			return false
		}
	}
	return true
}

func validManualStatus(status string) bool {
	switch status {
	case StatusOperational, StatusDegraded, StatusOutage, StatusMaintenance:
		return true
	}
	return false
}

// Save replaces the settings and the component list in one revision.
// Components missing from the list are deleted with their history; open
// incidents drop references to them.
func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (AdminView, error) {
	settings := request.Settings
	if request.ExpectedRevision < 1 || !validText(settings.Title, 0, 64, false) || !validText(settings.Description, 0, 500, true) {
		return AdminView{}, ErrInvalidInput
	}
	if len(request.Components) > MaxComponents {
		return AdminView{}, ErrTooManyComponents
	}
	names := map[string]bool{}
	for index, item := range request.Components {
		if item.ManualStatus == "" {
			request.Components[index].ManualStatus, item.ManualStatus = StatusOperational, StatusOperational
		}
		if !validText(item.Name, 1, 64, false) || !validText(item.Description, 0, 200, false) || !validManualStatus(item.ManualStatus) ||
			item.Source == SourceLineGroup && (item.LineGroupID == nil || *item.LineGroupID == uuid.Nil) ||
			item.Source == SourceManual && item.LineGroupID != nil || item.Source != SourceManual && item.Source != SourceLineGroup {
			return AdminView{}, ErrInvalidInput
		}
		key := strings.ToLower(item.Name)
		if names[key] {
			return AdminView{}, ErrDuplicateComponent
		}
		names[key] = true
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, PermissionManage); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM status_page_settings WHERE id = 1 FOR UPDATE`).Scan(&revision); err != nil {
			return err
		}
		if revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		return s.saveComponents(ctx, tx, actor, request)
	})
	if err != nil {
		return AdminView{}, err
	}
	return s.Admin(ctx, actor)
}
