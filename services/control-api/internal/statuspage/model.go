// Package statuspage is the controller's public service status page: customer-named
// components whose status comes from a manual value, open incidents, maintenance windows and,
// for line-group components, the share of the line group's endpoints that
// can serve. The public view carries component-level status only: no node
// address, host name, node or endpoint count, ratio or line group id.
package statuspage

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	PermissionRead   = "system_configuration.read"
	PermissionManage = "system_configuration.manage"

	OperationSave           = "status_page.save"
	OperationIncidentCreate = "status_page.incident_create"
	OperationIncidentUpdate = "status_page.incident_update"
	OperationIncidentDelete = "status_page.incident_delete"

	StatusOperational = "operational"
	StatusDegraded    = "degraded"
	StatusOutage      = "outage"
	StatusMaintenance = "maintenance"

	SourceManual    = "manual"
	SourceLineGroup = "line_group"

	KindIncident    = "incident"
	KindMaintenance = "maintenance"

	MaxComponents  = 50
	HistoryDays    = 90
	RetentionDays  = 120
	RecentDays     = 14
	UpcomingDays   = 7
	degradedRatio4 = 4 // degraded below 4/5 (80%) of enabled endpoints available
	degradedRatio5 = 5
)

var (
	ErrInvalidInput        = errors.New("status page input is invalid")
	ErrPermissionDenied    = errors.New("status page permission denied")
	ErrNotFound            = errors.New("status page resource not found")
	ErrRevisionConflict    = errors.New("status page revision conflict")
	ErrDisabled            = errors.New("status page is not public")
	ErrLineGroupNotFound   = errors.New("status page line group not found")
	ErrIncidentTransition  = errors.New("status page incident status transition is invalid")
	ErrDuplicateComponent  = errors.New("status page component name is duplicated")
	ErrTooManyComponents   = errors.New("status page has too many components")
	ErrUnknownComponentRef = errors.New("status page incident references an unknown component")
)

var (
	incidentStatuses    = []string{"investigating", "identified", "monitoring", "resolved"}
	maintenanceStatuses = []string{"scheduled", "in_progress", "completed"}
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	RequestID string
}

type Settings struct {
	Enabled     bool   `json:"enabled"`
	Title       string `json:"title"`
	Description string `json:"description"`
	ShowLogo    bool   `json:"show_logo"`
}

type ComponentInput struct {
	// ID empty: a new component. A known ID keeps its history.
	ID           *uuid.UUID `json:"id,omitempty"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Source       string     `json:"source"`
	LineGroupID  *uuid.UUID `json:"line_group_id,omitempty"`
	ManualStatus string     `json:"manual_status"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Settings         Settings         `json:"settings"`
	Components       []ComponentInput `json:"components"`
}

type AdminComponent struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Source           string     `json:"source"`
	LineGroupID      *uuid.UUID `json:"line_group_id,omitempty"`
	LineGroupName    string     `json:"line_group_name,omitempty"`
	LineGroupMissing bool       `json:"line_group_missing"`
	ManualStatus     string     `json:"manual_status"`
	AutoStatus       string     `json:"auto_status,omitempty"`
	Status           string     `json:"status"`
}

type LineGroupOption struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type IncidentUpdate struct {
	ID        uuid.UUID `json:"id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type Incident struct {
	ID             uuid.UUID        `json:"id"`
	Kind           string           `json:"kind"`
	Title          string           `json:"title"`
	Impact         string           `json:"impact"`
	Status         string           `json:"status"`
	ComponentIDs   []uuid.UUID      `json:"component_ids"`
	ScheduledStart *time.Time       `json:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time       `json:"scheduled_end,omitempty"`
	StartedAt      time.Time        `json:"started_at"`
	ResolvedAt     *time.Time       `json:"resolved_at,omitempty"`
	Updates        []IncidentUpdate `json:"updates"`
}

type AdminView struct {
	Revision   int64             `json:"revision"`
	Settings   Settings          `json:"settings"`
	Components []AdminComponent  `json:"components"`
	Incidents  []Incident        `json:"incidents"`
	LineGroups []LineGroupOption `json:"line_groups"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type IncidentInput struct {
	Kind           string      `json:"kind"`
	Title          string      `json:"title"`
	Impact         string      `json:"impact"`
	Status         string      `json:"status"`
	Message        string      `json:"message"`
	ComponentIDs   []uuid.UUID `json:"component_ids"`
	ScheduledStart *time.Time  `json:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time  `json:"scheduled_end,omitempty"`
}

type UpdateInput struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// PublicDay is one UTC day of a component's history. Uptime is nil on a day
// without samples (shown as "no data").
type PublicDay struct {
	Day    string   `json:"day"`
	Status string   `json:"status"`
	Uptime *float64 `json:"uptime"`
}

type PublicComponent struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Status      string      `json:"status"`
	Uptime90    *float64    `json:"uptime_90d"`
	History     []PublicDay `json:"history"`
}

type PublicView struct {
	Schema      string            `json:"schema"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	ShowLogo    bool              `json:"show_logo"`
	Status      string            `json:"status"`
	Components  []PublicComponent `json:"components"`
	Active      []Incident        `json:"active"`
	Upcoming    []Incident        `json:"upcoming"`
	Recent      []Incident        `json:"recent"`
	GeneratedAt time.Time         `json:"generated_at"`
}

const PublicSchema = "cdnca.status-page/v1"

// severity orders statuses; the worse one wins.
func severity(status string) int {
	switch status {
	case StatusOutage:
		return 3
	case StatusDegraded:
		return 2
	case StatusMaintenance:
		return 1
	}
	return 0
}

func worst(statuses ...string) string {
	result := StatusOperational
	for _, status := range statuses {
		if severity(status) > severity(result) {
			result = status
		}
	}
	return result
}

// lineGroupStatus turns endpoint counts into a component status: nothing
// enabled or nothing available is an outage, under 80% available degraded.
func lineGroupStatus(total, available int) string {
	switch {
	case total <= 0 || available <= 0:
		return StatusOutage
	case available*degradedRatio5 < total*degradedRatio4:
		return StatusDegraded
	}
	return StatusOperational
}

// dayStatus colours one day: any outage minute is red, any degraded minute
// amber, any maintenance minute blue.
func dayStatus(degraded, outage, maintenance int) string {
	switch {
	case outage > 0:
		return StatusOutage
	case degraded > 0:
		return StatusDegraded
	case maintenance > 0:
		return StatusMaintenance
	}
	return StatusOperational
}

// uptime is 1 - outage / (sampled - maintenance); nil without samples.
func uptime(sampled, outage, maintenance int) *float64 {
	counted := sampled - maintenance
	if counted <= 0 {
		return nil
	}
	value := 1 - float64(outage)/float64(counted)
	if value < 0 {
		value = 0
	}
	return &value
}
