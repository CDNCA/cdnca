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
	// StatusUnconfigured: no evidence to judge (no nodes, no tasks, no probe address).
	// It is never sampled, never counts toward uptime and never lowers a group or the page.
	StatusUnconfigured = "unconfigured"

	SourceManual      = "manual"
	SourceLineGroup   = "line_group"
	SourceNode        = "node"
	SourceNodeOverall = "node_overall"
	SourceGateway     = "gateway"
	SourceControlAPI  = "control_api"
	SourceWebConsole  = "web_console"
	SourceDNSSync     = "dns_sync"
	SourceCertIssue   = "cert_issue"

	KindIncident    = "incident"
	KindMaintenance = "maintenance"

	MaxComponents  = 50
	MaxGroups      = 20
	HistoryDays    = 90
	RetentionDays  = 120
	RecentDays     = HistoryDays
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
	ErrTooManyGroups       = errors.New("status page has too many groups")
	ErrDuplicateGroup      = errors.New("status page group name is duplicated")
	ErrUnknownGroup        = errors.New("status page component references an unknown group")
	ErrNodeNotFound        = errors.New("status page node not found")
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
	NameEN       string     `json:"name_en"`
	Description  string     `json:"description"`
	Source       string     `json:"source"`
	LineGroupID  *uuid.UUID `json:"line_group_id,omitempty"`
	NodeID       *uuid.UUID `json:"node_id,omitempty"`
	GroupID      *uuid.UUID `json:"group_id,omitempty"`
	ManualStatus string     `json:"manual_status"`
	Hidden       bool       `json:"hidden"`
}

// GroupInput is one administrator-defined group. The client generates the ID
// of a new group so components in the same request can refer to it.
type GroupInput struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	NameEN string    `json:"name_en"`
	Hidden bool      `json:"hidden"`
}

// SaveRequest lists groups and components in display order.
type SaveRequest struct {
	ExpectedRevision int64
	Settings         Settings         `json:"settings"`
	Groups           []GroupInput     `json:"groups"`
	Components       []ComponentInput `json:"components"`
}

type AdminComponent struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	NameEN           string     `json:"name_en"`
	Description      string     `json:"description"`
	Source           string     `json:"source"`
	LineGroupID      *uuid.UUID `json:"line_group_id,omitempty"`
	LineGroupName    string     `json:"line_group_name,omitempty"`
	LineGroupMissing bool       `json:"line_group_missing"`
	NodeID           *uuid.UUID `json:"node_id,omitempty"`
	NodeName         string     `json:"node_name,omitempty"`
	GroupID          *uuid.UUID `json:"group_id,omitempty"`
	ManualStatus     string     `json:"manual_status"`
	Hidden           bool       `json:"hidden"`
	AutoStatus       string     `json:"auto_status,omitempty"`
	Status           string     `json:"status"`
	// Note says why the status is what it is (no nodes, no recent tasks, ...).
	Note Text `json:"note"`
	// reason is a short English summary of why the component is not operational, for the per-minute detail.
	reason string
}

type AdminGroup struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	NameEN string    `json:"name_en"`
	Hidden bool      `json:"hidden"`
}

type LineGroupOption struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type NodeOption struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Text is a bilingual string; EN may be empty (the page then falls back to ZH).
type Text struct {
	ZH string `json:"zh"`
	EN string `json:"en"`
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
	Groups     []AdminGroup      `json:"groups"`
	Components []AdminComponent  `json:"components"`
	Incidents  []Incident        `json:"incidents"`
	LineGroups []LineGroupOption `json:"line_groups"`
	Nodes      []NodeOption      `json:"nodes"`
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

// PublicEvent is an incident's share of one day of a component.
type PublicEvent struct {
	ID      string     `json:"id"`
	Kind    string     `json:"kind"`
	Title   Text       `json:"title"`
	Impact  string     `json:"impact"`
	Start   time.Time  `json:"start"`
	End     *time.Time `json:"end,omitempty"`
	Minutes int        `json:"minutes"`
}

// PublicDay is one UTC day of a component's history. Status is no_data and
// Uptime nil on a day without samples; they are never shown as 0%.
type PublicDay struct {
	Day         string   `json:"day"`
	Status      string   `json:"status"`
	Uptime      *float64 `json:"uptime"`
	Sampled     int      `json:"sampled"`
	Degraded    int      `json:"degraded"`
	Outage      int      `json:"outage"`
	Maintenance int      `json:"maintenance"`
	// Operational and NoData complete the day's split (operational + degraded + outage + maintenance + no_data
	// = the minutes of the day that have passed; today only counts up to now). Computed from the same rows.
	Operational int           `json:"operational"`
	NoData      int           `json:"no_data"`
	Events      []PublicEvent `json:"events,omitempty"`
}

// PublicComponent is a component or, with Mode "group", a group of them
// (its children name it in Parent). Keys are opaque; group keys start with "g-".
type PublicComponent struct {
	Key             string      `json:"key"`
	Name            Text        `json:"name"`
	Status          string      `json:"status"`
	Note            Text        `json:"note"`
	Mode            string      `json:"mode,omitempty"`
	Parent          string      `json:"parent,omitempty"`
	Uptime90        *float64    `json:"uptime_90d"`
	MonitoringSince string      `json:"monitoring_since,omitempty"`
	History         []PublicDay `json:"history"`
}

type PublicUpdate struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Message   Text      `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type PublicIncident struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	Title          Text           `json:"title"`
	Impact         string         `json:"impact"`
	Status         string         `json:"status"`
	ComponentKeys  []string       `json:"component_keys"`
	ScheduledStart *time.Time     `json:"scheduled_start,omitempty"`
	ScheduledEnd   *time.Time     `json:"scheduled_end,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	ResolvedAt     *time.Time     `json:"resolved_at,omitempty"`
	Updates        []PublicUpdate `json:"updates"`
}

type PublicView struct {
	Schema      string            `json:"schema"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	ShowLogo    bool              `json:"show_logo"`
	Status      string            `json:"status"`
	Components  []PublicComponent `json:"components"`
	Active      []PublicIncident  `json:"active"`
	Upcoming    []PublicIncident  `json:"upcoming"`
	Recent      []PublicIncident  `json:"recent"`
	GeneratedAt time.Time         `json:"generated_at"`
}

const PublicSchema = "cdnca.status-page/v2"

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

// worst picks the most severe status. Unconfigured only wins when nothing else is given.
func worst(statuses ...string) string {
	result := StatusOperational
	for _, status := range statuses {
		if severity(status) > severity(result) {
			result = status
		}
	}
	return result
}

// ratioStatus turns member counts into a status: no member is unconfigured (nothing to judge,
// never an outage), none up is an outage, under 80% up degraded.
func ratioStatus(total, up int) string {
	switch {
	case total <= 0:
		return StatusUnconfigured
	case up <= 0:
		return StatusOutage
	case up*degradedRatio5 < total*degradedRatio4:
		return StatusDegraded
	}
	return StatusOperational
}

// lineGroupStatus is ratioStatus over a line group's enabled endpoints.
func lineGroupStatus(total, available int) string { return ratioStatus(total, available) }

// shareStatus judges task outcomes: no task is unconfigured, no failure operational,
// under half failed degraded, half or more failed an outage.
func shareStatus(total, failed int) string {
	switch {
	case total <= 0:
		return StatusUnconfigured
	case failed <= 0:
		return StatusOperational
	case failed*2 < total:
		return StatusDegraded
	}
	return StatusOutage
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
