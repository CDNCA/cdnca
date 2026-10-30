package originfailover

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound            = errors.New("origin_failover_not_found")
	ErrInvalidInput        = errors.New("origin_failover_invalid_input")
	ErrFailbackUnavailable = errors.New("origin_failback_unavailable")
)

// PoolStatus is a site's origin pool state: what the site settings page
// shows and what aggregated edge scheduling reads (Overall).
type PoolStatus struct {
	SiteID        uuid.UUID      `json:"site_id"`
	FailbackMode  string         `json:"failback_mode"`
	ActiveLevel   int            `json:"active_level"`
	Overall       string         `json:"overall"`
	FailbackReady bool           `json:"failback_ready"`
	Levels        []LevelStatus  `json:"levels"`
	Origins       []OriginStatus `json:"origins"`
	SwitchedAt    *time.Time     `json:"switched_at"`
	CheckedAt     *time.Time     `json:"checked_at"`
}

type LevelStatus struct {
	Level  int    `json:"level"`
	Status string `json:"status"`
}

type OriginStatus struct {
	Position  int        `json:"position"`
	Host      string     `json:"host"`
	Port      int        `json:"port"`
	Level     int        `json:"level"`
	Enabled   bool       `json:"enabled"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason"`
	CheckedAt *time.Time `json:"checked_at"`
}
