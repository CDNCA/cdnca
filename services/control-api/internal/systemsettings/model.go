package systemsettings

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid platform system settings input")
	ErrInvalidStore        = errors.New("invalid platform system settings store")
	ErrPermissionDenied    = errors.New("platform system settings permission denied")
	ErrRevisionConflict    = errors.New("platform system settings revision conflict")
	ErrIdempotencyConflict = errors.New("platform system settings idempotency conflict")
	ErrUnavailable         = errors.New("platform system settings unavailable")
)

const schema = "cdnca.platform-system-settings/v1"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type Settings struct {
	SystemName         string `json:"system_name"`
	UserTitle          string `json:"user_title"`
	AdminTitle         string `json:"admin_title"`
	FooterLinks        string `json:"footer_links"`
	FooterText         string `json:"footer_text"`
	GlobalJS           string `json:"global_js"`
	BoundDomains       string `json:"bound_domains"`
	Favicon            string `json:"favicon"`
	Logo               string `json:"logo"`
	LoginAd            string `json:"login_ad"`
	ExpiryClose        bool   `json:"expiry_close"`
	TrafficClose       bool   `json:"traffic_close"`
	AllowUpgrade       bool   `json:"allow_upgrade"`
	AllowDowngrade     bool   `json:"allow_downgrade"`
	PurchaseNotice     string `json:"purchase_notice"`
	Maintenance        bool   `json:"maintenance"`
	MaintenanceMessage string `json:"maintenance_message"`
	AutoUpgradeNode    bool   `json:"auto_upgrade_node"`
	Certificate        string `json:"certificate"`
	PrivateKey         string `json:"private_key"`
	// GlobalJSReportHosts are the https hosts the 全站JS代码 may report to or
	// load images from; the web container adds them to its CSP connect-src and
	// img-src. Plain lowercase hostnames, at most 20; omitted means none.
	GlobalJSReportHosts []string `json:"global_js_report_hosts,omitempty"`
}

// PublicBranding 是登录页无会话也可读的部分（匿名读系统名称）：
// 只有系统名称与两个控制台标题。
type PublicBranding struct {
	SystemName string `json:"system_name"`
	UserTitle  string `json:"user_title"`
	AdminTitle string `json:"admin_title"`
}

// PublicSettings 是下发给任意已登录会话（含租户用户）的子集：只含展示类字段，
// 不含绑定域名、证书引用等管理信息。
type PublicSettings struct {
	PublicBranding
	PurchaseNotice string `json:"purchase_notice"`
	GlobalJS       string `json:"global_js"`
}

type Document struct {
	Schema    string    `json:"schema"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Value     Settings  `json:"value"`
	Replayed  bool      `json:"-"`
}

type SaveRequest struct {
	ExpectedRevision int64
	Value            Settings
	IdempotencyKey   string
	RequestID        string
}

func DefaultSettings() Settings {
	return Settings{
		SystemName:         "cdnca",
		UserTitle:          "cdnca用户控制台",
		AdminTitle:         "cdnca管理员控制台",
		MaintenanceMessage: "维护中，请稍候重试!",
	}
}

func Schema() string { return schema }
