package dnsproviderremote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// DNS.COM plan tier, kept as the optional "plan" credential field (absent =
// free). Official plans: free has the three carriers;
// enterprise adds 拓展/区域/大洲 lines (dnsComEnterpriseLines); flagship adds
// 海外 on top of enterprise.
const (
	DNSComPlanField      = "plan"
	DNSComPlanFree       = "free"
	DNSComPlanEnterprise = "enterprise"
	DNSComPlanFlagship   = "flagship"
)

func validDNSComPlan(plan string) bool {
	return plan == DNSComPlanFree || plan == DNSComPlanEnterprise || plan == DNSComPlanFlagship
}

// dnsComEnterpriseLines are the enterprise plan's 拓展 (other carriers),
// 区域 (mainland regions) and 大洲 (continents) lines. They have no unified
// line (cnamelines and aggregated edge write only the five unified ones);
// reconcile operations name them as DNSPod does, and the view_id is matched
// by name from getView like the unified lines. The names are DNS.COM's
// public line names; the account's getView list is checked after
// deployment (BACKLOG-1035 C19), and a name it does not list is refused as
// not in plan rather than written to another line.
var dnsComEnterpriseLines = []string{
	"教育网", "铁通", "鹏博士", "广电网",
	"华北", "华东", "华南", "华中", "西北", "西南", "东北",
	"亚洲", "欧洲", "北美洲", "南美洲", "非洲", "大洋洲",
}

// DNSComPlanLines are the lines a DNS.COM plan tier opens: free 默认+三网,
// enterprise adds dnsComEnterpriseLines, flagship adds 境外 as well.
func DNSComPlanLines(plan string) []string {
	lines := []string{LineDefault, LineTelecom, LineUnicom, LineMobile}
	if plan == DNSComPlanEnterprise || plan == DNSComPlanFlagship {
		lines = append(lines, dnsComEnterpriseLines...)
	}
	if plan == DNSComPlanFlagship {
		lines = append(lines, LineOverseas)
	}
	return lines
}

func dnsComEnterpriseLine(line string) bool {
	for _, candidate := range dnsComEnterpriseLines {
		if candidate == line {
			return true
		}
	}
	return false
}

func dnsComPlanAllows(config ProviderConfig, line string) bool {
	if defaultReconcileLine(line) {
		return true
	}
	for _, allowed := range DNSComPlanLines(config.Credentials[DNSComPlanField]) {
		if allowed == line {
			return true
		}
	}
	return false
}

// DNS.COM publishes no view_id table (docs/7/11 lists only the fields), so
// the IDs are read per domain from /api/domain/getView/ and matched by name.
var dnsComViewNames = map[string][]string{
	LineDefault:  {"默认", "默认线路", "default"},
	LineTelecom:  {"电信", "中国电信", "telecom", "china telecom"},
	LineUnicom:   {"联通", "中国联通", "unicom", "china unicom"},
	LineMobile:   {"移动", "中国移动", "mobile", "china mobile"},
	LineOverseas: {"境外", "海外", "国外", "overseas", "abroad", "foreign"},
	// enterprise lines (dnsComEnterpriseLines)
	"教育网": {"教育网", "中国教育网", "education", "cernet"},
	"铁通":  {"铁通", "中国铁通", "tietong", "china tietong"},
	"鹏博士": {"鹏博士", "drpeng"},
	"广电网": {"广电网", "广电", "中国广电", "cbn", "china broadnet"},
	"华北":  {"华北", "north china"},
	"华东":  {"华东", "east china"},
	"华南":  {"华南", "south china"},
	"华中":  {"华中", "central china"},
	"西北":  {"西北", "northwest china"},
	"西南":  {"西南", "southwest china"},
	"东北":  {"东北", "northeast china"},
	"亚洲":  {"亚洲", "asia"},
	"欧洲":  {"欧洲", "europe"},
	"北美洲": {"北美洲", "北美", "north america"},
	"南美洲": {"南美洲", "南美", "south america"},
	"非洲":  {"非洲", "africa"},
	"大洋洲": {"大洋洲", "oceania"},
}

const dnsComViewCacheTTL = time.Hour

// dnsComViews is one domain's resolved line IDs. A unified line missing here
// is not available to the account (or disabled by the provider).
type dnsComViews struct {
	ids     map[string]string // unified line -> view_id
	lines   map[string]string // view_id -> unified line
	fetched time.Time
}

type dnsComViewCache struct {
	mu      sync.Mutex
	entries map[string]dnsComViews
}

// dnsComFlexText decodes a JSON string or number (the docs disagree on the
// types of every getView field) into text; null is "".
type dnsComFlexText string

func (text *dnsComFlexText) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	switch {
	case bytes.Equal(raw, []byte("null")):
		*text = ""
	case len(raw) > 0 && raw[0] == '"':
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || len(value) > 256 || containsControl(value) {
			return errors.New("invalid text")
		}
		*text = dnsComFlexText(strings.TrimSpace(value))
	case bytes.Equal(raw, []byte("true")):
		*text = "1"
	case bytes.Equal(raw, []byte("false")):
		*text = "0"
	default:
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return errors.New("invalid text")
		}
		if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
			return errors.New("invalid text")
		}
		*text = dnsComFlexText(number.String())
	}
	return nil
}

type dnsComView struct {
	ID         dnsComFlexText  `json:"id"`
	ParentID   dnsComFlexText  `json:"parent_id"`
	ViewName   dnsComFlexText  `json:"view_name"`
	ViewNameEn dnsComFlexText  `json:"view_name_en"`
	Sort       dnsComFlexText  `json:"sort"`
	Enable     *dnsComFlexText `json:"enable"`
}

// parseDNSComViews matches getView entries to unified lines by name. Only
// enabled entries count; two entries matching one line is refused rather
// than guessed (it would write the wrong line).
func parseDNSComViews(raw json.RawMessage) (dnsComViews, error) {
	var entries []dnsComView
	if err := decodeJSON(raw, &entries); err != nil {
		return dnsComViews{}, malformedProviderResponse()
	}
	views := dnsComViews{ids: map[string]string{}, lines: map[string]string{}}
	for _, entry := range entries {
		id := string(entry.ID)
		if !validReference(id, 64) {
			return dnsComViews{}, malformedProviderResponse()
		}
		if entry.Enable != nil && (*entry.Enable == "0" || *entry.Enable == "") {
			continue
		}
		line, ok := dnsComUnifiedName(string(entry.ViewName), string(entry.ViewNameEn))
		if !ok {
			continue
		}
		if known, duplicate := views.ids[line]; duplicate && known != id {
			return dnsComViews{}, malformedProviderResponse()
		}
		views.ids[line], views.lines[id] = id, line
	}
	return views, nil
}

func dnsComUnifiedName(name, english string) (string, bool) {
	name, english = strings.TrimSpace(name), strings.ToLower(strings.TrimSpace(english))
	for line, names := range dnsComViewNames {
		for _, candidate := range names {
			if name == candidate || english != "" && english == candidate {
				return line, true
			}
		}
	}
	return "", false
}

// views returns the domain's line IDs, from cache when fresh.
func (p *dnsComProvider) views(ctx context.Context, config ProviderConfig) (dnsComViews, error) {
	cache := p.adapter.dnsComViews
	if cache == nil {
		cache = &dnsComViewCache{}
	}
	key := providerCredentials(config, "api_key")[0] + "\x00" + config.ZoneName
	now := p.adapter.now()
	cache.mu.Lock()
	cached, ok := cache.entries[key]
	cache.mu.Unlock()
	if ok && now.Sub(cached.fetched) < dnsComViewCacheTTL && !now.Before(cached.fetched) {
		return cached, nil
	}
	envelope, err := p.request(ctx, config, "/api/domain/getView/", map[string]string{"domain": config.ZoneName})
	if err != nil {
		return dnsComViews{}, err
	}
	views, err := parseDNSComViews(envelope.Data)
	if err != nil {
		return dnsComViews{}, err
	}
	views.fetched = now
	cache.mu.Lock()
	if cache.entries == nil {
		cache.entries = map[string]dnsComViews{}
	}
	cache.entries[key] = views
	cache.mu.Unlock()
	return views, nil
}

// operationViewID is the view_id to write for a line: "" (omitted, the
// documented default) for the default line, else the matched ID; a line
// getView does not offer is not in the account's plan.
func (p *dnsComProvider) operationViewID(ctx context.Context, config ProviderConfig, line string) (string, error) {
	if defaultReconcileLine(line) {
		return "", nil
	}
	views, err := p.views(ctx, config)
	if err != nil {
		return "", err
	}
	id, ok := views.ids[line]
	if !ok {
		return "", failure(CodeLineNotInPlan, false)
	}
	return id, nil
}

// recordLines maps record view IDs to unified lines. getView is only called
// when some record carries a non-default view ID. Without a listed default
// entry, "0" is the default line (the documented default when omitted).
func (p *dnsComProvider) recordLines(ctx context.Context, config ProviderConfig, viewIDs []string) ([]string, error) {
	lines := make([]string, len(viewIDs))
	var views *dnsComViews
	for index, id := range viewIDs {
		if id == "" {
			lines[index] = LineDefault
			continue
		}
		if views == nil {
			loaded, err := p.views(ctx, config)
			if err != nil {
				return nil, err
			}
			views = &loaded
		}
		if line, ok := views.lines[id]; ok {
			lines[index] = line
		} else if _, listed := views.ids[LineDefault]; !listed && id == "0" {
			lines[index] = LineDefault
		} else {
			lines[index] = providerDNSCom + ":" + id
		}
	}
	return lines, nil
}

// mutationViewID is the view_id of a create or update. An update to the
// default line from another line needs the default entry's ID: omitting
// view_id keeps the old line (docs/12/16), so without a listed default
// entry the move is refused rather than guessed.
func (p *dnsComProvider) mutationViewID(ctx context.Context, config ProviderConfig,
	operation dnscheck.ProviderOperation) (string, error) {
	if operation.Action != dnscheck.ProviderUpdate || !defaultReconcileLine(operation.Line) ||
		defaultReconcileLine(operation.PreviousLine) {
		return p.operationViewID(ctx, config, operation.Line)
	}
	views, err := p.views(ctx, config)
	if err != nil {
		return "", err
	}
	id, ok := views.ids[LineDefault]
	if !ok {
		return "", failure(CodeUnsupported, false)
	}
	return id, nil
}
