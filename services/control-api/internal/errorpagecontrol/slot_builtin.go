package errorpagecontrol

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/jackc/pgx/v5"
)

// An unbound slot shows the page in effect, and
// a bound slot replaces that page on the nodes.

// Slot delivery: what a node answers for the slot while it is unbound.
const (
	// SlotDeliveryTheme: the active theme's page (the content shown).
	SlotDeliveryTheme = "theme"
	// SlotDeliveryFallback: no theme is activated, so the node answers with
	// its short plain-text fallback; the content shown is the default theme's
	// page, which a save puts live.
	SlotDeliveryFallback = "fallback"
	// SlotDeliveryNone: no node page reads the slot yet; a save only stores it.
	SlotDeliveryNone = "none"
)

type slotNodePage struct {
	Category string
	Status   int
}

// slotNodePages are the slots a node error page reads: the theme default
// page (category, status) a bound slot replaces. waf_block is the node's own
// block page (edge_route 403, sec-followup P13). The other slots have no node
// page in this release.
var slotNodePages = map[string]slotNodePage{
	SlotHTTP400:            {CategoryNoHost, 400},
	SlotWAFBlock:           {CategoryEdgeRoute, 403},
	SlotHTTP502:            {CategoryEdgeConnect, 502},
	SlotHTTP504:            {CategoryEdgeConnect, 504},
	SlotDomainUnconfigured: {CategoryUnknownSite, 404},
}

// slotOwnPages are the slots a node answers itself with a slot node page
// (errpage-3, ERROR_PAGE_SLOTS; siteobject.SlotNodePageStatus): the node
// page category and status. A bound one goes out as a node page; unbound,
// the node keeps its built-in answer (delivery fallback). site_locked has
// no node response (锁定只限制修改、节点照常服务): saved only.
var slotOwnPages = map[string]slotNodePage{
	SlotBlacklist:       {SlotBlacklist, 403},
	SlotHTTP403:         {SlotHTTP403, 403},
	SlotTrafficExceeded: {SlotTrafficExceeded, 509},
	SlotPackageExpired:  {SlotPackageExpired, 403},
	SlotNodeIPAccess:    {SlotNodeIPAccess, 403},
	SlotConnectionLimit: {SlotConnectionLimit, 503},
}

// SlotReachesNodes reports whether a node answers with the slot's page once
// it is bound (a theme page it replaces or a slot node page).
func SlotReachesNodes(key string) bool {
	_, theme := slotNodePages[key]
	_, own := slotOwnPages[key]
	return theme || own
}

// slotBuiltinText words the built-in page of a slot no theme page covers,
// rendered with the theme's error page template.
var slotBuiltinText = map[string][3]string{
	SlotBlacklist:       {"403", "403 访问被拒绝 / Access denied", "您的 IP 已被列入黑名单，无法访问本站。 Your IP address is blocked from this website."},
	SlotHTTP403:         {"403", "403 禁止访问 / Forbidden", "您没有权限访问该页面。 You do not have permission to access this page."},
	SlotTrafficExceeded: {"509", "网站流量已超出限制 / Traffic limit exceeded", "本网站的流量已超出限制，请联系网站管理员。 The traffic of this website has exceeded its limit. Please contact the website administrator."},
	SlotPackageExpired:  {"403", "套餐已到期 / Plan expired", "本网站所属套餐已到期，请联系网站管理员续费。 The plan of this website has expired. Please contact the website administrator."},
	SlotSiteLocked:      {"403", "网站已被锁定 / Website locked", "本网站已被锁定，暂时无法访问。 This website is locked and temporarily unavailable."},
	SlotNodeIPAccess:    {"403", "403 禁止直接访问 / Direct access denied", "不允许通过节点 IP 直接访问。 Direct access by node IP address is not allowed."},
	SlotConnectionLimit: {"503", "503 连接数超限 / Too many connections", "当前连接数过多，请稍后重试。 Too many connections. Please try again later."},
}

// builtinSlotContent is the page a slot shows while unbound and what a node
// answers for it (delivery).
func builtinSlotContent(ctx context.Context, tx pgx.Tx, key string) ([]byte, string, error) {
	packageSHA256, err := activeAdminThemePackage(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	rendered := themepack.DefaultRendered()
	if packageSHA256 != "" {
		digest, _ := hex.DecodeString(packageSHA256)
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT package_body FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, "", err
		}
		if err == nil {
			if own, renderErr := themepack.Render(raw); renderErr == nil {
				rendered = own
			}
		}
	}
	return slotPageFrom(rendered, key, packageSHA256 != "")
}

func slotPageFrom(rendered themepack.Rendered, key string, themed bool) ([]byte, string, error) {
	if page, ok := slotNodePages[key]; ok {
		for _, candidate := range rendered.ErrorPages {
			if candidate.Category == page.Category && candidate.Status == page.Status {
				delivery := SlotDeliveryTheme
				// Without a theme a node has only the built-in block pages.
				if !themed && page.Category != CategoryEdgeRoute {
					delivery = SlotDeliveryFallback
				}
				return candidate.Body, delivery, nil
			}
		}
		return nil, "", ErrConflict
	}
	text, ok := slotBuiltinText[key]
	if !ok {
		return nil, "", ErrInvalidInput
	}
	body, err := rendered.RenderErrorPage(text[0], text[1], text[2])
	if err != nil {
		return nil, "", ErrConflict
	}
	if _, own := slotOwnPages[key]; own {
		return body, SlotDeliveryFallback, nil
	}
	return body, SlotDeliveryNone, nil
}
