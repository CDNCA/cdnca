package themepack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
)

// TokenKind is the type of a theme token value (ADR 0007 §7.2).
type TokenKind string

const (
	TokenColor      TokenKind = "color"
	TokenLength     TokenKind = "length"
	TokenNumber     TokenKind = "number"
	TokenFontFamily TokenKind = "font_family"
	// TokenShadow is a box-shadow list: "none" or up to four
	// "[inset ]<x> <y>[ <blur>[ <spread>]] <color>" with px lengths and
	// #rrggbb or rgb(r g b / a%) colors. It is a CSS variable only and never
	// enters an error page (no errorpagestyle property takes it).
	TokenShadow TokenKind = "shadow"
)

// TokenSpec is one whitelisted token: its type, range, default (today's
// hard-coded value in apps/web) and where it lands.
type TokenSpec struct {
	Name    string
	Kind    TokenKind
	Min     float64
	Max     float64
	Default any
	// Antd is true for tokens passed to ConfigProvider.theme.token.
	Antd bool
	// CSSVariables are the custom properties the SPA stylesheet reads.
	CSSVariables []string
	// Group sorts the token in the theme customize panel (scale starts
	// folded). It is not part of a theme package or the rendered output.
	Group TokenGroup
}

// TokenGroup is the customize-panel section of a token.
type TokenGroup string

const (
	GroupBase   TokenGroup = "base"   // 基础
	GroupStatus TokenGroup = "status" // 状态
	GroupTable  TokenGroup = "table"  // 表格
	GroupChart  TokenGroup = "chart"  // 图表
	GroupDark   TokenGroup = "dark"   // 暗色
	GroupScale  TokenGroup = "scale"  // 刻度：页面零散颜色，每个一个精确值
)

const defaultFontFamily = `"Helvetica Neue", Helvetica, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "微软雅黑", Arial, sans-serif`

// tokenSpecs is the whitelist. Defaults reproduce apps/web/src/main.tsx and
// styles.css before themes, so the default theme changes nothing on screen.
var tokenSpecs = []TokenSpec{
	{Name: "colorPrimary", Kind: TokenColor, Group: GroupBase, Default: "#2d8cf0", Antd: true, CSSVariables: []string{"--setting-primary", "--cdnca-color-primary"}},
	{Name: "colorLink", Kind: TokenColor, Group: GroupBase, Default: "#2d8cf0", Antd: true},
	{Name: "colorLinkHover", Kind: TokenColor, Group: GroupBase, Default: "#57a3f3", Antd: true},
	{Name: "colorText", Kind: TokenColor, Group: GroupBase, Default: "#515a6e", Antd: true, CSSVariables: []string{"--cdnca-color-text"}},
	{Name: "colorTextSecondary", Kind: TokenColor, Group: GroupBase, Default: "#808695", Antd: true, CSSVariables: []string{"--cdnca-color-text-secondary"}},
	{Name: "colorBorder", Kind: TokenColor, Group: GroupBase, Default: "#dcdee2", Antd: true, CSSVariables: []string{"--setting-border-strong", "--cdnca-color-border"}},
	{Name: "colorBgLayout", Kind: TokenColor, Group: GroupBase, Default: "#f5f7f9", Antd: true, CSSVariables: []string{"--cdnca-color-bg-layout"}},
	{Name: "colorBgContainer", Kind: TokenColor, Group: GroupBase, Default: "#ffffff", Antd: true, CSSVariables: []string{"--setting-bg", "--cdnca-color-bg-container"}},
	{Name: "borderRadius", Kind: TokenLength, Group: GroupBase, Min: 0, Max: 16, Default: 4.0, Antd: true, CSSVariables: []string{"--cdnca-border-radius"}},
	{Name: "controlHeight", Kind: TokenLength, Group: GroupBase, Min: 24, Max: 48, Default: 32.0, Antd: true},
	{Name: "fontSize", Kind: TokenLength, Group: GroupBase, Min: 12, Max: 18, Default: 14.0, Antd: true, CSSVariables: []string{"--cdnca-font-size"}},
	{Name: "lineHeight", Kind: TokenNumber, Group: GroupBase, Min: 1, Max: 2, Default: 1.5, Antd: true},
	{Name: "fontFamily", Kind: TokenFontFamily, Group: GroupBase, Default: defaultFontFamily, Antd: true, CSSVariables: []string{"--cdnca-font-family"}},
	{Name: "colorBorderSecondary", Kind: TokenColor, Group: GroupBase, Default: "#e8eaec", CSSVariables: []string{"--setting-border", "--cdnca-color-border-secondary"}},
	{Name: "colorBgPage", Kind: TokenColor, Group: GroupBase, Default: "#eceef2", CSSVariables: []string{"--cdnca-color-bg-page"}},
	{Name: "colorBgLogin", Kind: TokenColor, Group: GroupBase, Default: "#f7f7f7", CSSVariables: []string{"--cdnca-color-bg-login"}},
	{Name: "colorSidebarDark", Kind: TokenColor, Group: GroupBase, Default: "#001529", CSSVariables: []string{"--cdnca-color-sidebar-dark"}},
	{Name: "sidebarWidth", Kind: TokenLength, Group: GroupBase, Min: 200, Max: 320, Default: 256.0, CSSVariables: []string{"--cdnca-sidebar-width"}},
	// Semantic colors, surfaces, shadows, buttons, focus ring and chart
	// palette (CSS only). Defaults are the values apps/web hard-codes today.
	{Name: "colorTitle", Kind: TokenColor, Group: GroupBase, Default: "#17233d"},
	{Name: "colorSuccess", Kind: TokenColor, Group: GroupStatus, Default: "#19be6b"},
	{Name: "colorWarning", Kind: TokenColor, Group: GroupStatus, Default: "#ff9900"},
	{Name: "colorError", Kind: TokenColor, Group: GroupStatus, Default: "#ed4014"},
	{Name: "colorInfoBg", Kind: TokenColor, Group: GroupStatus, Default: "#f0faff"},
	{Name: "colorSuccessBg", Kind: TokenColor, Group: GroupStatus, Default: "#edfff3"},
	{Name: "colorWarningBg", Kind: TokenColor, Group: GroupStatus, Default: "#fff9e6"},
	{Name: "colorErrorBg", Kind: TokenColor, Group: GroupStatus, Default: "#ffefe6"},
	{Name: "colorTableHeader", Kind: TokenColor, Group: GroupTable, Default: "#f8f8f9"},
	{Name: "colorTableHeaderText", Kind: TokenColor, Group: GroupTable, Default: "#515a6e"},
	{Name: "colorTableRowHover", Kind: TokenColor, Group: GroupTable, Default: "#ebf7ff"},
	{Name: "colorFocusRing", Kind: TokenColor, Group: GroupBase, Default: "#2d8cf0"},
	// Page panels (filter bars, setting sections) and their hairlines.
	{Name: "colorBgPanel", Kind: TokenColor, Group: GroupBase, Default: "#fbfdff"},
	{Name: "colorBorderPanel", Kind: TokenColor, Group: GroupBase, Default: "#edf1f7"},
	{Name: "colorBorderDivider", Kind: TokenColor, Group: GroupBase, Default: "#f0f1f2"},
	{Name: "shadowCard", Kind: TokenShadow, Group: GroupBase, Default: "0 1px 3px rgb(15 23 42 / 4%), 0 12px 28px rgb(15 23 42 / 6%)"},
	{Name: "shadowPopup", Kind: TokenShadow, Group: GroupBase, Default: "0 1px 6px rgb(0 0 0 / 20%)"},
	{Name: "buttonShadow", Kind: TokenShadow, Group: GroupBase, Default: "none"},
	{Name: "buttonFontWeight", Kind: TokenNumber, Group: GroupBase, Min: 300, Max: 700, Default: 400.0},
	{Name: "chartColor1", Kind: TokenColor, Group: GroupChart, Default: "#2d8cf0"},
	{Name: "chartColor2", Kind: TokenColor, Group: GroupChart, Default: "#19be6b"},
	{Name: "chartColor3", Kind: TokenColor, Group: GroupChart, Default: "#ff9900"},
	{Name: "chartColor4", Kind: TokenColor, Group: GroupChart, Default: "#ed4014"},
	{Name: "chartColor5", Kind: TokenColor, Group: GroupChart, Default: "#9a66e4"},
	// Dark mode (body.i-theme-dark) palette; a theme recolors dark mode through these.
	{Name: "colorBgDark", Kind: TokenColor, Group: GroupDark, Default: "#0f172a"},
	{Name: "colorChromeDark", Kind: TokenColor, Group: GroupDark, Default: "#111827"},
	{Name: "colorSurfaceDark", Kind: TokenColor, Group: GroupDark, Default: "#172033"},
	{Name: "colorSurfaceMutedDark", Kind: TokenColor, Group: GroupDark, Default: "#111c2e"},
	{Name: "colorBorderDark", Kind: TokenColor, Group: GroupDark, Default: "#273449"},
	{Name: "colorBorderSoftDark", Kind: TokenColor, Group: GroupDark, Default: "#1f2a3d"},
	{Name: "colorTextDark", Kind: TokenColor, Group: GroupDark, Default: "#e5e7eb"},
	{Name: "colorTextSecondaryDark", Kind: TokenColor, Group: GroupDark, Default: "#98a2b3"},
	{Name: "colorPrimaryDark", Kind: TokenColor, Group: GroupDark, Default: "#60a5fa"},
	// Further chart series (WAF attack types), node traffic in/out, the admin-home bar gradient and trend area.
	{Name: "chartColor6", Kind: TokenColor, Group: GroupChart, Default: "#2db7f5"},
	{Name: "chartColor7", Kind: TokenColor, Group: GroupChart, Default: "#808695"},
	{Name: "chartColor8", Kind: TokenColor, Group: GroupChart, Default: "#e46cbb"},
	{Name: "chartColor9", Kind: TokenColor, Group: GroupChart, Default: "#5cadff"},
	{Name: "chartColor10", Kind: TokenColor, Group: GroupChart, Default: "#f2c037"},
	{Name: "chartTrafficIn", Kind: TokenColor, Group: GroupChart, Default: "#5b8ff9"},
	{Name: "chartTrafficOut", Kind: TokenColor, Group: GroupChart, Default: "#61d9a5"},
	{Name: "chartBar1", Kind: TokenColor, Group: GroupChart, Default: "#69cdff"},
	{Name: "chartBar2", Kind: TokenColor, Group: GroupChart, Default: "#3eb3f7"},
	{Name: "chartBar3", Kind: TokenColor, Group: GroupChart, Default: "#1495eb"},
	{Name: "chartArea", Kind: TokenColor, Group: GroupChart, Default: "#bbdefb"},
	// Status dot of a pending node; light hairline of nested form rows.
	{Name: "colorStatusPending", Kind: TokenColor, Group: GroupStatus, Default: "#faad14"},
	{Name: "colorBorderLight", Kind: TokenColor, Group: GroupBase, Default: "#f0f0f0"},
	// Recurring page colors: soft and tinted surfaces, extra text and hairline shades, text on colored fills.
	{Name: "colorBgSubtle", Kind: TokenColor, Group: GroupBase, Default: "#f8fbff"},
	{Name: "colorBgMuted", Kind: TokenColor, Group: GroupBase, Default: "#fafbfc"},
	{Name: "colorBgSlate", Kind: TokenColor, Group: GroupBase, Default: "#f8fafc"},
	{Name: "colorBgSoft", Kind: TokenColor, Group: GroupBase, Default: "#f5f7fa"},
	{Name: "colorBgField", Kind: TokenColor, Group: GroupBase, Default: "#f7f9fc"},
	{Name: "colorBgHover", Kind: TokenColor, Group: GroupBase, Default: "#f3f3f3"},
	{Name: "colorPrimaryBg", Kind: TokenColor, Group: GroupBase, Default: "#eaf4ff"},
	{Name: "colorPrimaryBgSoft", Kind: TokenColor, Group: GroupBase, Default: "#f0f7ff"},
	{Name: "colorBorderMuted", Kind: TokenColor, Group: GroupBase, Default: "#dfe4ec"},
	{Name: "colorBorderInput", Kind: TokenColor, Group: GroupBase, Default: "#d9dfe8"},
	{Name: "colorBorderCard", Kind: TokenColor, Group: GroupBase, Default: "#e5eaf3"},
	{Name: "colorTextEmphasis", Kind: TokenColor, Group: GroupBase, Default: "#27364e"},
	{Name: "colorTextSubtle", Kind: TokenColor, Group: GroupBase, Default: "#596273"},
	{Name: "colorTextHint", Kind: TokenColor, Group: GroupBase, Default: "#667085"},
	{Name: "colorTextTertiary", Kind: TokenColor, Group: GroupBase, Default: "#a2a8b3"},
	{Name: "colorTextFaint", Kind: TokenColor, Group: GroupBase, Default: "#98a2b3"},
	{Name: "colorTextDisabled", Kind: TokenColor, Group: GroupBase, Default: "#999999"},
	{Name: "colorTextInverse", Kind: TokenColor, Group: GroupBase, Default: "#ffffff"},
	// Scale: one-off page colors, one exact value each (customize panel folds this group).
	{Name: "colorBlue1", Kind: TokenColor, Group: GroupScale, Default: "#fcfdff"},
	{Name: "colorBlue2", Kind: TokenColor, Group: GroupScale, Default: "#fbfcfe"},
	{Name: "colorBlue3", Kind: TokenColor, Group: GroupScale, Default: "#f8faff"},
	{Name: "colorBlue4", Kind: TokenColor, Group: GroupScale, Default: "#f7fbff"},
	{Name: "colorBlue5", Kind: TokenColor, Group: GroupScale, Default: "#f7faff"},
	{Name: "colorBlue6", Kind: TokenColor, Group: GroupScale, Default: "#f8fafd"},
	{Name: "colorBlue7", Kind: TokenColor, Group: GroupScale, Default: "#f5faff"},
	{Name: "colorBlue8", Kind: TokenColor, Group: GroupScale, Default: "#f4f9ff"},
	{Name: "colorBlue9", Kind: TokenColor, Group: GroupScale, Default: "#f3f7ff"},
	{Name: "colorBlue10", Kind: TokenColor, Group: GroupScale, Default: "#f1f8ff"},
	{Name: "colorBlue11", Kind: TokenColor, Group: GroupScale, Default: "#eef6ff"},
	{Name: "colorBlue12", Kind: TokenColor, Group: GroupScale, Default: "#eef7ff"},
	{Name: "colorBlue13", Kind: TokenColor, Group: GroupScale, Default: "#edf5ff"},
	{Name: "colorBlue14", Kind: TokenColor, Group: GroupScale, Default: "#eaf3ff"},
	{Name: "colorBlue15", Kind: TokenColor, Group: GroupScale, Default: "#eef3fa"},
	{Name: "colorBlue16", Kind: TokenColor, Group: GroupScale, Default: "#eaf3fe"},
	{Name: "colorBlue17", Kind: TokenColor, Group: GroupScale, Default: "#eaf1fb"},
	{Name: "colorBlue18", Kind: TokenColor, Group: GroupScale, Default: "#e6f2ff"},
	{Name: "colorBlue19", Kind: TokenColor, Group: GroupScale, Default: "#e1f0fe"},
	{Name: "colorBlue20", Kind: TokenColor, Group: GroupScale, Default: "#dbeafe"},
	{Name: "colorBlue21", Kind: TokenColor, Group: GroupScale, Default: "#d9eaff"},
	{Name: "colorBlue22", Kind: TokenColor, Group: GroupScale, Default: "#d8eaff"},
	{Name: "colorBlue23", Kind: TokenColor, Group: GroupScale, Default: "#dfe8f6"},
	{Name: "colorBlue24", Kind: TokenColor, Group: GroupScale, Default: "#d5eaff"},
	{Name: "colorBlue25", Kind: TokenColor, Group: GroupScale, Default: "#d9e2ef"},
	{Name: "colorBlue26", Kind: TokenColor, Group: GroupScale, Default: "#d9e0eb"},
	{Name: "colorBlue27", Kind: TokenColor, Group: GroupScale, Default: "#d8dee9"},
	{Name: "colorBlue28", Kind: TokenColor, Group: GroupScale, Default: "#badcff"},
	{Name: "colorBlue29", Kind: TokenColor, Group: GroupScale, Default: "#b8d7ff"},
	{Name: "colorBlue30", Kind: TokenColor, Group: GroupScale, Default: "#b8cff2"},
	{Name: "colorBlue31", Kind: TokenColor, Group: GroupScale, Default: "#c7d1df"},
	{Name: "colorBlue32", Kind: TokenColor, Group: GroupScale, Default: "#c3cfdf"},
	{Name: "colorBlue33", Kind: TokenColor, Group: GroupScale, Default: "#91caff"},
	{Name: "colorBlue34", Kind: TokenColor, Group: GroupScale, Default: "#8fc3ff"},
	{Name: "colorBlue35", Kind: TokenColor, Group: GroupScale, Default: "#69a8ff"},
	{Name: "colorBlue36", Kind: TokenColor, Group: GroupScale, Default: "#6cadde"},
	{Name: "colorBlue37", Kind: TokenColor, Group: GroupScale, Default: "#4f8ee8"},
	{Name: "colorBlue38", Kind: TokenColor, Group: GroupScale, Default: "#4e8de7"},
	{Name: "colorBlue39", Kind: TokenColor, Group: GroupScale, Default: "#4b8ce8"},
	{Name: "colorBlue40", Kind: TokenColor, Group: GroupScale, Default: "#2f7df6"},
	{Name: "colorBlue41", Kind: TokenColor, Group: GroupScale, Default: "#2f8cf4"},
	{Name: "colorBlue42", Kind: TokenColor, Group: GroupScale, Default: "#1677ff"},
	{Name: "colorBlue43", Kind: TokenColor, Group: GroupScale, Default: "#667fa8"},
	{Name: "colorBlue44", Kind: TokenColor, Group: GroupScale, Default: "#176dd1"},
	{Name: "colorBlue45", Kind: TokenColor, Group: GroupScale, Default: "#1f3858"},
	{Name: "colorBlue46", Kind: TokenColor, Group: GroupScale, Default: "#23304a"},
	{Name: "colorBlue47", Kind: TokenColor, Group: GroupScale, Default: "#1f2d3d"},
	{Name: "colorBlue48", Kind: TokenColor, Group: GroupScale, Default: "#0f234b"},
	{Name: "colorBlue49", Kind: TokenColor, Group: GroupScale, Default: "#17233c"},
	{Name: "colorBlue50", Kind: TokenColor, Group: GroupScale, Default: "#0f172a"},
	{Name: "colorBlue51", Kind: TokenColor, Group: GroupScale, Default: "#101828"},
	{Name: "colorNeutral1", Kind: TokenColor, Group: GroupScale, Default: "#f8f9fc"},
	{Name: "colorNeutral2", Kind: TokenColor, Group: GroupScale, Default: "#fafafa"},
	{Name: "colorNeutral3", Kind: TokenColor, Group: GroupScale, Default: "#f6f8fb"},
	{Name: "colorNeutral4", Kind: TokenColor, Group: GroupScale, Default: "#f7f8fa"},
	{Name: "colorNeutral5", Kind: TokenColor, Group: GroupScale, Default: "#f6f8fa"},
	{Name: "colorNeutral6", Kind: TokenColor, Group: GroupScale, Default: "#f6f7f9"},
	{Name: "colorNeutral7", Kind: TokenColor, Group: GroupScale, Default: "#f3f4f6"},
	{Name: "colorNeutral8", Kind: TokenColor, Group: GroupScale, Default: "#f2f4f7"},
	{Name: "colorNeutral9", Kind: TokenColor, Group: GroupScale, Default: "#f4f4f4"},
	{Name: "colorNeutral10", Kind: TokenColor, Group: GroupScale, Default: "#f1f3f6"},
	{Name: "colorNeutral11", Kind: TokenColor, Group: GroupScale, Default: "#f2f3f5"},
	{Name: "colorNeutral12", Kind: TokenColor, Group: GroupScale, Default: "#f1f3f5"},
	{Name: "colorNeutral13", Kind: TokenColor, Group: GroupScale, Default: "#edf2f8"},
	{Name: "colorNeutral14", Kind: TokenColor, Group: GroupScale, Default: "#eef2f7"},
	{Name: "colorNeutral15", Kind: TokenColor, Group: GroupScale, Default: "#f0f2f5"},
	{Name: "colorNeutral16", Kind: TokenColor, Group: GroupScale, Default: "#eef1f5"},
	{Name: "colorNeutral17", Kind: TokenColor, Group: GroupScale, Default: "#edf1f6"},
	{Name: "colorNeutral18", Kind: TokenColor, Group: GroupScale, Default: "#eef0f5"},
	{Name: "colorNeutral19", Kind: TokenColor, Group: GroupScale, Default: "#eef0f4"},
	{Name: "colorNeutral20", Kind: TokenColor, Group: GroupScale, Default: "#e8eef7"},
	{Name: "colorNeutral21", Kind: TokenColor, Group: GroupScale, Default: "#e9edf5"},
	{Name: "colorNeutral22", Kind: TokenColor, Group: GroupScale, Default: "#e8eef6"},
	{Name: "colorNeutral23", Kind: TokenColor, Group: GroupScale, Default: "#e8edf5"},
	{Name: "colorNeutral24", Kind: TokenColor, Group: GroupScale, Default: "#e6edf6"},
	{Name: "colorNeutral25", Kind: TokenColor, Group: GroupScale, Default: "#eeeeee"},
	{Name: "colorNeutral26", Kind: TokenColor, Group: GroupScale, Default: "#e5ebf3"},
	{Name: "colorNeutral27", Kind: TokenColor, Group: GroupScale, Default: "#e8ebf0"},
	{Name: "colorNeutral28", Kind: TokenColor, Group: GroupScale, Default: "#e4e9f2"},
	{Name: "colorNeutral29", Kind: TokenColor, Group: GroupScale, Default: "#e3e8f0"},
	{Name: "colorNeutral30", Kind: TokenColor, Group: GroupScale, Default: "#e1e6ef"},
	{Name: "colorNeutral31", Kind: TokenColor, Group: GroupScale, Default: "#dce7f3"},
	{Name: "colorNeutral32", Kind: TokenColor, Group: GroupScale, Default: "#e2e5ed"},
	{Name: "colorNeutral33", Kind: TokenColor, Group: GroupScale, Default: "#dfe5ee"},
	{Name: "colorNeutral34", Kind: TokenColor, Group: GroupScale, Default: "#dfe3ea"},
	{Name: "colorNeutral35", Kind: TokenColor, Group: GroupScale, Default: "#dcdfe6"},
	{Name: "colorNeutral36", Kind: TokenColor, Group: GroupScale, Default: "#d9dee7"},
	{Name: "colorNeutral37", Kind: TokenColor, Group: GroupScale, Default: "#d9dde5"},
	{Name: "colorNeutral38", Kind: TokenColor, Group: GroupScale, Default: "#d7dce5"},
	{Name: "colorNeutral39", Kind: TokenColor, Group: GroupScale, Default: "#d9d9d9"},
	{Name: "colorNeutral40", Kind: TokenColor, Group: GroupScale, Default: "#d0d5dd"},
	{Name: "colorNeutral41", Kind: TokenColor, Group: GroupScale, Default: "#cccccc"},
	{Name: "colorNeutral42", Kind: TokenColor, Group: GroupScale, Default: "#c5c8ce"},
	{Name: "colorNeutral43", Kind: TokenColor, Group: GroupScale, Default: "#bfc4ce"},
	{Name: "colorNeutral44", Kind: TokenColor, Group: GroupScale, Default: "#b9c0cc"},
	{Name: "colorNeutral45", Kind: TokenColor, Group: GroupScale, Default: "#b8bfca"},
	{Name: "colorNeutral46", Kind: TokenColor, Group: GroupScale, Default: "#b8bec8"},
	{Name: "colorNeutral47", Kind: TokenColor, Group: GroupScale, Default: "#b9bdc4"},
	{Name: "colorNeutral48", Kind: TokenColor, Group: GroupScale, Default: "#aab3c2"},
	{Name: "colorNeutral49", Kind: TokenColor, Group: GroupScale, Default: "#a8b2c2"},
	{Name: "colorNeutral50", Kind: TokenColor, Group: GroupScale, Default: "#a7adb8"},
	{Name: "colorNeutral51", Kind: TokenColor, Group: GroupScale, Default: "#a0a8b6"},
	{Name: "colorNeutral52", Kind: TokenColor, Group: GroupScale, Default: "#a0a5b1"},
	{Name: "colorNeutral53", Kind: TokenColor, Group: GroupScale, Default: "#9aa4b5"},
	{Name: "colorNeutral54", Kind: TokenColor, Group: GroupScale, Default: "#9aa3b2"},
	{Name: "colorNeutral55", Kind: TokenColor, Group: GroupScale, Default: "#9aa1ad"},
	{Name: "colorNeutral56", Kind: TokenColor, Group: GroupScale, Default: "#9b9ea8"},
	{Name: "colorNeutral57", Kind: TokenColor, Group: GroupScale, Default: "#9399a5"},
	{Name: "colorNeutral58", Kind: TokenColor, Group: GroupScale, Default: "#8c96a8"},
	{Name: "colorNeutral59", Kind: TokenColor, Group: GroupScale, Default: "#8c93a3"},
	{Name: "colorNeutral60", Kind: TokenColor, Group: GroupScale, Default: "#8b93a1"},
	{Name: "colorNeutral61", Kind: TokenColor, Group: GroupScale, Default: "#909399"},
	{Name: "colorNeutral62", Kind: TokenColor, Group: GroupScale, Default: "#8c8c8c"},
	{Name: "colorNeutral63", Kind: TokenColor, Group: GroupScale, Default: "#7c8799"},
	{Name: "colorNeutral64", Kind: TokenColor, Group: GroupScale, Default: "#6e7685"},
	{Name: "colorNeutral65", Kind: TokenColor, Group: GroupScale, Default: "#6b7280"},
	{Name: "colorNeutral66", Kind: TokenColor, Group: GroupScale, Default: "#657180"},
	{Name: "colorNeutral67", Kind: TokenColor, Group: GroupScale, Default: "#5c667a"},
	{Name: "colorNeutral68", Kind: TokenColor, Group: GroupScale, Default: "#5b667a"},
	{Name: "colorNeutral69", Kind: TokenColor, Group: GroupScale, Default: "#5c6577"},
	{Name: "colorNeutral70", Kind: TokenColor, Group: GroupScale, Default: "#536178"},
	{Name: "colorNeutral71", Kind: TokenColor, Group: GroupScale, Default: "#526077"},
	{Name: "colorNeutral72", Kind: TokenColor, Group: GroupScale, Default: "#606266"},
	{Name: "colorNeutral73", Kind: TokenColor, Group: GroupScale, Default: "#475467"},
	{Name: "colorNeutral74", Kind: TokenColor, Group: GroupScale, Default: "#3b4352"},
	{Name: "colorNeutral75", Kind: TokenColor, Group: GroupScale, Default: "#344054"},
	{Name: "colorNeutral76", Kind: TokenColor, Group: GroupScale, Default: "#373737"},
	{Name: "colorNeutral77", Kind: TokenColor, Group: GroupScale, Default: "#333333"},
	{Name: "colorNeutral78", Kind: TokenColor, Group: GroupScale, Default: "#303133"},
	{Name: "colorNeutral79", Kind: TokenColor, Group: GroupScale, Default: "#1d2329"},
	{Name: "colorNeutral80", Kind: TokenColor, Group: GroupScale, Default: "#000000"},
	{Name: "colorGreen1", Kind: TokenColor, Group: GroupScale, Default: "#f0fff6"},
	{Name: "colorGreen2", Kind: TokenColor, Group: GroupScale, Default: "#edfff7"},
	{Name: "colorGreen3", Kind: TokenColor, Group: GroupScale, Default: "#edfff5"},
	{Name: "colorGreen4", Kind: TokenColor, Group: GroupScale, Default: "#effbf5"},
	{Name: "colorGreen5", Kind: TokenColor, Group: GroupScale, Default: "#effaf5"},
	{Name: "colorGreen6", Kind: TokenColor, Group: GroupScale, Default: "#edfbf3"},
	{Name: "colorGreen7", Kind: TokenColor, Group: GroupScale, Default: "#fffbe6"},
	{Name: "colorGreen8", Kind: TokenColor, Group: GroupScale, Default: "#e8f9f0"},
	{Name: "colorGreen9", Kind: TokenColor, Group: GroupScale, Default: "#cdeed8"},
	{Name: "colorGreen10", Kind: TokenColor, Group: GroupScale, Default: "#c8f0dc"},
	{Name: "colorGreen11", Kind: TokenColor, Group: GroupScale, Default: "#c8efd9"},
	{Name: "colorGreen12", Kind: TokenColor, Group: GroupScale, Default: "#b8efda"},
	{Name: "colorGreen13", Kind: TokenColor, Group: GroupScale, Default: "#b9ebd2"},
	{Name: "colorGreen14", Kind: TokenColor, Group: GroupScale, Default: "#27b676"},
	{Name: "colorGreen15", Kind: TokenColor, Group: GroupScale, Default: "#389e0d"},
	{Name: "colorGreen16", Kind: TokenColor, Group: GroupScale, Default: "#00a870"},
	{Name: "colorGreen17", Kind: TokenColor, Group: GroupScale, Default: "#0f8f4d"},
	{Name: "colorGreen18", Kind: TokenColor, Group: GroupScale, Default: "#237804"},
	{Name: "colorOrange1", Kind: TokenColor, Group: GroupScale, Default: "#fff7e6"},
	{Name: "colorOrange2", Kind: TokenColor, Group: GroupScale, Default: "#fff8e6"},
	{Name: "colorOrange3", Kind: TokenColor, Group: GroupScale, Default: "#ffe0a8"},
	{Name: "colorOrange4", Kind: TokenColor, Group: GroupScale, Default: "#ffd591"},
	{Name: "colorOrange5", Kind: TokenColor, Group: GroupScale, Default: "#ffad33"},
	{Name: "colorOrange6", Kind: TokenColor, Group: GroupScale, Default: "#f3a337"},
	{Name: "colorOrange7", Kind: TokenColor, Group: GroupScale, Default: "#fa541c"},
	{Name: "colorOrange8", Kind: TokenColor, Group: GroupScale, Default: "#c98b2e"},
	{Name: "colorOrange9", Kind: TokenColor, Group: GroupScale, Default: "#d46b08"},
	{Name: "colorOrange10", Kind: TokenColor, Group: GroupScale, Default: "#ad6800"},
	{Name: "colorOrange11", Kind: TokenColor, Group: GroupScale, Default: "#7a4d05"},
	{Name: "colorRed1", Kind: TokenColor, Group: GroupScale, Default: "#fff5f2"},
	{Name: "colorRed2", Kind: TokenColor, Group: GroupScale, Default: "#fff3f0"},
	{Name: "colorRed3", Kind: TokenColor, Group: GroupScale, Default: "#fff1f0"},
	{Name: "colorRed4", Kind: TokenColor, Group: GroupScale, Default: "#ffccc7"},
	{Name: "colorRed5", Kind: TokenColor, Group: GroupScale, Default: "#ffc7bb"},
	{Name: "colorRed6", Kind: TokenColor, Group: GroupScale, Default: "#ff654f"},
	{Name: "colorRed7", Kind: TokenColor, Group: GroupScale, Default: "#df4b2e"},
	{Name: "colorRed8", Kind: TokenColor, Group: GroupScale, Default: "#ee461c"},
	{Name: "colorPurple1", Kind: TokenColor, Group: GroupScale, Default: "#c7254e"},
	// Dark-mode one-off colors.
	{Name: "colorScale1Dark", Kind: TokenColor, Group: GroupDark, Default: "#d8dee9"},
	{Name: "colorScale2Dark", Kind: TokenColor, Group: GroupDark, Default: "#d1d5db"},
	{Name: "colorScale3Dark", Kind: TokenColor, Group: GroupDark, Default: "#374151"},
	{Name: "colorScale4Dark", Kind: TokenColor, Group: GroupDark, Default: "#353b4a"},
	{Name: "colorScale5Dark", Kind: TokenColor, Group: GroupDark, Default: "#22324c"},
	{Name: "colorScale6Dark", Kind: TokenColor, Group: GroupDark, Default: "#1c2940"},
	{Name: "colorScale7Dark", Kind: TokenColor, Group: GroupDark, Default: "#242834"},
	{Name: "colorScale8Dark", Kind: TokenColor, Group: GroupDark, Default: "#202731"},
	{Name: "colorScale9Dark", Kind: TokenColor, Group: GroupDark, Default: "#000000"},
}

var (
	shadowLength = `-?(?:0|[0-9]{1,3}(?:\.[0-9]{1,2})?px)`
	shadowColor  = `(?:#[0-9a-f]{6}|rgb\([0-9]{1,3} [0-9]{1,3} [0-9]{1,3} / [0-9]{1,3}%\))`
	shadowPart   = `(?:inset )?` + shadowLength + ` ` + shadowLength + `(?: ` + shadowLength + `(?: ` + shadowLength + `)?)? ` + shadowColor
	shadowRegexp = regexp.MustCompile(`^(?:none|` + shadowPart + `(?:, ` + shadowPart + `){0,3})$`)
)

// validShadow reports whether value is a TokenShadow value.
func validShadow(value string) bool { return len(value) <= 256 && shadowRegexp.MatchString(value) }

var tokenIndex = func() map[string]TokenSpec {
	index := make(map[string]TokenSpec, len(tokenSpecs))
	for _, spec := range tokenSpecs {
		index[spec.Name] = spec
	}
	return index
}()

// TokenSpecs returns the whitelist in a stable order.
func TokenSpecs() []TokenSpec { return append([]TokenSpec(nil), tokenSpecs...) }

// resolveTokens checks each supplied token against its spec and fills the
// rest with defaults. Values are kept as string (colors, fonts) or float64.
func resolveTokens(raw map[string]json.RawMessage) (map[string]any, error) {
	resolved := make(map[string]any, len(tokenSpecs))
	for _, spec := range tokenSpecs {
		resolved[spec.Name] = spec.Default
	}
	overrides, err := decodeTokens(raw, "tokens.")
	if err != nil {
		return nil, err
	}
	for name, value := range overrides {
		resolved[name] = value
	}
	return resolved, nil
}

// Roles a package may give its own token values (tokens_by_role): the
// administrator console and the user console. A token a role leaves out
// keeps the shared value.
var themeRoles = []string{"admin", "user"}

// resolveRoleTokens checks tokens_by_role; each role keeps only the tokens
// it overrides.
func resolveRoleTokens(raw map[string]map[string]json.RawMessage) (map[string]map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	resolved := make(map[string]map[string]any, len(raw))
	for role, tokens := range raw {
		if !oneOf(role, themeRoles) {
			return nil, invalid("token_role", "tokens_by_role."+role)
		}
		values, err := decodeTokens(tokens, "tokens_by_role."+role+".")
		if err != nil {
			return nil, err
		}
		if len(values) > 0 {
			resolved[role] = values
		}
	}
	return resolved, nil
}

func decodeTokens(raw map[string]json.RawMessage, field string) (map[string]any, error) {
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make(map[string]any, len(names))
	for _, name := range names {
		spec, ok := tokenIndex[name]
		if !ok {
			return nil, invalid("token_unknown", field+name)
		}
		value, err := decodeToken(spec, raw[name])
		if err != nil {
			return nil, invalid("token_value", field+name)
		}
		values[name] = value
	}
	return values, nil
}

func decodeToken(spec TokenSpec, raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	switch spec.Kind {
	case TokenColor:
		text, ok := value.(string)
		if !ok || !errorpagestyle.ValidDeclaration("color", text) {
			return nil, fmt.Errorf("color")
		}
		return text, nil
	case TokenFontFamily:
		text, ok := value.(string)
		if !ok || !errorpagestyle.ValidFontStack(text) {
			return nil, fmt.Errorf("font")
		}
		return text, nil
	case TokenShadow:
		text, ok := value.(string)
		if !ok || !validShadow(text) {
			return nil, fmt.Errorf("shadow")
		}
		return text, nil
	case TokenLength, TokenNumber:
		number, ok := value.(json.Number)
		if !ok {
			return nil, fmt.Errorf("number")
		}
		parsed, err := strconv.ParseFloat(number.String(), 64)
		if err != nil || parsed < spec.Min || parsed > spec.Max {
			return nil, fmt.Errorf("range")
		}
		// Two decimal places at most, so CSS text is exact.
		if scaled := parsed * 100; math.Abs(scaled-math.Round(scaled)) > 1e-9 {
			return nil, fmt.Errorf("precision")
		}
		return parsed, nil
	}
	return nil, fmt.Errorf("kind")
}

// cssValue renders a resolved token as CSS text.
func cssValue(spec TokenSpec, value any) string {
	switch spec.Kind {
	case TokenLength:
		return strconv.FormatFloat(value.(float64), 'f', -1, 64) + "px"
	case TokenNumber:
		return strconv.FormatFloat(value.(float64), 'f', -1, 64)
	default:
		return value.(string)
	}
}

// tokenStyleValue is the value a template style declaration gets for
// "token:<name>": the token's CSS text, which must also satisfy the
// declaration's property (checked by errorpagestyle.Render).
func tokenStyleValue(tokens map[string]any, name string) (string, bool) {
	spec, ok := tokenIndex[name]
	if !ok {
		return "", false
	}
	return cssValue(spec, tokens[name]), true
}
