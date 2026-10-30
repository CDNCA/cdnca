import i18n from "../../i18n";

const zhCN = {
  title: "网站协议批量设置",
  forbidden: "无权管理网站",
  siteIDs: "网站 ID",
  siteIDsPlaceholder: "每行输入一个网站 ID（最多 100 个）",
  http2: "HTTP/2",
  http3: "HTTP/3",
  prefer: "优先使用服务端套件",
  keep: "不修改",
  on: "开启",
  off: "关闭",
  preset: "按预设",
  http3Hint: "只修改输入的网站；保存后自动重新发布。HTTP/3 仍需网站启用 TLSv1.3 与套餐支持。",
  submit: "批量保存",
  invalidSites: "请输入有效且不重复的网站 ID（最多 100 个）",
  noChanges: "请至少选择一项要修改的设置",
  requestFailed: "批量保存失败，请稍后重试",
  summary: "已保存 {{updated}} 个网站，失败 {{failed}} 个",
  columns: { site: "网站", state: "结果", error: "失败原因" },
  itemStates: { updated: "已保存", failed: "失败" },
  errors: {
    site_not_found: "网站不存在或无权访问",
    site_locked: "网站已被管理员锁定",
    version_conflict: "网站刚被其他操作修改，请重新提交",
    unknown: "保存失败",
  },
};

const enUS = {
  title: "Website protocol batch settings",
  forbidden: "You cannot manage websites",
  siteIDs: "Website IDs",
  siteIDsPlaceholder: "One website ID per line (up to 100)",
  http2: "HTTP/2",
  http3: "HTTP/3",
  prefer: "Prefer server ciphers",
  keep: "Keep",
  on: "On",
  off: "Off",
  preset: "By preset",
  http3Hint: "Only the listed websites change; they are republished after saving. HTTP/3 still needs TLSv1.3 on the website and a package that allows it.",
  submit: "Save batch",
  invalidSites: "Enter valid unique website IDs (up to 100)",
  noChanges: "Choose at least one setting to change",
  requestFailed: "The batch could not be saved. Try again later.",
  summary: "{{updated}} websites saved, {{failed}} failed",
  columns: { site: "Website", state: "Result", error: "Failure reason" },
  itemStates: { updated: "Saved", failed: "Failed" },
  errors: {
    site_not_found: "The website does not exist or is not accessible",
    site_locked: "The website is locked by an administrator",
    version_conflict: "The website was just changed by another operation. Submit again.",
    unknown: "Save failed",
  },
};

function pseudo(value: unknown): unknown {
  // interpolations ({{name}}) stay intact
  if (typeof value === "string")
    return `［${value.replace(/\{\{\w+\}\}|\S/g, (match) => (match.length > 1 ? match : `${match}~`))}］`;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      pseudo(item),
    ]),
  );
}

for (const [locale, messages] of Object.entries({
  "zh-CN": zhCN,
  "en-US": enUS,
  "qps-ploc": pseudo(zhCN),
  "qps-Ploc": pseudo(zhCN),
}))
  i18n.addResourceBundle(locale, "siteProtocols", messages, true, true);

export { enUS, zhCN };
