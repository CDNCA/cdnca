package dnsproviderremote

// Unified DNS line values: the DNSPod line names the reconcile pipeline
// already carries (cnameallocation, dnsreconcilehttp, market dnsLine). Other
// providers map them to their own line codes. docs/dns/provider-line-capabilities.md
// lists the official sources of every mapping.
const (
	LineDefault  = "默认"
	LineTelecom  = "电信"
	LineUnicom   = "联通"
	LineMobile   = "移动"
	LineOverseas = "境外"
)

// providerLineCodes maps the unified lines a provider adapter can write to
// the provider's line code. DNSPod is absent: it takes the unified names (and
// its finer DNSPod line names) verbatim.
var providerLineCodes = map[string]map[string]string{
	providerAliyun: {
		LineDefault: "default", LineTelecom: "telecom", LineUnicom: "unicom", LineMobile: "mobile", LineOverseas: "oversea",
	},
	// Huawei basic lines (official 解析线路 table, zh-cn_topic_0085546214):
	// "Abroad 境外" sits beside "CN 中国大陆"; HK/MO/TW are listed under 亚太.
	providerHuawei: {
		LineDefault: "default_view", LineTelecom: "Dianxin", LineUnicom: "Liantong", LineMobile: "Yidong",
		LineOverseas: "Abroad",
	},
	// DNS.LA line IDs from GET https://api.dns.la/api/allLineList; the
	// default line is the empty ID.
	providerDNSLA: {
		LineDefault: "", LineTelecom: "84613316902921216", LineUnicom: "84613316923892736",
		LineMobile: "84613316953252864", LineOverseas: "84613317016167424",
	},
}

// SupportedLines returns the unified lines the provider adapter writes, in a
// fixed order. Providers without line support return only 默认, which is
// what ADR 0008 §6.4 degrades to (global primary/backup).
func SupportedLines(providerType string) []string {
	capability, ok := providerCapabilityFor(providerType)
	if !ok {
		return nil
	}
	if !capability.Line {
		return []string{LineDefault}
	}
	lines := make([]string, 0, 5)
	for _, line := range []string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas} {
		if _, ok := providerLineCode(providerType, line); ok {
			lines = append(lines, line)
		}
	}
	return lines
}

// providerLineCode returns the provider code to write for a unified line.
func providerLineCode(providerType, line string) (string, bool) {
	if defaultReconcileLine(line) {
		line = LineDefault
	}
	if providerType == providerDNSPodCN {
		return dnsPodOperationLine(line), true
	}
	// DNS.COM view IDs are resolved per domain at write time (getView, see
	// dnscom_lines.go); the plan gate is validateProviderReconcileOperation's.
	if providerType == providerCustomHTTP || providerType == providerPlugin || providerType == providerDNSCom {
		switch line {
		case LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas:
			return line, true
		}
		if providerType == providerDNSCom && dnsComEnterpriseLine(line) {
			return line, true
		}
		return "", false
	}
	code, ok := providerLineCodes[providerType][line]
	return code, ok
}

// unifiedLine maps a provider line code read back to the unified line. A
// code with no unified line keeps a provider prefix so it never compares
// equal to a unified value (it reads as a foreign, independent line).
func unifiedLine(providerType, code string) string {
	for line, known := range providerLineCodes[providerType] {
		if known == code {
			return line
		}
	}
	return providerType + ":" + code
}

// writableLine reports whether the adapter can write the operation's line.
func writableLine(providerType, line string) bool {
	_, ok := providerLineCode(providerType, line)
	return ok
}

// sameLine compares a record's unified line with an operation's line.
func sameLine(recordLine, operationLine string) bool {
	return recordLine == operationLine || defaultReconcileLine(recordLine) && defaultReconcileLine(operationLine)
}

// recordsOnLine keeps the records of one line: other lines of the same owner
// and type are independent record sets and neither match nor compete.
func recordsOnLine(records []reconcileRecord, line string) []reconcileRecord {
	kept := records[:0:0]
	for _, record := range records {
		if sameLine(record.Line, line) {
			kept = append(kept, record)
		}
	}
	return kept
}

// aliyunLine reads an Aliyun record's Line; the documented default for an
// omitted Line is "default".
func aliyunLine(code string) string {
	if code == "" {
		return LineDefault
	}
	return unifiedLine(providerAliyun, code)
}

// aliyunOperationLine is the Line parameter for a validated operation line.
func aliyunOperationLine(line string) string {
	code, _ := providerLineCode(providerAliyun, line)
	return code
}

const huaweiDefaultLine = "default_view"

// huaweiLine reads a Huawei record set line ID; sets listed without one are
// on the default line.
func huaweiLine(code string) string {
	if code == "" {
		return LineDefault
	}
	return unifiedLine(providerHuawei, code)
}

// huaweiOperationLine is the line ID for a validated operation line.
func huaweiOperationLine(line string) string {
	code, _ := providerLineCode(providerHuawei, line)
	return code
}

// dnsLALine reads a DNS.LA record line: the default line has an empty ID; a
// line outside the unified enum is named by its line code.
func dnsLALine(lineID, lineCode string) string {
	if lineID == "" {
		return LineDefault
	}
	for line, known := range providerLineCodes[providerDNSLA] {
		if known == lineID {
			return line
		}
	}
	if lineCode == "" {
		lineCode = lineID
	}
	return providerDNSLA + ":" + lineCode
}
