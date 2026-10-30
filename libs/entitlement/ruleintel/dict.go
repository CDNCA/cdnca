package ruleintel

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/cluster"
)

// 主控脱敏用的字典（ADR 0011 §4.3 脱敏规则 2–4，RI-08）。授权端 Validate 只看形状；
// 主控在出站前用这里的函数把参数名、路径模板、签名维度换成可以出主控的形式。

// ParamSalt 是参数名 HMAC 的平台盐：所有安装相同，授权端能跨安装聚合同名参数，
// 但不能反查字典外的名字（字典外名字的穷举仍可能，ADR §9 Q4）。
const ParamSalt = "cdnca-rule-intel-param/v1"

// ParamClassDict / ParamClassOther 是 param.class 的两个取值。
const (
	ParamClassDict  = "dict"
	ParamClassOther = "other"
)

// paramdict.txt 是内置的官方通用参数名字典（随官方规则包下发的 dataset/param-dict 尚未发布，
// 发布后由主控覆盖；内置表只收录公开框架里常见的参数名）。
//
//go:embed paramdict.txt
var paramDictRaw string

var paramDict = func() map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(paramDictRaw, "\n") {
		if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
			out[name] = true
		}
	}
	return out
}()

// pathClasses 是可以出主控的路径模板类别（按前缀匹配，第一个命中的为准）。
var pathClasses = []struct{ prefix, class string }{
	{"/wp-admin/", "/wp-admin/*"}, {"/wp-login.php", "/wp-login.php"}, {"/wp-content/", "/wp-content/*"},
	{"/wp-includes/", "/wp-includes/*"}, {"/xmlrpc.php", "/xmlrpc.php"}, {"/wp-json/", "/wp-json/*"},
	{"/api/", "/api/*"}, {"/admin/", "/admin/*"}, {"/administrator/", "/administrator/*"},
	{"/phpmyadmin/", "/phpmyadmin/*"}, {"/cgi-bin/", "/cgi-bin/*"}, {"/.env", "/.env"}, {"/.git/", "/.git/*"},
	{"/vendor/", "/vendor/*"}, {"/actuator/", "/actuator/*"}, {"/graphql", "/graphql"}, {"/login", "/login"},
	{"/user/", "/user/*"}, {"/static/", "/static/*"}, {"/upload/", "/upload/*"}, {"/uploads/", "/uploads/*"},
}

// ParamConds 是一个参数在报告条件里的形式：字典内原样上报 param.name（+ param.class=dict），
// 字典外只报 param.class=other + param.hash=HMAC(ParamSalt, 规范名)。loc 为空则不带位置。
func ParamConds(loc, name string) [][2]string {
	normalized := NormalizeParamName(name)
	if normalized == "" {
		return nil
	}
	var conds [][2]string
	if loc = strings.ToLower(strings.TrimSpace(loc)); loc != "" {
		conds = append(conds, [2]string{cluster.DimParamLoc, loc})
	}
	if paramDict[normalized] {
		return append(conds, [2]string{cluster.DimParamName, normalized}, [2]string{cluster.DimParamClass, ParamClassDict})
	}
	mac := hmac.New(sha256.New, []byte(ParamSalt))
	_, _ = mac.Write([]byte(normalized))
	return append(conds, [2]string{cluster.DimParamClass, ParamClassOther},
		[2]string{cluster.DimParamHash, hex.EncodeToString(mac.Sum(nil))})
}

// NormalizeParamName 与 cluster 规范化一致：小写、去 [] 后缀、数字下标改 [*]。
func NormalizeParamName(name string) string {
	canon, err := cluster.Normalizer{}.Normalize(cluster.RawCandidate{Kind: cluster.KindWAFExclusion,
		Conds: []cluster.Cond{{Dim: cluster.DimParamName, Value: name}}})
	if err != nil || len(canon.Conds) != 1 {
		return ""
	}
	return canon.Conds[0].Value
}

// InParamDict 报告规范名是否在官方通用参数名字典内。
func InParamDict(name string) bool { return paramDict[NormalizeParamName(name)] }

// PathClass 把路径模板映射到可以出主控的类别；字典外返回 ""（调用方丢弃该条件）。
func PathClass(template string) string {
	path := strings.ToLower(strings.TrimSpace(template))
	for _, entry := range pathClasses {
		if path == strings.TrimSuffix(entry.prefix, "/") || strings.HasPrefix(path, entry.prefix) {
			return entry.class
		}
	}
	return ""
}

// signatureBuckets 是自动防御行为分桶维度 → 报告维度（bucket.*）。
var signatureBuckets = map[string]string{
	"bytes_bucket": "bucket.bytes", "interval_cv_bucket": "bucket.interval_cv",
	"unique_path_ratio_bucket": "bucket.unique_path_ratio", "static_ratio_bucket": "bucket.static_ratio",
	"challenge_passed": "bucket.challenge_passed", "missing_header": "bucket.missing_header",
}

var signatureKeep = map[string]bool{"method": true, "ja4": true, "ua_family": true, "http_version": true,
	"asn": true, "country": true, "status": true}

// SignatureConds 把 AD-03 签名条件（维度=值）按 §4.3 脱敏规则 4 改写：保留 method、ja4、ua_family、
// http_version、asn、country、status 与行为分桶；header_order_hash 扩成 64 位摘要（节点值是 16 位，
// 授权端只收 64 位）；path_template 只留类别；cidr、ua_hash、ip_tag、query_names_hash 等其它维度一律丢弃。
// 结果按维度、值升序，确定性；dropped 是丢弃的条件数。
func SignatureConds(conds [][2]string) (out [][2]string, dropped int) {
	seen := map[[2]string]bool{}
	for _, c := range conds {
		dim, value := strings.ToLower(strings.TrimSpace(c[0])), strings.TrimSpace(c[1])
		var mapped [2]string
		switch {
		case value == "":
			dropped++
			continue
		case signatureKeep[dim]:
			mapped = [2]string{dim, value}
		case signatureBuckets[dim] != "":
			mapped = [2]string{signatureBuckets[dim], strings.ToLower(value)}
		case dim == "header_order_hash":
			sum := sha256.Sum256([]byte("cdnca-rule-intel-header-order/v1\x00" + strings.ToLower(value)))
			mapped = [2]string{dim, hex.EncodeToString(sum[:])}
		case dim == "path_template":
			class := PathClass(value)
			if class == "" {
				dropped++
				continue
			}
			mapped = [2]string{cluster.DimPathClass, class}
		default:
			dropped++
			continue
		}
		if validateCond(mapped[0], mapped[1]) != nil {
			dropped++
			continue
		}
		if !seen[mapped] {
			seen[mapped] = true
			out = append(out, mapped)
		}
	}
	sortPairs(out)
	return out, dropped
}

func sortPairs(pairs [][2]string) {
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && (pairs[j][0] < pairs[j-1][0] || pairs[j][0] == pairs[j-1][0] && pairs[j][1] < pairs[j-1][1]); j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
}
