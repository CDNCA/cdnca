package dnsproviderremote

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// provinceLineGolden is every province+carrier line with the provider codes
// copied from the sources in province_lines.go (阿里云 pubz-operator-line,
// 华为云 GoEdge/dnsmgr 线路表, DNS.LA allLineList, DNSPod 线路说明), not
// derived from the table under test.
var provinceLineGolden = []struct{ province, carrier, line, aliyun, huawei, dnsLA string }{
	{"北京", "telecom", "北京电信", "cn_telecom_beijing", "Dianxin_Beijing", "84613320799429632"},
	{"北京", "unicom", "北京联通", "cn_unicom_beijing", "Liantong_Beijing", "84613320736515072"},
	{"北京", "mobile", "北京移动", "cn_mobile_beijing", "Yidong_Beijing", "84613323240514560"},
	{"天津", "telecom", "天津电信", "cn_telecom_tianjin", "Dianxin_Tianjin", "84613321172722688"},
	{"天津", "unicom", "天津联通", "cn_unicom_tianjin", "Liantong_Tianjin", "84613321097225216"},
	{"天津", "mobile", "天津移动", "cn_mobile_tianjin", "Yidong_Tianjin", "84613323278263296"},
	{"河北", "telecom", "河北电信", "cn_telecom_hebei", "Dianxin_Hebei", "84613321709593600"},
	{"河北", "unicom", "河北联通", "cn_unicom_hebei", "Liantong_Hebei", "84613321659261952"},
	{"河北", "mobile", "河北移动", "cn_mobile_hebei", "Yidong_Hebei", "84613323341177856"},
	{"山西", "telecom", "山西电信", "cn_telecom_shanxi", "Dianxin_Shanxi", "84613321889948672"},
	{"山西", "unicom", "山西联通", "cn_unicom_shanxi", "Liantong_Shanxi", "84613321831228416"},
	{"山西", "mobile", "山西移动", "cn_mobile_shanxi", "Yidong_Shanxi", "84613323353760768"},
	{"内蒙古", "telecom", "内蒙电信", "cn_telecom_neimenggu", "Dianxin_Neimenggu", "84613322045137920"},
	{"内蒙古", "unicom", "内蒙联通", "cn_unicom_neimenggu", "Liantong_Neimenggu", "84613321982223360"},
	{"内蒙古", "mobile", "内蒙移动", "cn_mobile_neimenggu", "Yidong_Neimenggu", "84613323370537984"},
	{"辽宁", "telecom", "辽宁电信", "cn_telecom_liaoning", "Dianxin_Liaoning", "84613321613124608"},
	{"辽宁", "unicom", "辽宁联通", "cn_unicom_liaoning", "Liantong_Liaoning", "84613321562792960"},
	{"辽宁", "mobile", "辽宁移动", "cn_mobile_liaoning", "Yidong_Liaoning", "84613323328594944"},
	{"吉林", "telecom", "吉林电信", "cn_telecom_jilin", "Dianxin_Jilin", "84613321487295488"},
	{"吉林", "unicom", "吉林联通", "cn_unicom_jilin", "Liantong_Jilin", "84613321441158144"},
	{"吉林", "mobile", "吉林移动", "cn_mobile_jilin", "Yidong_Jilin", "84613323316012032"},
	{"黑龙江", "telecom", "黑龙江电信", "cn_telecom_heilongjiang", "Dianxin_Heilongjiang", "84613321365660672"},
	{"黑龙江", "unicom", "黑龙江联通", "cn_unicom_heilongjiang", "Liantong_Heilongjiang", "84613321315329024"},
	{"黑龙江", "mobile", "黑龙江移动", "cn_mobile_heilongjiang", "Yidong_Heilongjiang", "84613323303429120"},
	{"上海", "telecom", "上海电信", "cn_telecom_shanghai", "Dianxin_Shanghai", "84613320933647360"},
	{"上海", "unicom", "上海联通", "cn_unicom_shanghai", "Liantong_Shanghai", "84613320866538496"},
	{"上海", "mobile", "上海移动", "cn_mobile_shanghai", "Yidong_Shanghai", "84613323261486080"},
	{"江苏", "telecom", "江苏电信", "cn_telecom_jiangsu", "Dianxin_Jiangsu", "84613322728809472"},
	{"江苏", "unicom", "江苏联通", "cn_unicom_jiangsu", "Liantong_Jiangsu", "84613322712032256"},
	{"江苏", "mobile", "江苏移动", "cn_mobile_jiangsu", "Yidong_Jiangsu", "84613323399898112"},
	{"浙江", "telecom", "浙江电信", "cn_telecom_zhejiang", "Dianxin_Zhejiang", "84613322783335424"},
	{"浙江", "unicom", "浙江联通", "cn_unicom_zhejiang", "Liantong_Zhejiang", "84613322766558208"},
	{"浙江", "mobile", "浙江移动", "cn_mobile_zhejiang", "Yidong_Zhejiang", "84613323420869632"},
	{"安徽", "telecom", "安徽电信", "cn_telecom_anhui", "Dianxin_Anhui", "84613322753975296"},
	{"安徽", "unicom", "安徽联通", "cn_unicom_anhui", "Liantong_Anhui", "84613322745586688"},
	{"安徽", "mobile", "安徽移动", "cn_mobile_anhui", "Yidong_Anhui", "84613323408286720"},
	{"福建", "telecom", "福建电信", "cn_telecom_fujian", "Dianxin_Fujian", "84613322842055680"},
	{"福建", "unicom", "福建联通", "cn_unicom_fujian", "Liantong_Fujian", "84613322829472768"},
	{"福建", "mobile", "福建移动", "cn_mobile_fujian", "Yidong_Fujian", "84613323446035456"},
	{"江西", "telecom", "江西电信", "cn_telecom_jiangxi", "Dianxin_Jiangxi", "84613322812695552"},
	{"江西", "unicom", "江西联通", "cn_unicom_jiangxi", "Liantong_Jiangxi", "84613322795918336"},
	{"江西", "mobile", "江西移动", "cn_mobile_jiangxi", "Yidong_Jiangxi", "84613323433452544"},
	{"山东", "telecom", "山东电信", "cn_telecom_shandong", "Dianxin_Shandong", "84613322699449344"},
	{"山东", "unicom", "山东联通", "cn_unicom_shandong", "Liantong_Shandong", "84613322112246784"},
	{"山东", "mobile", "山东移动", "cn_mobile_shandong", "Yidong_Shandong", "84613323383120896"},
	{"河南", "telecom", "河南电信", "cn_telecom_henan", "Dianxin_Henan", "84613320589714432"},
	{"河南", "unicom", "河南联通", "cn_unicom_henan", "Liantong_Henan", "84613320530994176"},
	{"河南", "mobile", "河南移动", "cn_mobile_henan", "Yidong_Henan", "84613323248903168"},
	{"湖北", "telecom", "湖北电信", "cn_telecom_hubei", "Dianxin_Hubei", "84613322863027200"},
	{"湖北", "unicom", "湖北联通", "cn_unicom_hubei", "Liantong_Hubei", "84613322854638592"},
	{"湖北", "mobile", "湖北移动", "cn_mobile_hubei", "Yidong_Hubei", "84613323467006976"},
	{"湖南", "telecom", "湖南电信", "cn_telecom_hunan", "Dianxin_Hunan", "84613322888193024"},
	{"湖南", "unicom", "湖南联通", "cn_unicom_hunan", "Liantong_Hunan", "84613322879804416"},
	{"湖南", "mobile", "湖南移动", "cn_mobile_hunan", "Yidong_Hunan", "84613323475395584"},
	{"广东", "telecom", "广东电信", "cn_telecom_guangdong", "Dianxin_Guangdong", "84613322917553152"},
	{"广东", "unicom", "广东联通", "cn_unicom_guangdong", "Liantong_Guangdong", "84613322904970240"},
	{"广东", "mobile", "广东移动", "cn_mobile_guangdong", "Yidong_Guangdong", "84613323487978496"},
	{"广西", "telecom", "广西电信", "cn_telecom_guangxi", "Dianxin_Guangxi", "84613322980467712"},
	{"广西", "unicom", "广西联通", "cn_unicom_guangxi", "Liantong_Guangxi", "84613322967884800"},
	{"广西", "mobile", "广西移动", "cn_mobile_guangxi", "Yidong_Guangxi", "84613323517338624"},
	{"海南", "telecom", "海南电信", "cn_telecom_hainan", "Dianxin_Hainan", "84613322951107584"},
	{"海南", "unicom", "海南联通", "cn_unicom_hainan", "Liantong_Hainan", "84613322934330368"},
	{"海南", "mobile", "海南移动", "cn_mobile_hainan", "Yidong_Hainan", "84613323504755712"},
	{"重庆", "telecom", "重庆电信", "cn_telecom_chongqing", "Dianxin_Chongqing", "84613321269191680"},
	{"重庆", "unicom", "重庆联通", "cn_unicom_chongqing", "Liantong_Chongqing", "84613321218860032"},
	{"重庆", "mobile", "重庆移动", "cn_mobile_chongqing", "Yidong_Chongqing", "84613323290846208"},
	{"四川", "telecom", "四川电信", "cn_telecom_sichuan", "Dianxin_Sichuan", "84613323005633536"},
	{"四川", "unicom", "四川联通", "cn_unicom_sichuan", "Liantong_Sichuan", "84613322997244928"},
	{"四川", "mobile", "四川移动", "cn_mobile_sichuan", "Yidong_Sichuan", "84613323529921536"},
	{"贵州", "telecom", "贵州电信", "cn_telecom_guizhou", "Dianxin_Guizhou", "84613323043382272"},
	{"贵州", "unicom", "贵州联通", "cn_unicom_guizhou", "Liantong_Guizhou", "84613323026605056"},
	{"贵州", "mobile", "贵州移动", "cn_mobile_guizhou", "Yidong_Guizhou", "84613323538310144"},
	{"云南", "telecom", "云南电信", "cn_telecom_yunnan", "Dianxin_Yunnan", "84613323068548096"},
	{"云南", "unicom", "云南联通", "cn_unicom_yunnan", "Liantong_Yunnan", "84613323055965184"},
	{"云南", "mobile", "云南移动", "cn_mobile_yunnan", "Yidong_Yunnan", "84613323555087360"},
	{"西藏", "telecom", "西藏电信", "cn_telecom_xizang", "Dianxin_Xizang", "84613323093713920"},
	{"西藏", "unicom", "西藏联通", "cn_unicom_xizang", "Liantong_Xizang", "84613323076936704"},
	{"西藏", "mobile", "西藏移动", "cn_mobile_xizang", "Yidong_Xizang", "84613323567670272"},
	{"陕西", "telecom", "陕西电信", "cn_telecom_shaanxi", "Dianxin_Shaanxi", "84613323118879744"},
	{"陕西", "unicom", "陕西联通", "cn_unicom_shaanxi", "Liantong_Shaanxi", "84613323102102528"},
	{"陕西", "mobile", "陕西移动", "cn_mobile_shaanxi", "Yidong_Shaanxi", "84613323580253184"},
	{"甘肃", "telecom", "甘肃电信", "cn_telecom_gansu", "Dianxin_Gansu", "84613323169211392"},
	{"甘肃", "unicom", "甘肃联通", "cn_unicom_gansu", "Liantong_Gansu", "84613323160822784"},
	{"甘肃", "mobile", "甘肃移动", "cn_mobile_gansu", "Yidong_Gansu", "84613323605419008"},
	{"青海", "telecom", "青海电信", "cn_telecom_qinghai", "Dianxin_Qinghai", "84613323198571520"},
	{"青海", "unicom", "青海联通", "cn_unicom_qinghai", "Liantong_Qinghai", "84613323185988608"},
	{"青海", "mobile", "青海移动", "cn_mobile_qinghai", "Yidong_Qinghai", "84613323622196224"},
	{"宁夏", "telecom", "宁夏电信", "cn_telecom_ningxia", "Dianxin_Ningxia", "84613323144045568"},
	{"宁夏", "unicom", "宁夏联通", "cn_unicom_ningxia", "Liantong_Ningxia", "84613323135656960"},
	{"宁夏", "mobile", "宁夏移动", "cn_mobile_ningxia", "Yidong_Ningxia", "84613323588641792"},
	{"新疆", "telecom", "新疆电信", "cn_telecom_xinjiang", "Dianxin_Xinjiang", "84613323227931648"},
	{"新疆", "unicom", "新疆联通", "cn_unicom_xinjiang", "Liantong_Xinjiang", "84613323211154432"},
	{"新疆", "mobile", "新疆移动", "cn_mobile_xinjiang", "Yidong_Xinjiang", "84613323634779136"},
}

func TestProvinceCarrierLineFullTable(t *testing.T) {
	if len(provinceLineGolden) != 93 {
		t.Fatalf("golden rows = %d, want 31×3", len(provinceLineGolden))
	}
	for _, row := range provinceLineGolden {
		line, ok := ProvinceCarrierLine(row.province, row.carrier)
		if !ok || line != row.line {
			t.Fatalf("ProvinceCarrierLine(%s, %s) = (%q, %v), want %q", row.province, row.carrier, line, ok, row.line)
		}
		for provider, want := range map[string]string{providerAliyun: row.aliyun, providerHuawei: row.huawei,
			providerDNSLA: row.dnsLA, providerDNSPodCN: row.line} {
			if code, ok := providerLineCode(provider, line); !ok || code != want {
				t.Fatalf("%s %s = (%q, %v), want %q", provider, line, code, ok, want)
			}
		}
		// Read back maps to the same unified line.
		if aliyunLine(row.aliyun) != line || huaweiLine(row.huawei) != line || dnsLALine(row.dnsLA, "") != line {
			t.Fatalf("read-back of %s: aliyun=%q huawei=%q dns_la=%q", line,
				aliyunLine(row.aliyun), huaweiLine(row.huawei), dnsLALine(row.dnsLA, ""))
		}
	}
	// Every provider code is used once: no two lines share a code.
	for _, provider := range []string{providerAliyun, providerHuawei, providerDNSLA} {
		seen := map[string]string{}
		for line, code := range providerLineCodes[provider] {
			if other, duplicate := seen[code]; duplicate {
				t.Fatalf("%s code %q on %q and %q", provider, code, line, other)
			}
			seen[code] = line
		}
		if len(seen) != 5+93 {
			t.Fatalf("%s has %d codes, want 98", provider, len(seen))
		}
	}
}

func TestProvinceCarrierLineAliasesAndUnknown(t *testing.T) {
	for _, test := range []struct{ province, carrier, want string }{
		{"广西壮族自治区", "telecom", "广西电信"},
		{"内蒙古", "mobile", "内蒙移动"},
		{"内蒙古自治区", "unicom", "内蒙联通"},
		{"内蒙", "telecom", "内蒙电信"},
		{"新疆维吾尔自治区", "unicom", "新疆联通"},
		{"宁夏回族自治区", "mobile", "宁夏移动"},
		{"西藏自治区", "telecom", "西藏电信"},
		{"广东省", "mobile", "广东移动"},
		{"北京市", "unicom", "北京联通"},
		{" 黑龙江省 ", "telecom", "黑龙江电信"},
		{"陕西", "telecom", "陕西电信"},
		{"山西省", "telecom", "山西电信"},
	} {
		if line, ok := ProvinceCarrierLine(test.province, test.carrier); !ok || line != test.want {
			t.Fatalf("ProvinceCarrierLine(%q, %q) = (%q, %v), want %q", test.province, test.carrier, line, ok, test.want)
		}
	}
	for _, test := range []struct{ province, carrier string }{
		{"香港", "telecom"}, {"中国香港", "mobile"}, {"澳门", "unicom"}, {"台湾", "telecom"},
		{"", "telecom"}, {"省", "telecom"}, {"市", "mobile"}, {"华南", "telecom"}, {"Guangdong", "telecom"},
		{"广东", "电信"}, {"广东", "overseas"}, {"广东", ""}, {"广东", "Telecom"}, {"广东", "tietong"},
	} {
		if line, ok := ProvinceCarrierLine(test.province, test.carrier); ok {
			t.Fatalf("ProvinceCarrierLine(%q, %q) = %q, want not ok", test.province, test.carrier, line)
		}
	}
}

func TestSupportsProvinceLines(t *testing.T) {
	want := map[string]bool{providerAliyun: true, providerHuawei: true, providerDNSLA: true, providerDNSPodCN: true}
	for _, capability := range ProviderCapabilityMatrix() {
		provider := capability.ProviderType
		if SupportsProvinceLines(provider) != want[provider] {
			t.Fatalf("SupportsProvinceLines(%s) = %v", provider, !want[provider])
		}
		lines := SupportedLines(provider)
		config := completeTestConfig(reconcileHTTPProviderConfig(provider))
		if provider == providerDNSCom {
			config.Credentials[DNSComPlanField] = DNSComPlanFlagship
		}
		for _, row := range provinceLineGolden {
			if slices.Contains(lines, row.line) != want[provider] {
				t.Fatalf("SupportedLines(%s) contains %s = %v", provider, row.line, !want[provider])
			}
			operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: row.line}
			if err := validateProviderReconcileOperation(config, operation); (err == nil) != want[provider] {
				t.Fatalf("%s %s validation = %v", provider, row.line, err)
			}
		}
	}
	if SupportsProvinceLines("dnsdun") {
		t.Fatal("unknown provider supports province lines")
	}
}

// The codes reach the provider APIs' documented fields: Aliyun "Line",
// Huawei record set "line", DNS.LA "lineId".
func TestProvinceLinesOnTheWire(t *testing.T) {
	line, _ := ProvinceCarrierLine("广东", "mobile")
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line}

	aliyun, aliyunRemote, aliyunConfig := newAliyunLineRemote(t)
	if _, err := aliyunRemote.Mutate(t.Context(), aliyunConfig, create); err != nil {
		t.Fatalf("aliyun create error = %v", err)
	}
	if len(aliyun.mutations) != 1 || aliyun.mutations[0].Get("Line") != "cn_mobile_guangdong" {
		t.Fatalf("aliyun mutations = %v", aliyun.mutations)
	}

	huawei, huaweiRemote, huaweiConfig := newHuaweiLineRemote(t)
	applyHuaweiLine(t, huaweiRemote, huaweiConfig, create)
	if huawei.set("Yidong_Guangdong") == nil {
		t.Fatal("huawei record set on Yidong_Guangdong missing")
	}

	dnsLA, dnsLARemote, dnsLAConfig := newDNSLALineRemote(t)
	if _, err := dnsLARemote.Mutate(t.Context(), dnsLAConfig, create); err != nil {
		t.Fatalf("dns_la create error = %v", err)
	}
	var body map[string]any
	if len(dnsLA.bodies) != 1 || json.Unmarshal([]byte(dnsLA.bodies[0]), &body) != nil || body["lineId"] != "84613323487978496" {
		t.Fatalf("dns_la bodies = %v", dnsLA.bodies)
	}
}
