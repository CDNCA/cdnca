package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

// 「转发列表」下的「分组管理」「默认设置」两个页签走独立接口，
// 本测试覆盖随之新增的 7 条路由：分组 CRUD、默认设置读写，以及默认设置在新建转发时按范围带入。
func TestL4StreamGroupsAndDefaultsHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	platform, err := identity.NewStore(pool).BootstrapPlatformUser(
		context.Background(), "group-admin", "Group Admin", passwordHash, "bootstrap-group-admin",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenant := insertL4Tenant(t, pool, "Group Tenant", "group-owner", passwordHash, []string{"streams.read", "streams.manage"})
	other := insertL4Tenant(t, pool, "Group Other", "group-other", passwordHash, []string{"streams.read", "streams.manage"})
	if platform.UserID == uuid.Nil {
		t.Fatal("platform principal was not created")
	}

	tokens, err := identity.NewTokenManager("l4-group-integration-test-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	// 缺少 APIKeyPepper 时 Server 只留下 initializationErr、identity 为空，任何登录都会 panic。
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	adminAuth, _ := loginOK(t, client, server.URL, "group-admin")
	ownerAuth, _ := loginOK(t, client, server.URL, "group-owner")
	otherAuth, _ := loginOK(t, client, server.URL, "group-other")
	installL4AutomaticPolicy(t, pool, tenant)
	installL4AutomaticPolicy(t, pool, other)

	t.Run("分组 CRUD", func(t *testing.T) {
		first := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-create-1", streamGroupRequest{Name: "华东", Remark: "上海机房"})
		if first.DisplayID != "1" || first.Revision != 1 || first.Name != "华东" || first.Remark != "上海机房" ||
			first.ScopeID != tenant.scopeID || first.StreamCount != 0 || first.Owner == nil || first.Owner.ID != tenant.userID {
			t.Fatalf("created group = %#v", first)
		}
		second := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-create-2", streamGroupRequest{Name: "华南"})
		if second.DisplayID != "2" {
			t.Fatalf("second group display_id = %q, want 2", second.DisplayID)
		}
		// 重放同一幂等键必须返回同一分组，而不是再建一个。
		replayed := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-create-1", streamGroupRequest{Name: "华东", Remark: "上海机房"})
		if replayed.ID != first.ID || replayed.DisplayID != first.DisplayID {
			t.Fatalf("replayed group create = %#v, want %s", replayed, first.ID)
		}
		// 同名冲突以 lower(name) 判定，只有 ASCII 名才能验证大小写不敏感。
		third := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-create-3", streamGroupRequest{Name: "Edge"})
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/stream-groups", ownerAuth.AccessToken, "group-create-dup", "",
			streamGroupRequest{Name: "edge"}),
			http.StatusConflict, "stream_group_name_conflict", "")
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/stream-groups", ownerAuth.AccessToken, "group-create-blank", "",
			streamGroupRequest{Name: "   "}),
			http.StatusBadRequest, "validation_error", "")
		// 未知字段停在 JSON 解码（DisallowUnknownFields）上，契约码是 invalid_request。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/stream-groups", ownerAuth.AccessToken, "group-create-unknown-field", "",
			map[string]any{"name": "未知字段", "unexpected": true}),
			http.StatusBadRequest, "invalid_request", "")

		// 路径 ID 非 UUID 与缺 If-Match 的写请求都停在请求校验上。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPatch,
			"/v1/stream-groups/not-a-uuid", ownerAuth.AccessToken, "group-patch-bad-id", `"1"`,
			streamGroupRequest{ExpectedRevision: 1, Name: "改名"}),
			http.StatusBadRequest, "validation_error", "")
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPatch,
			"/v1/stream-groups/"+first.ID.String(), ownerAuth.AccessToken, "group-patch-no-match", "",
			streamGroupRequest{ExpectedRevision: 1, Name: "华东二区"}),
			http.StatusBadRequest, "validation_error", "")

		list := listStreamGroups(t, client, server.URL+"/v1/stream-groups?page=1&limit=20", ownerAuth.AccessToken)
		if list.Total != 3 || len(list.Items) != 3 || list.Page != 1 || list.Limit != 20 {
			t.Fatalf("owner group list = %#v", list)
		}
		if list.Items[0].ID != first.ID || list.Items[1].ID != second.ID || list.Items[2].ID != third.ID {
			t.Fatalf("group list order = %#v", list.Items)
		}
		if otherList := listStreamGroups(t, client, server.URL+"/v1/stream-groups?page=1&limit=20", otherAuth.AccessToken); otherList.Total != 0 {
			t.Fatalf("other tenant group list = %#v", otherList)
		}
		searched := listStreamGroups(t, client, server.URL+"/v1/stream-groups?page=1&limit=20&search=华南", ownerAuth.AccessToken)
		if searched.Total != 1 || searched.Items[0].ID != second.ID {
			t.Fatalf("searched group list = %#v", searched)
		}
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodGet,
			"/v1/stream-groups?page=1&limit=20&unknown=1", ownerAuth.AccessToken, "", "", nil),
			http.StatusBadRequest, "validation_error", "")

		// 跨租户写：对方名下的分组对外表现为不存在。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPatch,
			"/v1/stream-groups/"+first.ID.String(), otherAuth.AccessToken, "group-patch-foreign", `"1"`,
			streamGroupRequest{ExpectedRevision: 1, Name: "越权"}),
			http.StatusNotFound, "stream_group_not_found", "")

		updated := updateStreamGroup(t, client, server.URL, first.ID, ownerAuth.AccessToken, "group-update-1",
			streamGroupRequest{ExpectedRevision: 1, Name: "华东二区", Remark: "浦东"}, 1)
		if updated.Revision != 2 || updated.Name != "华东二区" || updated.Remark != "浦东" || updated.DisplayID != first.DisplayID {
			t.Fatalf("updated group = %#v", updated)
		}
		// revision 已推进到 2，再用 1 提交必须冲突。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPatch,
			"/v1/stream-groups/"+first.ID.String(), ownerAuth.AccessToken, "group-update-stale", `"1"`,
			streamGroupRequest{ExpectedRevision: 1, Name: "华东三区"}),
			http.StatusConflict, "version_conflict", "")
		// If-Match 与 expected_revision 必须相互一致。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPatch,
			"/v1/stream-groups/"+first.ID.String(), ownerAuth.AccessToken, "group-update-mismatch", `"2"`,
			streamGroupRequest{ExpectedRevision: 9, Name: "华东三区"}),
			http.StatusBadRequest, "validation_error", "")

		// 分组被默认设置引用时不能删除（外键 RESTRICT）。
		blocker := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-create-blocker", streamGroupRequest{Name: "被引用分组"})
		groupDefault := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-create-group-scope", streamDefaultRequest{
			SettingName: l4forward.SettingListenProtocol, Value: l4forward.ProtocolUDP,
			ScopeName: l4forward.DefaultScopeGroup, GroupID: &blocker.ID,
		})
		if groupDefault.ScopeName != l4forward.DefaultScopeGroup || groupDefault.Group == nil ||
			groupDefault.Group.ID != blocker.ID || groupDefault.Group.Name != "被引用分组" ||
			groupDefault.Value != l4forward.ProtocolUDP || groupDefault.Owner == nil || groupDefault.Owner.ID != tenant.userID {
			t.Fatalf("created group-scoped default = %#v", groupDefault)
		}
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/stream-groups/"+blocker.ID.String(), ownerAuth.AccessToken, "group-delete-in-use", `"1"`,
			streamGroupRequest{ExpectedRevision: 1}),
			http.StatusConflict, "stream_group_in_use", "")
		// 版本不符同样拒绝，且失败不推进 revision。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/stream-groups/"+blocker.ID.String(), ownerAuth.AccessToken, "group-delete-stale", `"9"`,
			streamGroupRequest{ExpectedRevision: 9}),
			http.StatusConflict, "version_conflict", "")

		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-delete-blocker", groupDefault.ID)
		deleteStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-delete-1", blocker.ID, 1)
		// 软删后同一分组对外就是不存在，且不再出现在列表里。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/stream-groups/"+blocker.ID.String(), ownerAuth.AccessToken, "group-delete-again", `"2"`,
			streamGroupRequest{ExpectedRevision: 2}),
			http.StatusNotFound, "stream_group_not_found", "")
		if list := listStreamGroups(t, client, server.URL+"/v1/stream-groups?page=1&limit=20", ownerAuth.AccessToken); list.Total != 3 {
			t.Fatalf("group list after delete = %#v", list)
		}
		// 后续子用例以「默认设置为空」为前提，这里把本用例留下的默认设置与分组清干净。
		// 分组经过上面的改名与软删，先前的列表快照里 revision 已经过期，必须重新拉一份。
		defaults := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", ownerAuth.AccessToken)
		for index, item := range defaults.Items {
			deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken,
				"default-cleanup-"+strconv.Itoa(index), item.ID)
		}
		remaining := listStreamGroups(t, client, server.URL+"/v1/stream-groups?page=1&limit=20", ownerAuth.AccessToken)
		for _, item := range remaining.Items {
			deleteStreamGroup(t, client, server.URL, ownerAuth.AccessToken,
				"group-cleanup-"+item.ID.String(), item.ID, item.Revision)
		}
	})

	t.Run("默认设置的列表与校验", func(t *testing.T) {
		// type 必须显式给出且只能等于 stream。
		for _, query := range []string{
			"/v1/user-configs?page=1&limit=20",
			"/v1/user-configs?type=site&page=1&limit=20",
		} {
			assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodGet, query, ownerAuth.AccessToken, "", "", nil),
				http.StatusBadRequest, "validation_error", "")
		}
		if list := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", ownerAuth.AccessToken); list.Total != 0 {
			t.Fatalf("empty default list = %#v", list)
		}
		if list := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", adminAuth.AccessToken); list.Total != 0 {
			t.Fatalf("platform default list = %#v", list)
		}

		// 配置项与取值受控；范围与 group_id 必须自洽。
		for name, body := range map[string]streamDefaultRequest{
			"未知配置项": {SettingName: "upstream_port", Value: "80", ScopeName: l4forward.DefaultScopeGlobal},
			"取值越界":  {SettingName: l4forward.SettingBalanceWay, Value: "least_conn", ScopeName: l4forward.DefaultScopeGlobal},
			"未知范围":  {SettingName: l4forward.SettingListenProtocol, Value: l4forward.ProtocolTCP, ScopeName: "site"},
		} {
			assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
				"/v1/user-configs", ownerAuth.AccessToken, "default-invalid-"+name, "", body),
				http.StatusBadRequest, "validation_error", "")
		}
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/user-configs", ownerAuth.AccessToken, "default-group-no-id", "",
			streamDefaultRequest{SettingName: l4forward.SettingListenProtocol,
				Value: l4forward.ProtocolTCP, ScopeName: l4forward.DefaultScopeGroup}),
			http.StatusBadRequest, "validation_error", "")
		orphan := uuid.New()
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/user-configs", ownerAuth.AccessToken, "default-group-orphan", "",
			streamDefaultRequest{SettingName: l4forward.SettingListenProtocol,
				Value: l4forward.ProtocolTCP, ScopeName: l4forward.DefaultScopeGroup, GroupID: &orphan}),
			http.StatusNotFound, "stream_group_not_found", "")

		global := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-create-global", streamDefaultRequest{
			SettingName: l4forward.SettingListenProtocol,
			Value:       l4forward.ProtocolTCP, ScopeName: l4forward.DefaultScopeGlobal,
		})
		// display_id 由分配器按租户发放，前面的失败创建已经推高过序号，这里只断言它被真实写入
		// 且为正整数——精确值属于分配器契约，由分组用例里首次创建的那条断言。
		if displayID, err := strconv.ParseInt(global.DisplayID, 10, 64); err != nil || displayID <= 0 {
			t.Fatalf("created global default display_id = %q", global.DisplayID)
		}
		if global.ScopeName != l4forward.DefaultScopeGlobal || global.Group != nil || global.Value != l4forward.ProtocolTCP ||
			global.Owner == nil || global.Owner.ID != tenant.userID {
			t.Fatalf("created global default = %#v", global)
		}
		// 同一用户、同一设置项的全局默认至多一条。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/user-configs", ownerAuth.AccessToken, "default-create-global-dup", "",
			streamDefaultRequest{SettingName: l4forward.SettingListenProtocol,
				Value: l4forward.ProtocolUDP, ScopeName: l4forward.DefaultScopeGlobal}),
			http.StatusConflict, "stream_name_conflict", "")
		list := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", ownerAuth.AccessToken)
		if list.Total != 1 || len(list.Items) != 1 || list.Items[0].ID != global.ID ||
			list.Items[0].SettingName != l4forward.SettingListenProtocol {
			t.Fatalf("owner default list = %#v", list)
		}
		if otherList := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", otherAuth.AccessToken); otherList.Total != 0 {
			t.Fatalf("other tenant default list = %#v", otherList)
		}
		searched := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20&search=listen", ownerAuth.AccessToken)
		if searched.Total != 1 {
			t.Fatalf("searched default list = %#v", searched)
		}

		// 非 UUID 的路径 ID 停在请求校验上。
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/user-configs/not-a-uuid", ownerAuth.AccessToken, "default-delete-bad-id", "", nil),
			http.StatusBadRequest, "validation_error", "")
		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-delete-global", global.ID)
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/user-configs/"+global.ID.String(), ownerAuth.AccessToken, "default-delete-global-again", "", nil),
			http.StatusNotFound, "stream_default_not_found", "")
		replacement := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-create-replacement", streamDefaultRequest{
			SettingName: l4forward.SettingListenProtocol,
			Value:       l4forward.ProtocolUDP, ScopeName: l4forward.DefaultScopeGlobal,
		})
		conflict := rawStreamGroupRequest(t, client, server.URL, http.MethodDelete,
			"/v1/user-configs/"+replacement.ID.String(), ownerAuth.AccessToken, "default-delete-global", "", nil)
		assertError(t, conflict, http.StatusConflict, "idempotency_conflict", "")
		conflict.Body.Close()
		retained := listStreamDefaults(t, client, server.URL+"/v1/user-configs?type=stream&page=1&limit=20", ownerAuth.AccessToken)
		if retained.Total != 1 || len(retained.Items) != 1 || retained.Items[0].ID != replacement.ID {
			t.Fatalf("conflicting delete changed defaults: %#v", retained)
		}
		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "default-delete-replacement", replacement.ID)
	})

	t.Run("默认设置在建转发时按范围带入", func(t *testing.T) {
		group := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-defaults-target", streamGroupRequest{Name: "默认值分组"})
		balanceDefault := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-bring-balance", streamDefaultRequest{
			SettingName: l4forward.SettingBalanceWay,
			Value:       l4forward.BalanceWayIPHash,
			ScopeName:   l4forward.DefaultScopeGlobal,
		})
		// proxy_protocol 的带入值要能同时满足 proxy_protocol_inbound 与 geo 的可信代理配对校验。
		proxyDefault := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-bring-proxy", streamDefaultRequest{
			SettingName: l4forward.SettingProxyProtocol,
			Value:       l4forward.DefaultValueDisabled,
			ScopeName:   l4forward.DefaultScopeGlobal,
		})
		// 分组级默认覆盖同级全局默认：同名设置项上分组范围必须赢。
		groupDefault := createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-bring-group", streamDefaultRequest{
			SettingName: l4forward.SettingListenProtocol,
			Value:       l4forward.ProtocolUDP,
			ScopeName:   l4forward.DefaultScopeGroup,
			GroupID:     &group.ID,
		})
		createStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-bring-group-protocol", streamDefaultRequest{
			SettingName: l4forward.SettingListenProtocol,
			Value:       l4forward.ProtocolTCP,
			ScopeName:   l4forward.DefaultScopeGlobal,
		})

		// 未选分组：协议取全局默认 tcp，负载方式取全局默认 ip_hash。
		globalFields := validStreamFields(tenant, "默认值-全局", l4forward.ProtocolTCP, 18300, "192.0.2.30")
		globalFields.Protocol = ""
		globalFields.BalanceWay = ""
		globalFields.ProxyProtocolV1 = false
		globalApplied := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "stream-defaults-global",
			createStreamRequest{Fields: globalFields})
		if globalApplied.Protocol != l4forward.ProtocolTCP || globalApplied.BalanceWay != l4forward.BalanceWayIPHash ||
			globalApplied.ProxyProtocolInbound || globalApplied.ProxyProtocolV1 {
			t.Fatalf("global defaults were not applied: %#v", globalApplied)
		}
		if len(globalApplied.Groups) != 0 {
			t.Fatalf("stream without groups reported groups: %#v", globalApplied.Groups)
		}

		// 选了分组：分组默认把协议改成 udp，负载方式仍取全局默认。
		groupFields := validStreamFields(tenant, "默认值-分组", l4forward.ProtocolTCP, 18301, "192.0.2.31")
		groupFields.Protocol = ""
		groupFields.BalanceWay = ""
		groupFields.ProxyProtocolV1 = false
		groupApplied := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "stream-defaults-group",
			createStreamRequest{Fields: groupFields, GroupIDs: []string{group.ID.String()}})
		if groupApplied.Protocol != l4forward.ProtocolUDP || groupApplied.BalanceWay != l4forward.BalanceWayIPHash {
			t.Fatalf("group defaults did not override global defaults: %#v", groupApplied)
		}
		if len(groupApplied.Groups) != 1 || groupApplied.Groups[0].ID != group.ID ||
			groupApplied.Groups[0].Name != "默认值分组" {
			t.Fatalf("stream group references = %#v", groupApplied.Groups)
		}
		if fetched := getL4Forward(t, client, server.URL, groupApplied.ID, ownerAuth.AccessToken); len(fetched.Groups) != 1 ||
			fetched.Groups[0].ID != group.ID {
			t.Fatalf("fetched group references = %#v", fetched.Groups)
		}

		// L4-DEFAULT-01：新建草稿读取的生效默认与建转发同一解析（全局→分组覆盖），proxy 默认原样返回。
		effective := func(query string) l4forward.FieldDefaults {
			t.Helper()
			response := l4Request(t, client, http.MethodGet, server.URL+"/v1/user-configs/effective?type=stream"+query, nil, ownerAuth.AccessToken, "", "")
			var item l4forward.FieldDefaults
			decodeResponse(t, response, http.StatusOK, &item)
			response.Body.Close()
			return item
		}
		if global := effective(""); global.Protocol == nil || *global.Protocol != l4forward.ProtocolTCP ||
			global.BalanceWay == nil || *global.BalanceWay != l4forward.BalanceWayIPHash ||
			global.ProxyProtocolInbound == nil || *global.ProxyProtocolInbound {
			t.Fatalf("effective global defaults = %#v", global)
		}
		if grouped := effective("&group_id=" + group.ID.String()); grouped.Protocol == nil || *grouped.Protocol != l4forward.ProtocolUDP ||
			grouped.BalanceWay == nil || *grouped.BalanceWay != l4forward.BalanceWayIPHash {
			t.Fatalf("effective group defaults = %#v", grouped)
		}
		// 租户不能读别人的默认。
		other := l4Request(t, client, http.MethodGet, server.URL+"/v1/user-configs/effective?type=stream&owner_id="+uuid.NewString(), nil, ownerAuth.AccessToken, "", "")
		if other.StatusCode != http.StatusForbidden {
			t.Fatalf("effective defaults of another owner status = %d, want 403", other.StatusCode)
		}
		other.Body.Close()

		// 成员关系变更必须显式推进 scope 版本，否则下发的边缘配置不会更新。
		var before, after int64
		if err := pool.QueryRow(context.Background(),
			`SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID).Scan(&before); err != nil {
			t.Fatalf("load edge configuration scope revision: %v", err)
		}
		explicit := validStreamFields(tenant, "默认值-显式", l4forward.ProtocolTCP, 18302, "192.0.2.32")
		explicit.ProxyProtocolV1 = false
		explicitApplied := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "stream-defaults-explicit",
			createStreamRequest{Fields: explicit, GroupIDs: []string{group.ID.String()}})
		if explicitApplied.Protocol != l4forward.ProtocolTCP {
			t.Fatalf("explicit protocol lost to defaults: %#v", explicitApplied)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID).Scan(&after); err != nil {
			t.Fatalf("reload edge configuration scope revision: %v", err)
		}
		if after <= before {
			t.Fatalf("edge configuration scope revision = %d, want > %d", after, before)
		}

		// 引用不存在的分组、以及别家租户的分组，都必须 404。
		stray := validStreamFields(tenant, "默认值-野分组", l4forward.ProtocolTCP, 18303, "192.0.2.33")
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/streams", ownerAuth.AccessToken, "stream-stray-group", "",
			createStreamRequest{Fields: stray, GroupIDs: []string{uuid.New().String()}}),
			http.StatusNotFound, "stream_group_not_found", "")
		foreign := createStreamGroup(t, client, server.URL, otherAuth.AccessToken, "group-foreign", streamGroupRequest{Name: "外部分组"})
		assertError(t, rawStreamGroupRequest(t, client, server.URL, http.MethodPost,
			"/v1/streams", ownerAuth.AccessToken, "stream-foreign-group", "",
			createStreamRequest{Fields: stray, GroupIDs: []string{foreign.ID.String()}}),
			http.StatusNotFound, "stream_group_not_found", "")

		// 列表页要带出「所属分组」，未选分组的行为空数组。
		list := listL4Forwards(t, client, server.URL+"/v1/streams?page=1&limit=20", ownerAuth.AccessToken)
		groupsByID := make(map[uuid.UUID][]l4forward.GroupReference, len(list.Items))
		for _, item := range list.Items {
			groupsByID[item.ID] = item.Groups
		}
		if got := groupsByID[groupApplied.ID]; len(got) != 1 || got[0].ID != group.ID {
			t.Fatalf("listed group references = %#v", got)
		}
		if got := groupsByID[globalApplied.ID]; len(got) != 0 {
			t.Fatalf("listed ungrouped references = %#v", got)
		}

		// 默认设置删除后不再带走新转发：删掉分组级协议、全局协议代理、全局负载方式，
		// 新转发必须回到各自的字段默认值。
		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-delete-group", groupDefault.ID)
		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-delete-proxy", proxyDefault.ID)
		deleteStreamDefault(t, client, server.URL, ownerAuth.AccessToken, "defaults-delete-balance", balanceDefault.ID)
		afterDelete := validStreamFields(tenant, "默认值-删除后", l4forward.ProtocolTCP, 18304, "192.0.2.34")
		afterDelete.Protocol = ""
		afterDelete.BalanceWay = ""
		afterDelete.ProxyProtocolV1 = false
		if item := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "stream-defaults-after-delete",
			createStreamRequest{Fields: afterDelete, GroupIDs: []string{group.ID.String()}}); item.Protocol != l4forward.ProtocolTCP ||
			item.BalanceWay != l4forward.BalanceWayRoundRobin || item.ProxyProtocolInbound || item.ProxyProtocolV1 {
			t.Fatalf("deleted default still applied: %#v", item)
		}
		// 删除分组会连同成员关系一起清掉，转发不再是任何分组的成员。
		deleteStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "group-delete-members", group.ID, 1)
		if fetched := getL4Forward(t, client, server.URL, groupApplied.ID, ownerAuth.AccessToken); len(fetched.Groups) != 0 {
			t.Fatalf("deleted group still referenced: %#v", fetched.Groups)
		}
	})
}

type streamGroupRequest struct {
	TargetScopeID    string `json:"target_scope_id,omitempty"`
	OwnerID          string `json:"owner_id,omitempty"`
	ExpectedRevision int64  `json:"expected_revision,omitempty"`
	Name             string `json:"name"`
	Remark           string `json:"remark,omitempty"`
}

type streamDefaultRequest struct {
	TargetScopeID string     `json:"target_scope_id,omitempty"`
	OwnerID       string     `json:"owner_id,omitempty"`
	SettingName   string     `json:"setting_name"`
	Value         string     `json:"setting_value"`
	ScopeName     string     `json:"scope_name"`
	GroupID       *uuid.UUID `json:"group_id"`
}

func rawStreamGroupRequest(
	t *testing.T, client *http.Client, baseURL, method, path, token, key, ifMatch string, body any,
) *http.Response {
	t.Helper()
	return l4Request(t, client, method, baseURL+path, body, token, key, ifMatch)
}

func createStreamGroup(t *testing.T, client *http.Client, baseURL, token, key string, body streamGroupRequest) l4forward.Group {
	t.Helper()
	response := l4Request(t, client, http.MethodPost, baseURL+"/v1/stream-groups", body, token, key, "")
	var item l4forward.Group
	decodeResponse(t, response, http.StatusCreated, &item)
	if etag := response.Header.Get("ETag"); etag != `"`+strconv.FormatInt(item.Revision, 10)+`"` {
		t.Fatalf("create group ETag = %q, want revision %d", etag, item.Revision)
	}
	response.Body.Close()
	return item
}

func updateStreamGroup(
	t *testing.T, client *http.Client, baseURL string, id uuid.UUID, token, key string, body streamGroupRequest, revision int64,
) l4forward.Group {
	t.Helper()
	response := l4Request(t, client, http.MethodPatch, baseURL+"/v1/stream-groups/"+id.String(), body, token, key,
		`"`+strconv.FormatInt(revision, 10)+`"`)
	var item l4forward.Group
	decodeResponse(t, response, http.StatusOK, &item)
	if etag := response.Header.Get("ETag"); etag != `"`+strconv.FormatInt(item.Revision, 10)+`"` {
		t.Fatalf("update group ETag = %q, want revision %d", etag, item.Revision)
	}
	response.Body.Close()
	return item
}

func deleteStreamGroup(t *testing.T, client *http.Client, baseURL, token, key string, id uuid.UUID, revision int64) {
	t.Helper()
	response := l4Request(t, client, http.MethodDelete, baseURL+"/v1/stream-groups/"+id.String(),
		streamGroupRequest{ExpectedRevision: revision}, token, key, `"`+strconv.FormatInt(revision, 10)+`"`)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete stream group status = %d, want 204", response.StatusCode)
	}
	if body, err := io.ReadAll(response.Body); err != nil || len(body) != 0 {
		t.Fatalf("delete stream group body = %q (%v)", body, err)
	}
	response.Body.Close()
}

func listStreamGroups(t *testing.T, client *http.Client, rawURL, token string) l4forward.GroupListResult {
	t.Helper()
	response := l4Request(t, client, http.MethodGet, rawURL, nil, token, "", "")
	var result l4forward.GroupListResult
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}

func createStreamDefault(t *testing.T, client *http.Client, baseURL, token, key string, body streamDefaultRequest) l4forward.UserDefault {
	t.Helper()
	response := l4Request(t, client, http.MethodPost, baseURL+"/v1/user-configs", body, token, key, "")
	var item l4forward.UserDefault
	decodeResponse(t, response, http.StatusCreated, &item)
	response.Body.Close()
	return item
}

func deleteStreamDefault(t *testing.T, client *http.Client, baseURL, token, key string, id uuid.UUID) {
	t.Helper()
	response := l4Request(t, client, http.MethodDelete, baseURL+"/v1/user-configs/"+id.String(), nil, token, key, "")
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete stream default status = %d, want 204", response.StatusCode)
	}
	response.Body.Close()
}

func listStreamDefaults(t *testing.T, client *http.Client, rawURL, token string) l4forward.UserDefaultListResult {
	t.Helper()
	response := l4Request(t, client, http.MethodGet, rawURL, nil, token, "", "")
	var result l4forward.UserDefaultListResult
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}
