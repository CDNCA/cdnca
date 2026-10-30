package icpquery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secretKey = "seller-secret-key-123"

func testClient(server *httptest.Server) *Client {
	c := New()
	c.http = server.Client()
	c.tianAPI = server.URL + "/tian"
	c.alAPI = server.URL + "/al"
	c.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return c
}

func serve(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server
}

func TestTianAPIFiledAndQueriesRegistrableDomain(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tian" || r.URL.Query().Get("key") != secretKey || r.URL.Query().Get("domain") != "example.com.cn" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"code":200,"msg":"success","result":{"domain":"example.com.cn","icp_state":"存在","icp_number":"京ICP备12345678号-1","main_name":"示例公司","icp_type":"企业"}}`))
	})
	got, err := testClient(server).Query(context.Background(), Config{Provider: ProviderTianAPI, APIKey: secretKey}, "www.EXAMPLE.com.cn")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Filed || got.Licence != "京ICP备12345678号-1" || got.Domain != "example.com.cn" || got.Subject != "示例公司" {
		t.Fatalf("got %+v", got)
	}
}

func TestTianAPIUnfiledAndErrors(t *testing.T) {
	cases := map[string]struct {
		body   string
		status Status
		err    error
	}{
		"none":      {`{"code":200,"result":{"icp_state":"暂无"}}`, Unfiled, nil},
		"empty":     {`{"code":250,"msg":"数据返回为空"}`, Unfiled, nil},
		"bad key":   {`{"code":230,"msg":"API密钥无效"}`, "", ErrCredential},
		"quota":     {`{"code":150}`, "", ErrQuota},
		"ratelimit": {`{"code":130}`, "", ErrRateLimited},
		"down":      {`{"code":110}`, "", ErrProvider},
	}
	for name, c := range cases {
		server := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(c.body)) })
		got, err := testClient(server).Query(context.Background(), Config{Provider: ProviderTianAPI, APIKey: secretKey}, "a.example.com")
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: want %v, got %v", name, c.err, err)
			}
			continue
		}
		if err != nil || got.Status != c.status {
			t.Errorf("%s: got %+v, %v", name, got, err)
		}
	}
}

func TestALAPI(t *testing.T) {
	filed := `{"request_id":"1","success":true,"message":"success","code":200,"data":{"domain":"baidu.com","is_icp":true,"main_licence":"京ICP证030173号","service_licence":"京ICP证030173号-1","unit_name":"北京百度网讯科技有限公司","nature_name":"企业"}}`
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/al" || r.URL.Query().Get("token") != secretKey {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(filed))
	})
	got, err := testClient(server).Query(context.Background(), Config{Provider: ProviderALAPI, APIKey: secretKey}, "baidu.com")
	if err != nil || got.Status != Filed || got.Licence != "京ICP证030173号-1" {
		t.Fatalf("got %+v, %v", got, err)
	}
	badToken := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"code":10002,"message":"token秘钥错误","data":null}`))
	})
	if _, err := testClient(badToken).Query(context.Background(), Config{Provider: ProviderALAPI, APIKey: secretKey}, "baidu.com"); !errors.Is(err, ErrCredential) {
		t.Fatalf("want ErrCredential, got %v", err)
	}
	unfiled := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"code":200,"data":{"domain":"x.com","is_icp":false}}`))
	})
	if got, err := testClient(unfiled).Query(context.Background(), Config{Provider: ProviderALAPI, APIKey: secretKey}, "x.com"); err != nil || got.Status != Unfiled {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestCustomProvider(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("d") != "example.org" || r.Header.Get("User-Agent") != userAgent {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"data":{"list":[{"state":"已备案","no":"粤ICP备1号"}]}}`))
	})
	cfg := Config{Provider: ProviderCustom, APIKey: secretKey, URLTemplate: server.URL + "/q?d={domain}&k={key}",
		StatusPath: "data.list.0.state", FiledValues: []string{"已备案"}, LicencePath: "data.list.0.no"}
	got, err := testClient(server).Query(context.Background(), cfg, "www.example.org")
	if err != nil || got.Status != Filed || got.Licence != "粤ICP备1号" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestCustomProviderRejectsInsecureTemplates(t *testing.T) {
	for _, template := range []string{"http://x.com/?d={domain}", "https://x.com/?k={key}", "https://u:p@x.com/{domain}", "ftp://x/{domain}"} {
		cfg := Config{Provider: ProviderCustom, APIKey: "k", URLTemplate: template, StatusPath: "a"}
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: want ErrInvalidInput, got %v", template, err)
		}
	}
}

func TestDialGuardBlocksInternalTargets(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) })
	cfg := Config{Provider: ProviderCustom, APIKey: secretKey, URLTemplate: server.URL + "/?d={domain}", StatusPath: "ok"}
	// New() keeps the guarded transport; httptest listens on 127.0.0.1.
	_, err := New().Query(context.Background(), cfg, "example.com")
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("want ErrTransport, got %v", err)
	}
	if strings.Contains(err.Error(), secretKey) {
		t.Fatal("error leaked the API key")
	}
}

func TestErrorsNeverContainKey(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	_, err := testClient(server).Query(context.Background(), Config{Provider: ProviderTianAPI, APIKey: secretKey}, "example.com")
	if err == nil || strings.Contains(err.Error(), secretKey) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.com":    "example.com",
		"a.b.example.com.cn": "example.com.cn",
		"例子.中国":              "xn--fsqu00a.xn--fiqs8s",
		"Example.COM.":       "example.com",
	}
	for in, want := range cases {
		got, err := RegistrableDomain(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*.example.com", "com", "bad_label.example.com"} {
		if _, err := RegistrableDomain(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: want ErrInvalidInput, got %v", bad, err)
		}
	}
}
