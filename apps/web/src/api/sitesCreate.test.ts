import { sitesApi, type CreateSiteRequest, type PatchSiteBasicRequest } from './sites'

// live-site D5 (10-22, real 73 console response): a site created with
// 「CNAME 分配模式：按套餐自动」 sends empty cname_mode/cname_domain; the server
// fills them from the package snapshot and starts the CNAME allocation
// (pending, task id, revision 1). The client compared them for exact equality,
// reported 「创建结果待确认」 for a site that was created, and a retry with a
// new idempotency key created a duplicate.
const request = {
  "basic": {
    "package_id": "01a16186-5aec-7363-89d5-49b5f455006e",
    "package_subscription_id": "01a16190-6b9c-79f2-8823-4550317b8d83",
    "cname_mode": "",
    "cname_domain": "",
    "cname_hostname": "",
    "package_name": "测试套餐",
    "group_id": null,
    "group_name": null,
    "domains": [
      "www.example.com"
    ],
    "http_enabled": true,
    "http_listen_ports": [
      "80"
    ],
    "https_listen_ports": [],
    "ipv6_enabled": false,
    "tls_protocols": [
      "TLSv1.2",
      "TLSv1.3"
    ],
    "origins": [
      "192.0.2.10"
    ],
    "cname": "",
    "https_enabled": false,
    "enabled": true,
    "status": "active",
    "is_default": false
  },
  "origin_pool": {
    "origins": [
      {
        "host": "192.0.2.10",
        "port": 80,
        "weight": 1,
        "enabled": true
      }
    ],
    "balance_method": "round_robin",
    "failover_tries": 1,
    "connect_timeout_ms": 3000,
    "read_timeout_ms": 30000
  }
} as CreateSiteRequest

const response = {
  "id": "01a16194-09e6-78f4-9c74-ffcbd3ae4395",
  "scope_id": "01a16190-05cc-79ae-ad1e-f6c6b0f1279c",
  "display_id": "3",
  "version": 1,
  "owner": null,
  "created_at": "2026-10-22T03:07:34.246704Z",
  "updated_at": "2026-10-22T03:07:34.246704Z",
  "lock": {
    "locked": false,
    "reason": null,
    "locked_at": null,
    "operator": null
  },
  "status_state": "normal",
  "status_code": 200,
  "status_recovery": null,
  "listener_state": {
    "ipv6_desired_enabled": false,
    "ipv6_runtime_state": "disabled"
  },
  "basic": {
    "package_id": "01a16186-5aec-7363-89d5-49b5f455006e",
    "package_subscription_id": "01a16190-6b9c-79f2-8823-4550317b8d83",
    "cname_mode": "site",
    "cname_domain": "cdn.example.net",
    "cname_hostname": "",
    "package_name": "测试套餐",
    "group_id": null,
    "group_name": null,
    "domains": [
      "www.example.com"
    ],
    "http_enabled": true,
    "http_listen_ports": [
      "80"
    ],
    "https_listen_ports": [],
    "ipv6_enabled": false,
    "origins": [
      "192.0.2.10"
    ],
    "cname": "",
    "tls_protocols": [
      "TLSv1.2",
      "TLSv1.3"
    ],
    "cname_state": "pending",
    "cname_task_id": "e7b130d1-fc15-4fdb-b5e9-81a68cb17980",
    "cname_current_revision": 1,
    "cname_lkg_revision": null,
    "https_enabled": false,
    "force_https": false,
    "https_redirect_port": 0,
    "cache_shared_across_domains": false,
    "tls_cipher_preset": "compatible",
    "tls_ocsp_stapling": true,
    "tls_client_auth": "off",
    "tls_client_ca_pem": "",
    "enabled": true,
    "status": "active",
    "sync_status": "pending",
    "is_default": false
  },
  "origin_pool": {
    "origins": [
      {
        "host": "192.0.2.10",
        "port": 80,
        "weight": 1,
        "enabled": true,
        "level": 0,
        "max_conns": 0
      }
    ],
    "balance_method": "round_robin",
    "failover_tries": 1,
    "connect_timeout_ms": 3000,
    "read_timeout_ms": 30000,
    "keepalive_enabled": true,
    "keepalive_idle_timeout_ms": 60000,
    "request_host": {
      "mode": "visitor"
    },
    "scheme": "http",
    "https_port": 443,
    "tls": {
      "trust": "system"
    },
    "follow_port": false,
    "websocket": {
      "enabled": true,
      "allowed_origins": []
    },
    "trusted_proxy_cidrs": [],
    "failback_mode": "auto",
    "health_check_path": "/",
    "follow_redirect": {
      "enabled": false,
      "max_hops": 3,
      "cross_origin": false
    }
  },
  "traffic_enforcement": null
}

function json(body: unknown, status = 201): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('sitesApi.create', () => {
  afterEach(() => vi.restoreAllMocks())

  it('accepts the package-derived CNAME allocation the server starts', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    const saved = await sitesApi.create('token', request, 'idem-1')
    expect(saved.id).toBe(response.id)
    expect(saved.basic.cname_mode).toBe('site')
    expect(saved.basic.cname_state).toBe('pending')
  })

  it('still rejects a response for different domains', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...response, basic: { ...response.basic, domains: ['other.example.com'] } }))
    await expect(sitesApi.create('token', request, 'idem-2')).rejects.toMatchObject({ status: 502 })
  })

  it('rejects a CNAME mode that differs from an explicit request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(response))
    await expect(sitesApi.create('token', { ...request, basic: { ...request.basic, cname_mode: 'package' } }, 'idem-3'))
      .rejects.toMatchObject({ status: 502 })
  })
})

// PJ-C02：sync_status 只由服务端派生（迁移 503），服务端拒收带它的写请求。编辑草稿从
// 详情展开会带上它，存下的重试请求体也可能带，发出前必须去掉。
describe('site writes never send sync_status (PJ-C02)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('drops it from a create body and a basic patch spread from a detail', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(json(response)))
    const stale = JSON.stringify({ ...request, basic: { ...request.basic, sync_status: 'synced' } })
    await sitesApi.create('token', request, 'idem-4', stale)
    const changes = { ...response.basic } as unknown as PatchSiteBasicRequest['changes']
    await sitesApi.patchBasic('token', response.id, { expected_version: 1, section: 'basic', changes }, 'idem-5')
    for (const [, init] of fetchSpy.mock.calls) {
      const body = JSON.parse(String(init?.body)) as { basic?: object; changes?: object }
      expect(body.basic ?? body.changes).not.toHaveProperty('sync_status')
    }
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })
})
