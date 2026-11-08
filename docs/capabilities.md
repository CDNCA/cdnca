# Plugins and capabilities (Community Edition)

<p align="right"><a href="capabilities.zh-CN.md">简体中文</a></p>

This page lists what the Community Edition includes: what each capability solves, where to turn it on and the main settings. Full details for every item, including the commercial edition, are on the website under [plugins and capabilities](https://www.cdnca.com/en/docs/capabilities/).

## Scheduling

### Per-line probing and smart scheduling

Nodes in a line group are probed from China Telecom, Unicom and Mobile (or per province and carrier), and visitors resolve to the few nodes with the lowest latency that are healthy and below the load limit. A line with no eligible node falls back to the carrier's national line, then the default line.

- Turn on: admin console, Nodes → Line groups, click Smart scheduling on the line group.
- Latency sources: checkpoints of the dnspup probing module, or nodes in the line group probing each other; with neither, the existing DNS configuration stays.
- Main settings: nodes per line (default 3), granularity (by carrier / by province and carrier), latency window (default 15 minutes), maximum load (default 85%).
- Details: [per-line probing and smart scheduling](https://www.cdnca.com/en/docs/capabilities/line-scheduling/)

## Node and plugin marketplaces (marketplace features roll out by version)

Register a free installation identity once on the control plane server first: `control-api community-register --account <portal account> --password-stdin`.

### Node marketplace

Subscribe to nodes other control planes list, or list your own for sale. Offers bill per day, per GB, by 95th percentile and so on, at prices the supplier sets; top-ups go straight to the supplier's own merchant account.

- Where: admin console, Marketplace → Node market.
- Details: [node market](https://www.cdnca.com/en/docs/capabilities/node-market/)

### Plugin marketplace

Get, buy and enable plugins such as rule packs, themes and DNS integrations; each purchase is bound to this control plane. Official items are not free for the Community Edition.
Feature plugins take effect once paid or claimed. Themes, rule packs, UI page plugins and external services are confirmed by the control plane administrator in My plugins; a tenant plugin is installed for all tenants or for the tenants chosen at confirmation, and tenants do nothing.

- Where: admin console, Marketplace → Plugin store.
- Details: [plugin market](https://www.cdnca.com/en/docs/capabilities/plugin-market/)

## Security

### WAF and CC protection

A WAF rule library (platform and tenant rules), CC rule sets counting by client IP, network, domain, URI, JA4, UA, Referer, header or query parameter, JS challenges, quick block, JA4 blocking and access control; CC auto-switching moves to a stricter rule group during traffic spikes.

- Where: admin console, Sites → WAF rules / CC rules / Rule packs, and the CC protection, WAF protection and Automatic defense tabs of a site.
- Official rule packs (OWASP CRS levels, advanced CC rule groups, in-house detection rules) can be bought on the plugin marketplace.
- Details: [WAF and CC protection](https://www.cdnca.com/en/docs/capabilities/waf-cc/)

### Layer-4 protection

Protection rules for TCP/UDP forwarding: judge each new connection by first-packet content, the TLS handshake name (SNI), client IP, carrier and IDC, and country, then drop, drop and ban, or allow; plus per-IP new connections per second and region limits.

- Where: admin console, Forwarding list, Protection rules of a forward.
- Details: [layer-4 protection](https://www.cdnca.com/en/docs/capabilities/l4-protection/)

### Kernel blocking and connection protection

Limit connections in the node kernel: per-client concurrency and new-connection rates, idle connection detection, malformed TCP filtering, dropping invalid packets, and syncing CC temporary bans to the kernel. Nodes pick native XDP, generic XDP or nftables automatically, in that order.

- Where: admin console, Nodes → Connection protection; per site, Firewall configuration → Firewall action policy.

### Ban list

Manual bans and the nodes' automatic WAF / CC bans per site; a release lifts a ban on every node serving the site. When a site is served by nodes subscribed in the node market, the list goes through the market to the supplier, whose nodes enforce it; each ban shows its delivery (in effect on the subscribed nodes, delivering, pending, not supported by the other side, and so on).

- Where: admin console, Sites → Ban list.
- Details: [kernel blocking and connection protection](https://www.cdnca.com/en/docs/capabilities/kernel-ban/)

## Built-in free modules

| Module | What it does | Where | More |
| --- | --- | --- | --- |
| dnspup probing | Probe origins and nodes from carrier checkpoints with your own dnspup key: per-purpose quotas and slow-down, ping/http probes and finer checkpoint selection, an area × carrier matrix with line alerts, on-demand mtr | System → dnspup probing | [Details](https://www.cdnca.com/en/docs/capabilities/probe-dnspup/) |
| IP library live updates | Pull the latest IP intelligence snapshot on a schedule with your own dnspup key | System → IP intelligence live updates (dnspup) | [Details](https://www.cdnca.com/en/docs/capabilities/ipintel-dnspup/) |
| ICP filing lookup | Check subscriber domains when an offer requires ICP filing | `MARKET_ICP_PROVIDER` and `MARKET_ICP_KEY_FILE` in the control plane's `optional.env` | [Details](https://www.cdnca.com/en/docs/capabilities/icp/) |
| SMS and email | Alibaba Cloud SMS, SUBMAIL, Alibaba Cloud DirectMail, SendGrid | System → System configuration → Mail | [Details](https://www.cdnca.com/en/docs/capabilities/sms-mail/) |

## Available in the commercial edition

These capabilities are not in the Community Edition; the commercial edition provides them. See the website:

- [Multi-CDN aggregated edge](https://www.cdnca.com/en/docs/capabilities/multi-cdn/), [cross-CDN scheduling](https://www.cdnca.com/en/docs/capabilities/cdn-scheduling/), [automatic fallback chain](https://www.cdnca.com/en/docs/capabilities/fallback-chain/)
- [Automatic defense](https://www.cdnca.com/en/docs/capabilities/auto-defense/) (the Community Edition has CC auto-switching and WAF auto-ban only), [attack auto-escalation](https://www.cdnca.com/en/docs/capabilities/escalate/)
- [SDK Shield](https://www.cdnca.com/en/docs/capabilities/sdk-shield/) (games and apps embed an SDK; first-packet token check, origin hiding)
- [Cloudflare preferred IPs](https://www.cdnca.com/en/docs/capabilities/cf-optimize/)
- [Online payments](https://www.cdnca.com/en/docs/capabilities/payments/), [billing bridge](https://www.cdnca.com/en/docs/capabilities/billing-bridge/), [migration import](https://www.cdnca.com/en/docs/capabilities/migrate-import/), multi-tenant plans and billing

Full comparison: [Community and Plus compared](https://www.cdnca.com/en/docs/capabilities/#editions).
