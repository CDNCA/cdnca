// ADR 0011 RI-09/RI-14：授权端规则情报接口（安装上报 + 运营读/驳回/恢复/加语料）的 OpenAPI 契约。
// 样例与 services/license-service/internal/licensing/rule_intel*.go 的 JSON 输出一致。
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const root = fileURLToPath(new URL('../', import.meta.url))
const document = JSON.parse(execFileSync('pnpm', [
  '--package=yaml@2.8.1', 'dlx', 'node',
  fileURLToPath(new URL('../tools/contract-doc-check/parse-yaml.cjs', import.meta.url)), '2.8.1',
], { cwd: root, input: readFileSync(new URL('./openapi/v1/license.yaml', import.meta.url)), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }))
const schemas = document.components.schemas
const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)
const validator = (name) => ajv.compile({ $schema: 'https://json-schema.org/draft/2020-12/schema', $ref: `#/components/schemas/${name}`, components: { schemas } })
const check = (name, value, expected = true) => {
  const validate = validator(name)
  assert.equal(validate(value), expected, `${name}: ${JSON.stringify(validate.errors)}`)
}

const fp = 'a'.repeat(64)
const candidate = {
  id: '0193a5b0-0000-7000-8000-000000000001', kind: 'waf_exclusion', fingerprint: fp,
  target: { engine: 'modsecurity', pack_id: 'system/crs-pl2', rule_id: '942430' },
  conds: [['param.loc', 'query'], ['param.name', 'content']], state: 'ready', state_day: 20380, first_seen: 20370,
  last_seen: 20380, installs_7d: 8, installs_30d: 12, customers_30d: 4, weight: 9.5, fp_weight: 0.05, fp_ratio: 0.005,
  confidence: 0.71, score: 6.7, hits: 1200, cluster_id: fp, member_count: 3, synthetic: false,
}

test('every rule intel path is documented with its permission', () => {
  const expected = {
    '/installation/v1/rule-intel-reports': { post: null },
    '/operator/v1/rule-intel/overview': { get: 'rule_intel.view' },
    '/operator/v1/rule-intel/candidates': { get: 'rule_intel.view' },
    '/operator/v1/rule-intel/candidates/{candidate_id}': { get: 'rule_intel.view' },
    '/operator/v1/rule-intel/candidates/rejections': { post: 'rule_intel.manage' },
    '/operator/v1/rule-intel/candidates/{candidate_id}/restore': { post: 'rule_intel.manage' },
    '/operator/v1/rule-intel/corpus': { get: 'rule_intel.view', post: 'rule_intel.manage' },
  }
  for (const [path, methods] of Object.entries(expected)) {
    for (const [method, permission] of Object.entries(methods)) {
      const operation = document.paths[path]?.[method]
      assert.ok(operation, `${method} ${path}`)
      if (permission) {
        assert.deepEqual(operation['x-required-permissions'], [permission], path)
        assert.deepEqual(operation.security, [{ OperatorSession: [] }], path)
      } else {
        assert.deepEqual(operation.security, [{ PluginRuntimeMTLS: [] }], path)
      }
      if (method === 'post' && permission) {
        const refs = operation.parameters.map((parameter) => parameter.$ref)
        assert.ok(refs.includes('#/components/parameters/OperatorIdempotencyKey'), path)
        assert.ok(refs.includes('#/components/parameters/OperatorOrigin'), path)
      }
    }
  }
})

test('installation report request and receipt', () => {
  const report = { waf_exclusions: [{ kind: 'waf_exclusion', target: candidate.target, conds: candidate.conds, hits: 10, sources: 3, days: 7 }],
    waf_rejections: [], waf_tighten: [], waf_rule_stats: [], autodefense_signatures: [], cc_rule_stats: [], cc_rule_tunes: [],
    false_positives: [], scanner_fingerprints: [] }
  check('RuleIntelReportRequest', { schema: 'cdnca.rule-intel-report/v1', installation_id: '0193a5b0-0000-7000-8000-0000000000aa',
    sequence: 1, observed_at: 1760000000, report, request_id: 'req-1', signature: 'A'.repeat(86) })
  check('RuleIntelReport', { ...report, attack_fragments: [] }, false) // 出现则非空
  check('RuleIntelReceipt', { schema: 'cdnca.rule-intel-receipt/v1', id: candidate.id, sequence: 1, report_digest: fp,
    section_counts: { waf_exclusions: 1 }, accepted: 1, blocked: 0, dropped: 0, fragments: 0, received_at: '2026-10-20T00:00:00Z',
    remaining_today: 3 })
})

test('operator read shapes', () => {
  check('RuleIntelOverview', { schema: 'cdnca.rule-intel.overview/v1', today: 20380,
    kinds: [{ kind: 'waf_exclusion', states: { ready: 1, new: 2 } }], installs_30d: 4, reports_30d: 9,
    pool: { total: 3, total_cap: 20000, kind_cap: 5000, by_kind: { waf_exclusion: 3 } }, corpus: { manual: 1 }, last_job: null })
  check('RuleIntelCandidatePage', { items: [candidate], total: 1, page: 1, page_size: 20 })
  check('RuleIntelCandidate', { ...candidate, kind: 'attack_fragment' }, false) // 片段不进候选池
  check('RuleIntelCandidateDetail', { schema: 'cdnca.rule-intel.candidate/v1', candidate, members: [],
    evidence: [{ day: 20380, weight: 2, fp: 0, installs: 2, hits: 100 }],
    tombstone: { reason: 'false_positive', until_day: 20560, permanent: false, reject_count: 1, active: true },
    synthetic_request: { method: 'GET', path: '/' }, samples: [],
    history: [{ action: 'rule.intel.candidate.reject', actor_kind: 'operator', actor_id: candidate.id, result: 'success',
      payload: { reason_code: 'false_positive' }, occurred_at: '2026-10-20T00:00:00Z' }] })
  check('RuleIntelCorpusPage', { items: [{ id: candidate.id, kind: 'benign', source: 'manual', fingerprint: fp,
    request: { method: 'GET' }, added_by: `operator:${candidate.id}`, added_at: '2026-10-20T00:00:00Z' }], total: 1, page: 1, page_size: 20 })
})

test('operator write shapes', () => {
  check('RuleIntelRejectRequest', { candidate_ids: [candidate.id], reason_code: 'false_positive', note: '误判' })
  check('RuleIntelRejectRequest', { candidate_ids: [], reason_code: 'attack' }, false)
  check('RuleIntelRejectRequest', { candidate_ids: [candidate.id], reason_code: 'because' }, false)
  check('RuleIntelRejectResult', { rejected: 1, skipped: 0, items: [{ id: candidate.id, state: 'rejected',
    tombstone: { reason: 'attack', until_day: null, permanent: true, reject_count: 3, active: true } }] })
  check('RuleIntelRestoreRequest', {})
  check('RuleIntelCorpusAddRequest', { kind: 'attack', attack_class: 'sqli', request: { path: '/' } })
  check('RuleIntelCorpusAddRequest', { kind: 'attack', request: {} }, false)
})

// RI-12：样例与 licensing.RuleIntelMerge / RuleIntelRollout 的 JSON 输出一致（空数组非 null）。
test('merge and rollout shapes', () => {
  const rollout = { id: candidate.id, merge_id: candidate.id, artifact_id: 'rule_pack/system:crs-tuning', from_revision: null,
    to_revision: 1, stage: 'canary', percent: 0, canary_installation_ids: [], state: 'running',
    started_at: '2026-10-20T00:00:00Z', advanced_at: '2026-10-20T00:00:00Z' }
  const merge = { id: candidate.id, target: 'system/crs-tuning', bump: 'patch', candidate_ids: [candidate.id], pack_sha256: [fp],
    base_refs: [], new_versions: ['1.0.0'], skipped: [{ candidate_id: candidate.id, reason: 'no_exact_parameter' }], state: 'published',
    gate_report: { passed: true, g3_state: 'not_applicable', static: { passed: true, checks: [] } },
    release_refs: ['rule_pack/system:crs-tuning@1'], operation: 'merge', created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z',
    published_at: '2026-10-20T00:00:00Z', rollouts: [rollout] }
  check('RuleIntelMerge', merge)
  check('RuleIntelMerge', { ...merge, state: 'merged' }, false)
  check('RuleIntelMergePage', { items: [merge], total: 1, page: 1, page_size: 20 })
  check('RuleIntelRollout', { ...rollout, from_revision: 3, to_revision: 4, stage: '5', percent: 5, state: 'paused',
    paused_reason: 'false_positive_feedback' })
  check('RuleIntelMergeRequest', { target: 'crs_tiers', candidate_ids: [candidate.id] })
  check('RuleIntelMergeRequest', { target: 'system/crs-pl1', candidate_ids: [candidate.id] }, false)
  check('RuleIntelPublishRequest', { canary_installation_ids: [candidate.id] })
  check('RuleIntelRolloutAction', { action: 'rollback' })
  check('RuleIntelRolloutAction', { action: 'retire' }, false) // 已发布永不退役
  check('RuleIntelRollout', { ...rollout, state: 'paused', paused_reason: 'node_rejected' })
  check('RuleIntelMerge', { ...merge, operation: 'withdraw', rule_id: '2', candidate_ids: [], bump: 'major' })
  check('RuleIntelMerge', { ...merge, operation: 'retire' }, false)
})

// RI-12 已发布规则页与回执汇总段
test('published rules and pack receipts', () => {
  const rule = { pack_id: 'system/crs-tuning', rule_id: '1', name: '排除 942430', state: 'active', version: '1.0.2', dormant: null,
    summary: { min_paranoia: 2, rule: 942430, targets: [{ loc: 'args', name: 'content' }] } }
  check('RuleIntelPublishedRules', { packs: [{ pack_id: 'system/crs-tuning', version: '1.0.2', revision: 3,
    rules: [rule, { ...rule, rule_id: '2', state: 'withdrawn', version: '1.0.1', dormant: false }] }] })
  check('RuleIntelPublishedRules', { packs: [{ pack_id: 'system/crs-tuning', version: '1.0.2', revision: 3,
    rules: [{ ...rule, state: 'retired' }] }] }, false)
  check('RuleIntelRuleAction', { pack_id: 'system/crs-tuning', rule_id: '2', reason: '误判' })
  check('RuleIntelRuleAction', { pack_id: 'system/crs-pl2', rule_id: '2' }, false)
  const report = { waf_exclusions: [], waf_rejections: [], waf_tighten: [], waf_rule_stats: [], autodefense_signatures: [],
    cc_rule_stats: [], cc_rule_tunes: [], false_positives: [], scanner_fingerprints: [] }
  check('RuleIntelReport', report)
  check('RuleIntelReport', { ...report, pack_receipts: [{ pack_id: 'system/crs-tuning', version: '1.0.1', applied: 3, rejected: 1 }] })
  check('RuleIntelReport', { ...report, pack_receipts: [] }, false)
  check('RuleIntelReport', { ...report, pack_receipts: [{ pack_id: 'dev/acme/x', version: '1.0.0', applied: 1, rejected: 0 }] }, false)
})
