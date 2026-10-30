import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { applyExactPatch, verifyArchive, verifySources } from './verify-sources.mjs';
import { moduleDirectory, moduleFiles, patchFile, renderPatch } from './ja4/make-patch.mjs';
import {
  moduleDirectory as brotliDirectory, moduleFiles as brotliFiles, patchFile as brotliPatchFile, renderPatch as renderBrotliPatch,
  upstreamCommit as brotliCommit, upstreamFiles as brotliUpstream,
} from './brotli/make-patch.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const original = 'one\ntwo\nthree\n';
const changed = 'one\nupdated\nthree\n';
const patch = '--- a/example.c\n+++ b/example.c\n@@ -1,3 +1,3 @@\n one\n-two\n+updated\n three\n';
const specification = {
  sha256: sha256(patch),
  files: [{ path: 'example.c', before: sha256(original), after: sha256(changed) }],
};

test('applies only the pinned patch to exact preimages and verifies postimages', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-patch-test-'));
  try {
    writeFileSync(join(dir, 'example.c'), original);
    applyExactPatch(dir, Buffer.from(patch), specification);
    assert.equal(readFileSync(join(dir, 'example.c'), 'utf8'), changed);
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch), specification), /preimage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects patch tampering and changed context before editing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-patch-test-'));
  try {
    writeFileSync(join(dir, 'example.c'), original);
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch + '\n'), specification), /patch hash/);
    writeFileSync(join(dir, 'example.c'), 'different\ntwo\nthree\n');
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch), specification), /preimage/);
    assert.equal(readFileSync(join(dir, 'example.c'), 'utf8'), 'different\ntwo\nthree\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('zero fuzz rejects omitted boundary context even with an approved preimage', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-patch-test-'));
  try {
    const drift = 'different\ntwo\nthree\n';
    writeFileSync(join(dir, 'example.c'), drift);
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch), {
      ...specification, files: [{ ...specification.files[0], before: sha256(drift) }],
    }), /patch application/);
    assert.equal(readFileSync(join(dir, 'example.c'), 'utf8'), drift);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects traversal and unlisted patch paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-patch-test-'));
  try {
    for (const path of ['../example.c', '/example.c', 'a/../example.c']) {
      assert.throws(() => applyExactPatch(dir, Buffer.from(patch), {
        ...specification, files: [{ ...specification.files[0], path }],
      }), /path/);
    }
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch), {
      ...specification, files: [],
    }), /paths/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects wrong archive and signature digests before invoking GPG or extracting', () => {
  assert.throws(() => verifyArchive(Buffer.from('bad'), Buffer.from('sig'), {
    sha256: sha256('good'), signature: { sha256: sha256('sig') },
  }), /source archive hash/);
  assert.throws(() => verifyArchive(Buffer.from('good'), Buffer.from('bad'), {
    sha256: sha256('good'), signature: { sha256: sha256('sig') },
  }), /source signature hash/);
});

test('rejects a dangling symlink preimage', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-patch-test-'));
  try {
    symlinkSync(join(dir, 'missing-target'), join(dir, 'example.c'));
    assert.throws(() => applyExactPatch(dir, Buffer.from(patch), specification), /symlink/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('locked patches retain immutable upstream hashes and explicit port provenance', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  assert.equal(lock.patches.length, 29);
  for (const [index, entry] of lock.patches.entries()) {
    assert.equal(sha256(readFileSync(new URL(entry.file, import.meta.url))), entry.sha256);
    assert.ok(entry.files.every((file) => /^[0-9a-f]{64}$/.test(file.after)));
    if ((index < 15 || index >= 17) && index !== 7 && entry.upstream) assert.equal(entry.sha256, entry.upstream.sha256);
    if ([7, 15, 16].includes(index) || entry.origin?.kind === 'cdnca-local-module' || entry.origin?.kind === 'vendored-module') assert.ok(entry.adaptation);
  }
  assert.equal(lock.source.signer.fingerprint, '25451EB088460026195BD62CB550E09EA0E98066');
  assert.equal(lock.source.sha256, '65b78baadd3f0984055de89bf13f4a1932e5bfe9c31932037a134ea2b1a0ce42');
});

test('the ngx_brotli patch is the vendored upstream filter, added as new files only', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entries = lock.patches.filter((entry) => entry.origin?.kind === 'vendored-module');
  assert.equal(entries.length, 1);
  const [entry] = entries;
  assert.equal(lock.patches.indexOf(entry), 24); // step 25; 26 (comp level variables) edits it
  assert.equal(entry.directory, 'bundle');
  assert.equal(entry.origin.repository, 'google/ngx_brotli');
  assert.equal(entry.origin.commit, brotliCommit);
  assert.equal(readFileSync(brotliPatchFile, 'utf8'), renderBrotliPatch());
  assert.deepEqual(entry.files.map((file) => file.path), brotliFiles.map((name) => `${brotliDirectory}/${name}`));
  for (const file of entry.files) {
    const name = file.path.slice(brotliDirectory.length + 1);
    assert.equal(file.before, null);
    assert.equal(file.after, sha256(readFileSync(new URL(`./brotli/${name}`, import.meta.url))));
    if (brotliUpstream[name]) assert.equal(file.after, brotliUpstream[name], `${name} is upstream ${brotliCommit}`);
  }
});

test('the compression level patch is step 26 and edits gzip and the vendored brotli filter', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[25];
  assert.equal(entry.file, 'patches/26-cdnca-comp-level-variable.patch');
  assert.equal(entry.directory, 'bundle');
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.ok(entry.adaptation);
  const [gzip, brotli] = entry.files;
  assert.equal(gzip.path, 'nginx-1.31.1/src/http/modules/ngx_http_gzip_filter_module.c');
  assert.ok(lock.patches.slice(0, 25).every((step) => step.files.every((other) => !other.path.endsWith('ngx_http_gzip_filter_module.c'))));
  assert.equal(brotli.before, lock.patches[24].files.find((file) => file.path === brotli.path).after);
});

test('the JA4 module patch is exactly the reviewed ja4/ sources, added as new files only', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entries = lock.patches.filter((entry) => entry.origin?.kind === 'cdnca-local-module');
  assert.equal(entries.length, 1);
  const [entry] = entries;
  assert.equal(entry.directory, 'bundle');
  assert.equal(lock.patches.indexOf(entry), 20); // step 21; 22 (proxy_toa) follows it
  assert.equal(readFileSync(patchFile, 'utf8'), renderPatch());
  assert.deepEqual(entry.files.map((file) => file.path), moduleFiles.map((name) => `${moduleDirectory}/${name}`));
  for (const file of entry.files) {
    assert.equal(file.before, null);
    assert.equal(file.after, sha256(readFileSync(new URL(`./ja4/${file.path.slice(moduleDirectory.length + 1)}`, import.meta.url))));
  }
});

test('the upstream host check patch is step 29 and continues the upstream chain', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[28];
  assert.equal(entry.file, 'patches/29-cdnca-upstream-ssl-host-check.patch');
  assert.equal(entry.directory, 'bundle/nginx-1.31.1');
  assert.equal(entry.upstream, undefined);
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.ok(entry.adaptation);
  assert.deepEqual(entry.files.map((file) => file.path), ['src/http/ngx_http_upstream.h', 'src/http/ngx_http_upstream.c']);
  // upstream.c: its preimage is step 24's postimage; upstream.h: no earlier step edits it.
  assert.equal(entry.files[1].before, lock.patches[23].files.find((file) => file.path === 'src/http/ngx_http_upstream.c').after);
  assert.ok(lock.patches.slice(0, 28).every((step) => step.files.every((other) => other.path !== 'src/http/ngx_http_upstream.h')));
  assert.match(readFileSync(new URL(entry.file, import.meta.url), 'utf8'), /ngx_http_cdnca_upstream_set_ssl_host_check/);
});

test('the body size patch is a local, core-only step', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[22];
  assert.equal(entry.file, 'patches/23-cdnca-client-max-body-size-variable.patch');
  assert.equal(entry.directory, 'bundle/nginx-1.31.1');
  assert.equal(entry.upstream, undefined);
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.ok(entry.adaptation);
  assert.ok(entry.files.every((file) => /^src\/http\//.test(file.path) && file.before !== null));
  // Its core-module preimage is the postimage of step 20 (the last earlier edit of that file).
  const core = (index) => lock.patches[index].files.find((file) => file.path === 'src/http/ngx_http_core_module.c');
  assert.equal(core(22).before, core(19).after);
});

test('the proxy_cache_valid variable patch is a local, core-only step', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[23];
  assert.equal(entry.file, 'patches/24-cdnca-proxy-cache-valid-variable.patch');
  assert.equal(entry.directory, 'bundle/nginx-1.31.1');
  assert.equal(entry.upstream, undefined);
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.ok(entry.adaptation);
  assert.deepEqual(entry.files.map((file) => file.path),
    ['src/http/ngx_http_cache.h', 'src/http/ngx_http_file_cache.c', 'src/http/ngx_http_upstream.c']);
  // No earlier step edits these files: their preimages are the signed archive's.
  for (const file of entry.files) {
    assert.ok(lock.patches.slice(0, 23).every((step) => step.files.every((other) => other.path !== file.path)));
  }
});

test('the per connection HTTP/2 patch is step 27, local and core-only', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[26];
  assert.equal(entry.file, 'patches/27-cdnca-http2-per-connection.patch');
  assert.equal(entry.directory, 'bundle/nginx-1.31.1');
  assert.equal(entry.upstream, undefined);
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.ok(entry.adaptation);
  assert.deepEqual(entry.files.map((file) => file.path),
    ['src/event/ngx_event_openssl.h', 'src/http/modules/ngx_http_ssl_module.c']);
  // ngx_http_ssl_module.c was last edited by step 14; the header by none.
  const ssl = (index) => lock.patches[index].files.find((file) => file.path === 'src/http/modules/ngx_http_ssl_module.c');
  assert.equal(entry.files[1].before, ssl(13).after);
  assert.ok(lock.patches.slice(0, 26).every((step) => step.files.every((other) => other.path !== 'src/event/ngx_event_openssl.h')));
  const patch = readFileSync(new URL(entry.file, import.meta.url), 'utf8');
  assert.match(patch, /^\+ngx_http_cdnca_ssl_set_http2\(ngx_ssl_conn_t \*ssl_conn, int enable\)$/m);
  assert.match(patch, /^\+        if \(\(h2scf->enable \|\| hc->addr_conf->http2\) && !c->ssl->cdnca_no_http2\) \{$/m);
});

test('the shared download rate patch is step 28 and follows the TOA stream proxy', () => {
  const lock = JSON.parse(readFileSync(new URL('./sources.lock.json', import.meta.url)));
  const entry = lock.patches[27];
  assert.equal(entry.file, 'patches/28-cdnca-stream-shared-download-rate.patch');
  assert.equal(entry.directory, 'bundle/nginx-1.31.1');
  assert.match(entry.origin.local, /^CDNCA original/);
  assert.deepEqual(entry.files.map((file) => file.path),
    ['src/stream/ngx_stream_proxy_module.c', 'src/stream/ngx_stream_upstream.h']);
  // the stream proxy was last edited by step 22 (proxy_toa); the header by none.
  const toa = lock.patches[21].files.find((file) => file.path === 'src/stream/ngx_stream_proxy_module.c');
  assert.equal(entry.files[0].before, toa.after);
  assert.ok(lock.patches.filter((step) => step !== entry).every((step) => step.files.every((other) => other.path !== 'src/stream/ngx_stream_upstream.h')));
  const patch = readFileSync(new URL(entry.file, import.meta.url), 'utf8');
  assert.match(patch, /^\+    \{ ngx_string\("proxy_download_rate_shared"\),$/m);
  assert.match(patch, /^\+            if \(limit_rate && from_upstream && u->download_rate_key\.len$/m);
});

test('signed upstream archive replays the complete source-only patch chain', {
  skip: !process.env.CDNCA_OPENRESTY_SOURCE,
}, () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-native-source-test-'));
  try {
    const output = join(dir, 'verified');
    const result = verifySources(process.env.CDNCA_OPENRESTY_SOURCE, output);
    assert.equal(result.patches, 29);
    assert.equal(result.evidence, 'source-only');
    assert.throws(() => verifySources(process.env.CDNCA_OPENRESTY_SOURCE, output), /must not exist/);
    const core = (file) => readFileSync(join(output, 'bundle/nginx-1.31.1', file), 'utf8');

    const log = core('src/http/modules/ngx_http_log_module.c');
    assert.match(log, /len = ngx_http_log_escape\(lcf, NULL, value->data, value->len\)/);
    assert.match(log, /ngx_http_log_check_length\(r, buf, end, value->len \+ len \* 3\)/);
    assert.match(log, /return \(u_char \*\) ngx_http_log_escape\(lcf, buf, value->data, value->len\)/);
    assert.match(log, /lcf->escape_non_ascii/);
    for (const module of ['ngx_devel_kit-0.3.4/src/ndk_rewrite.c', 'ngx_postgres-1.0/src/ngx_postgres_util.c']) {
      const body = readFileSync(join(output, 'bundle', module), 'utf8');
      assert.equal((body.match(/complex_end->code = ngx_http_script_complex_value_end_code;/g) ?? []).length, 1);
      assert.ok(body.indexOf('ngx_http_script_compile(&sc)') < body.indexOf('complex_end->code'));
    }
    assert.match(core('src/http/ngx_http_script.c'), /val->len = e->pos - e->buf.data/);
    assert.match(core('src/http/ngx_http_variables.c'), /r->ncaptures = 0/);
    assert.match(core('src/event/quic/ngx_event_quic.c'), /ngx_quic_address_hash/);
    assert.match(core('src/stream/ngx_stream_proxy_module.c'), /ngx_string\("proxy_toa"\)/);
    assert.match(core('src/event/ngx_event_connect.h'), /#define NGX_CDNCA_TOA_SOCKOPT  0x43464c54/);
    assert.match(core('src/event/quic/ngx_event_quic.c'), /qc->congestion.mtu = NGX_QUIC_MIN_INITIAL_SIZE/);
    assert.match(core('src/event/quic/ngx_event_quic_connection.h'), /#if \(NGX_QUIC_OPENSSL_API\)/);
    assert.match(core('src/os/unix/ngx_process_cycle.c'), /!c\[i\].read->skip_socket_leak_check/);
    assert.match(core('src/os/unix/ngx_process_cycle.c'), /!c\[i\].read->quic/);
    // 18-20: CVE-2026-95101, CVE-2026-93479, CVE-2026-15176 (nginx 1.31.7).
    assert.match(core('src/http/v3/ngx_http_v3_parse.c'), /rc = ngx_http_v3_parse_skip\(b, &st->skip\)/);
    assert.match(core('src/http/v3/ngx_http_v3_parse.h'), /ngx_uint_t +skip;/);
    for (const file of ['src/http/ngx_http_script.c', 'src/stream/ngx_stream_script.c']) {
      assert.match(core(file), /value->len = n \+ len;/);
    }
    assert.match(core('src/http/ngx_http_core_module.c'), /if \(alias && \(!r->valid_location \|\| r->uri_changed\)\)/);
    // 23: client_max_body_size with variables; every body filter reads the per-request limit.
    assert.match(core('src/http/ngx_http_core_module.c'), /ngx_http_core_client_max_body_size_slot,\n/);
    assert.match(core('src/http/ngx_http_core_module.c'), /if \(size == NGX_ERROR \|\| size == 0\) \{/);
    assert.match(core('src/http/ngx_http_core_module.h'), /ngx_http_complex_value_t +\*client_max_body_size_value;/);
    assert.match(core('src/http/ngx_http_request.h'), /unsigned +max_size_set:1;/);
    for (const file of ['src/http/ngx_http_request_body.c', 'src/http/v2/ngx_http_v2.c', 'src/http/v3/ngx_http_v3_request.c']) {
      assert.match(core(file), /ngx_http_request_body_max_size\(r, &max\) != NGX_OK/);
      assert.doesNotMatch(core(file), /clcf->client_max_body_size/);
    }
    // 24: proxy_cache_valid with variables, evaluated per response with the request.
    assert.match(core('src/http/ngx_http_cache.h'), /ngx_http_complex_value_t +\*value;/);
    assert.match(core('src/http/ngx_http_file_cache.c'), /ngx_http_file_cache_valid_value\(r, &valid\[i\]\)/);
    assert.equal((core('src/http/ngx_http_upstream.c').match(/ngx_http_file_cache_valid\(r,/g) ?? []).length, 4);
    // 21: the JA4 module tree that configure --add-module builds.
    assert.match(readFileSync(join(output, 'bundle/cdnca-ja4/config'), 'utf8'), /ngx_module_name=ngx_http_cdnca_ja4_module/);
    // 25/26: the ngx_brotli tree, and both compression levels take variables.
    assert.match(readFileSync(join(output, 'bundle/ngx_brotli/config'), 'utf8'), /ngx_module_libs="-lbrotlienc -lbrotlicommon -lm"/);
    assert.match(readFileSync(join(output, 'bundle/ngx_brotli/filter/ngx_http_brotli_filter_module.c'), 'utf8'), /ngx_http_brotli_quality\(r, conf\)/);
    assert.match(core('src/http/modules/ngx_http_gzip_filter_module.c'), /ctx->level = \(int\) ngx_http_gzip_level\(r, conf\);/);
    assert.equal(sha256(core('src/event/quic/ngx_event_quic_bpf_code.c')),
      '1748f472b22a737cd9c89d59258eeca26f64b8f46c60b466d2c3377699f142ac');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
