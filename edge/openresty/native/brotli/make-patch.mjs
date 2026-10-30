// Renders the source-chain patch that adds the vendored ngx_brotli filter
// module as bundle/ngx_brotli/ (edge/openresty/native/patches/25-ngx-brotli-module.patch).
//   node edge/openresty/native/brotli/make-patch.mjs          print the patch
//   node edge/openresty/native/brotli/make-patch.mjs --write  rewrite the patch file and its lock entry
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const moduleDirectory = 'ngx_brotli';
export const moduleFiles = ['config', 'filter/ngx_http_brotli_filter_module.c', 'LICENSE', 'THIRD_PARTY.md'];
export const patchFile = join(here, '..', 'patches', '25-ngx-brotli-module.patch');
export const upstreamCommit = 'a71f9312c2deb28875acc7bacfdd5695a111aa53';
// Byte-for-byte upstream files (THIRD_PARTY.md); config and THIRD_PARTY.md are CDNCA's.
export const upstreamFiles = {
  'filter/ngx_http_brotli_filter_module.c': 'af1a9fc7cd308ee7c1752d0aa64cec5c0a76f40fe2dec3e87ba60c9c4c9154b1',
  LICENSE: 'd77d1c7a59ab34c2b031299b9b606d27b3ceacad5c817a69444a94ccb6943454',
};

export function renderPatch() {
  return moduleFiles.map((name) => {
    const text = readFileSync(join(here, name), 'utf8');
    if (!text.endsWith('\n') || text.includes('\r')) throw new Error(`${name}: needs LF line endings and a final newline`);
    const lines = text.slice(0, -1).split('\n');
    return `--- /dev/null\n+++ b/${moduleDirectory}/${name}\n@@ -0,0 +1,${lines.length} @@\n${lines.map((line) => `+${line}\n`).join('')}`;
  }).join('');
}

// Rewrites the patch and its sources.lock.json entry (patch and file hashes).
function writePatchAndLock() {
  const sha256 = (value) => createHash('sha256').update(value).digest('hex');
  for (const [name, digest] of Object.entries(upstreamFiles)) {
    if (sha256(readFileSync(join(here, name))) !== digest) throw new Error(`${name} differs from upstream ${upstreamCommit}`);
  }
  const patch = renderPatch();
  writeFileSync(patchFile, patch);
  const lockFile = join(here, '..', 'sources.lock.json');
  const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
  const entry = lock.patches.find((item) => item.origin?.kind === 'vendored-module' && item.origin.repository === 'google/ngx_brotli');
  if (!entry) throw new Error('sources.lock.json has no google/ngx_brotli vendored-module entry');
  entry.sha256 = sha256(patch);
  entry.files = moduleFiles.map((name) => ({
    path: `${moduleDirectory}/${name}`, before: null, after: sha256(readFileSync(join(here, name))),
  }));
  writeFileSync(lockFile, `${JSON.stringify(lock, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--write') writePatchAndLock();
  else process.stdout.write(renderPatch());
}
