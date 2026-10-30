// Renders the source-chain patch that adds this directory's nginx module as
// bundle/cdnca-ja4/ (edge/openresty/native/patches/21-cdnca-ja4-module.patch).
//   node edge/openresty/native/ja4/make-patch.mjs          print the patch
//   node edge/openresty/native/ja4/make-patch.mjs --write  rewrite the patch file
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
export const moduleDirectory = 'cdnca-ja4';
export const moduleFiles = ['config', 'cdnca_ja4.h', 'cdnca_ja4.c', 'ngx_http_cdnca_ja4_module.c', 'THIRD_PARTY.md'];
export const patchFile = join(here, '..', 'patches', '21-cdnca-ja4-module.patch');

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
  const patch = renderPatch();
  writeFileSync(patchFile, patch);
  const lockFile = join(here, '..', 'sources.lock.json');
  const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
  const entry = lock.patches.find((item) => item.origin?.kind === 'cdnca-local-module');
  if (!entry) throw new Error('sources.lock.json has no cdnca-local-module entry');
  const sha256 = (value) => createHash('sha256').update(value).digest('hex');
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
