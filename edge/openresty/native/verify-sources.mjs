import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const nativeDirectory = dirname(fileURLToPath(import.meta.url));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const safePath = (value) => typeof value === 'string' && !isAbsolute(value)
  && value.split('/').every((part) => /^[A-Za-z0-9_.+-]+$/.test(part) && part !== '.' && part !== '..');

// Both whole-file preimages and every hunk context must match; no fuzzy fallback.
export function applyExactPatch(directory, patch, specification) {
  if (sha256(patch) !== specification.sha256) throw new Error('patch hash mismatch');
  const paths = specification.files.map((file) => file.path);
  if (!paths.length || new Set(paths).size !== paths.length || !paths.every(safePath)) {
    throw new Error('invalid or duplicate patch paths');
  }
  const headers = [...patch.toString('utf8').matchAll(/^(?:---|\+\+\+) (.+)$/gm)]
    .map((match) => match[1].split('\t')[0])
    .filter((path) => path !== '/dev/null');
  if (!headers.length || headers.some((path) => !/^[ab]\//.test(path) || !paths.includes(path.slice(2)))
    || paths.some((path) => !headers.includes(`b/${path}`) && !headers.includes(`a/${path}`))) {
    throw new Error('patch header paths do not match the lock');
  }
  for (const file of specification.files) {
    let current = directory;
    for (const part of file.path.split('/')) {
      current = join(current, part);
      if (lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error('symlink patch path');
    }
    const path = join(directory, file.path);
    if (file.before === null ? existsSync(path) : !existsSync(path) || sha256(readFileSync(path)) !== file.before) {
      throw new Error(`preimage mismatch: ${file.path}`);
    }
  }
  const options = { cwd: directory, input: patch, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] };
  const args = ['-F', '0', '-t', '-N', '-p', '1', '-V', 'none'];
  try {
    execFileSync('patch', [...args, '--dry-run'], options);
    execFileSync('patch', args, options);
  } catch {
    throw new Error('exact-context patch application failed');
  }
  for (const file of specification.files) {
    const path = join(directory, file.path);
    if (file.after === null ? existsSync(path) : !existsSync(path) || sha256(readFileSync(path)) !== file.after) {
      throw new Error(`postimage mismatch: ${file.path}`);
    }
  }
}

export function verifyArchive(archive, signature, source) {
  if (sha256(archive) !== source.sha256) throw new Error('source archive hash mismatch');
  if (sha256(signature) !== source.signature.sha256) throw new Error('source signature hash mismatch');
}

// Publish only a fully verified source tree. Never re-use or overwrite a build tree.
export function verifySources(archivePath, outputDirectory) {
  const lock = JSON.parse(readFileSync(join(nativeDirectory, 'sources.lock.json'), 'utf8'));
  if (lock.schema !== 'cdnca.native-openresty.sources/v1') throw new Error('unknown source lock');
  const source = lock.source;
  if (!safePath(source.archive_prefix) || !safePath(source.signature.file) || !safePath(source.signer.file)) {
    throw new Error('invalid source lock path');
  }
  const archive = readFileSync(archivePath);
  const signature = readFileSync(join(nativeDirectory, source.signature.file));
  const publicKey = readFileSync(join(nativeDirectory, source.signer.file));
  verifyArchive(archive, signature, source);
  if (sha256(publicKey) !== source.signer.sha256) throw new Error('source public key hash mismatch');
  const output = resolve(outputDirectory);
  if (lstatSync(output, { throwIfNoEntry: false })) throw new Error('output must not exist');
  const scratch = mkdtempSync(join(dirname(output), '.cdnca-source-verification-'));
  try {
    const signaturePath = join(scratch, 'source.asc');
    const archiveCopy = join(scratch, 'source.tar.gz');
    const keyPath = join(scratch, 'source-key.asc');
    const keyringPath = join(scratch, 'source-key.gpg');
    writeFileSync(archiveCopy, archive, { mode: 0o600 });
    writeFileSync(signaturePath, signature, { mode: 0o600 });
    writeFileSync(keyPath, publicKey, { mode: 0o600 });
    execFileSync('gpg', ['--no-options', '--homedir', scratch, '--batch', '--dearmor', '--output', keyringPath, keyPath], { stdio: 'pipe' });
    const status = execFileSync('gpgv', ['--homedir', scratch, '--keyring', keyringPath, '--status-fd', '1', signaturePath, archiveCopy], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const valid = [...status.matchAll(/^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) .+$/gm)];
    if (valid.length !== 1 || valid[0][1] !== source.signer.fingerprint
      || /^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|REVKEYSIG|EXPSIG) /m.test(status)) {
      throw new Error('unexpected source signer');
    }
    const names = execFileSync('tar', ['-tzf', archiveCopy], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).trim().split('\n');
    if (!names.every((name) => name.startsWith(`${source.archive_prefix}/`) && safePath(name.replace(/\/$/, '')))) {
      throw new Error('unsafe source archive paths');
    }
    const stage = join(scratch, 'stage');
    mkdirSync(stage, { mode: 0o700 });
    execFileSync('tar', ['-xzf', archiveCopy, '-C', stage], { stdio: 'pipe' });
    const tree = join(stage, source.archive_prefix);
    for (const step of lock.patches) {
      if (!safePath(step.file) || !safePath(step.directory)) throw new Error('unsafe patch lock path');
      applyExactPatch(join(tree, step.directory), readFileSync(join(nativeDirectory, step.file)), step);
    }
    renameSync(tree, output);
    return { source_sha256: source.sha256, signer: source.signer.fingerprint, patches: lock.patches.length, output, evidence: 'source-only' };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) throw new Error('usage: node verify-sources.mjs OPENRESTY_TARBALL NEW_OUTPUT_DIRECTORY');
  console.log(JSON.stringify(verifySources(process.argv[2], process.argv[3])));
}
