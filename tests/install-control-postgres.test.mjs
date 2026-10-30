import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const pgBin = process.env.CDNCA_TEST_PG_BIN

function controlPostgresBlock(name, required = true) {
  const block = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0]
  if (required) assert.ok(block, `missing ${name}`)
  return block ?? ''
}

function controlPostgresRun(uri, body, extra = {}) {
  return spawnSync('bash', ['-c', [
    'set -Eeuo pipefail',
    // Set after starting the system shell, which strips DYLD_* on macOS.
    'if [[ -n "${CDNCA_TEST_LIBPQ_DIR:-}" ]]; then export DYLD_LIBRARY_PATH="$CDNCA_TEST_LIBPQ_DIR"; fi',
    'python3() { if [[ -n "${CDNCA_TEST_ARGV_FILE:-}" ]]; then printf "%s\\n" "$@" >"$CDNCA_TEST_ARGV_FILE"; fi; command python3 "$@"; }',
    'log() { :; }', source.match(/^fail\(\).*$/m)[0],
    controlPostgresBlock('control_database_psql', false), controlPostgresBlock('prepare_database'), body,
  ].join('\n')], { encoding: 'utf8', timeout: 10000, env: {
    ...process.env, DATABASE_URL: uri, DATABASE_PASSWORD: '', ...extra,
  } })
}

function controlPostgresNoSecret(result, ...secrets) {
  for (const secret of secrets.filter(Boolean)) {
    assert.equal((result.stdout + result.stderr).includes(secret), false, 'database secret appeared in output')
  }
}

function controlPostgresQuery(cluster, sql) {
  const result = spawnSync(join(pgBin, 'psql'), ['-XAt', '--no-password', '-v', 'ON_ERROR_STOP=1'], {
    encoding: 'utf8', timeout: 10000, input: sql, env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('PG'))),
      PGHOST: cluster.root, PGPORT: String(cluster.port), PGUSER: 'fixture_admin', PGDATABASE: 'postgres',
    },
  })
  assert.equal(result.status, 0, 'isolated PostgreSQL fixture query failed')
  return result.stdout.trim()
}

function controlPostgresURI(cluster, password, query = {}) {
  const parameters = new URLSearchParams({ sslmode: 'verify-full', sslrootcert: join(cluster.root, 'server.crt'),
    connect_timeout: '2', ...query })
  return `postgresql://fixture_user:${encodeURIComponent(password)}@localhost:${cluster.port}/fixture_db?${parameters.toString().replaceAll('+', '%20')}`
}

async function controlPostgresCluster() {
  const root = realpathSync(mkdtempSync('/tmp/cdnca-install-pg.'))
  const data = join(root, 'data')
  let started = false
  try {
    const server = createServer()
    await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve))
    const port = server.address().port
    await new Promise((resolve) => server.close(resolve))
    const password = `test-${randomBytes(12).toString('hex')}:@/%?#='\\+ 空白 `
    writeFileSync(join(root, 'bootstrap-password'), randomBytes(32).toString('hex'), { mode: 0o600 })
    const init = spawnSync(join(pgBin, 'initdb'), ['-D', data, '--username=fixture_admin', '--auth-local=trust',
      '--auth-host=scram-sha-256', '--no-locale', '--encoding=UTF8', `--pwfile=${join(root, 'bootstrap-password')}`],
    { encoding: 'utf8', timeout: 30000 })
    assert.equal(init.status, 0, 'isolated PostgreSQL initdb failed')
    const cert = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
      '-keyout', join(root, 'server.key'), '-out', join(root, 'server.crt')], { encoding: 'utf8', timeout: 10000 })
    assert.equal(cert.status, 0, 'isolated PostgreSQL TLS fixture failed')
    chmodSync(join(root, 'server.key'), 0o600)
    writeFileSync(join(data, 'postgresql.conf'), `listen_addresses='127.0.0.1'\nport=${port}\nunix_socket_directories='${root}'\nssl=on\nssl_cert_file='${join(root, 'server.crt')}'\nssl_key_file='${join(root, 'server.key')}'\npassword_encryption='scram-sha-256'\n`, { mode: 0o600 })
    writeFileSync(join(data, 'pg_hba.conf'), 'local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n', { mode: 0o600 })
    const start = spawnSync(join(pgBin, 'pg_ctl'), ['-D', data, '-l', join(root, 'postgres.log'), '-w', 'start'],
      { encoding: 'utf8', timeout: 15000 })
    assert.equal(start.status, 0, 'isolated PostgreSQL startup failed')
    started = true
    const cluster = { root, data, port, password }
    controlPostgresQuery(cluster, `CREATE ROLE fixture_user LOGIN PASSWORD '${password.replaceAll("'", "''")}';\nCREATE DATABASE fixture_db OWNER fixture_user;`)
    const libdir = spawnSync(join(pgBin, 'pg_config'), ['--libdir'], { encoding: 'utf8' })
    assert.equal(libdir.status, 0)
    cluster.environment = { PATH: `${pgBin}:${process.env.PATH}`, CDNCA_TEST_LIBPQ_DIR: libdir.stdout.trim() }
    return cluster
  } catch (error) {
    if (started || existsSync(join(data, 'postmaster.pid'))) {
      const stopped = spawnSync(join(pgBin, 'pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { timeout: 10000 })
      assert.equal(stopped.status, 0, 'owned PostgreSQL must stop before failed-fixture cleanup')
    }
    rmSync(root, { recursive: true })
    throw error
  }
}

test('fresh PostgreSQL preflight really expands URI credentials, endpoint, TLS and query options',
  { skip: !pgBin && 'set CDNCA_TEST_PG_BIN to run isolated PostgreSQL integration tests' }, async (t) => {
    const cluster = await controlPostgresCluster()
    try {
      await t.test('empty external database connects using its complete URI, not the caller role/socket', () => {
        const uri = controlPostgresURI(cluster, cluster.password)
        const argv = join(cluster.root, 'python-argv')
        const result = controlPostgresRun(uri, 'prepare_database', { ...cluster.environment, CDNCA_TEST_ARGV_FILE: argv,
          PGHOST: cluster.root, PGPORT: String(cluster.port), PGUSER: 'must_not_be_used', PGDATABASE: 'must_not_be_used',
          PGPASSWORD: 'wrong', PGSERVICE: 'must_not_be_used', PGSERVICEFILE: '/missing/service',
          PGOPTIONS: '-c statement_timeout=invalid', PGSSLMODE: 'disable' })
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 0, result.stderr)
        assert.equal(readFileSync(argv, 'utf8'), '-I\n-B\n-\nempty\n')
      })
      await t.test('new local database credential validation uses the same URI-safe connection', () => {
        const uri = controlPostgresURI(cluster, cluster.password)
        const result = controlPostgresRun(uri, `
pg_isready() { return 0; }
systemctl() { return 0; }
runuser() { if [[ " $* " == *" --command "* ]]; then printf empty; else while IFS= read -r line; do :; done; fi; }
prepare_database`, { ...cluster.environment, TEMP_DIR: cluster.root, DATABASE_PASSWORD: 'fixture-generated-hex',
          PGHOST: cluster.root, PGPORT: String(cluster.port), PGUSER: 'must_not_be_used' })
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 0, result.stderr)
      })
      await t.test('SCRAM rejects a wrong password without credential or raw server error leakage', () => {
        const password = `${cluster.password}wrong`
        const uri = controlPostgresURI(cluster, password)
        const result = controlPostgresRun(uri, 'prepare_database', cluster.environment)
        controlPostgresNoSecret(result, uri, password, encodeURIComponent(password))
        assert.equal(result.status, 1)
        assert.match(result.stderr, /PostgreSQL connection check failed/)
        assert.doesNotMatch(result.stderr, /FATAL|password authentication failed/)
        assert.equal(result.stdout, '')
      })
      for (const [label, query] of [
        ['plaintext rejected by hostnossl policy', { sslmode: 'disable' }],
        ['untrusted root certificate', { sslrootcert: join(cluster.root, 'missing.crt') }],
        ['wrong TLS server name', { host: 'not-localhost.invalid', hostaddr: '127.0.0.1' }],
        ['invalid SSL mode', { sslmode: 'not-a-mode' }],
        ['required read-only server', { target_session_attrs: 'read-only' }],
        ['invalid session options', { options: '-c statement_timeout=invalid' }],
        ['unknown query option', { not_a_libpq_option: 'private-option-value' }],
      ]) {
        await t.test(`URI query settings are preserved: ${label}`, () => {
          const uri = controlPostgresURI(cluster, cluster.password, query)
          const result = controlPostgresRun(uri, 'control_database_psql reachable', cluster.environment)
          controlPostgresNoSecret(result, uri, cluster.password, 'private-option-value')
          assert.equal(result.status, 1)
          assert.equal(result.stdout, '')
          assert.equal(result.stderr, 'PostgreSQL connection check failed\n')
        })
      }
      await t.test('valid percent-encoded session options and TLS reach the real server', () => {
        const uri = controlPostgresURI(cluster, cluster.password, {
          options: '-c default_transaction_read_only=on -c statement_timeout=2000', application_name: 'installer + URI/验收',
        })
        const result = controlPostgresRun(uri, 'control_database_psql reachable', cluster.environment)
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 0, result.stderr)
        assert.equal(result.stdout, '1\n')
      })
      await t.test('Python startup ignores inherited PYTHONPATH and sitecustomize', () => {
        const marker = join(cluster.root, 'untrusted-python-loaded')
        writeFileSync(join(cluster.root, 'sitecustomize.py'), `open(${JSON.stringify(marker)}, 'w').close()\n`)
        const result = controlPostgresRun(controlPostgresURI(cluster, cluster.password), 'control_database_psql reachable',
          { ...cluster.environment, PYTHONPATH: cluster.root })
        assert.equal(result.status, 0, result.stderr)
        assert.equal(existsSync(marker), false, 'untrusted Python startup code ran')
      })
      for (const [label, uri] of [
        ['empty', ''], ['wrong scheme', 'https://fixture:private-value@localhost/db'],
        ['keyword connection string', 'user=fixture password=private-value'],
        ['newline', 'postgresql://localhost/fixture\nprivate-value'],
        ['carriage return', 'postgresql://localhost/fixture\rprivate-value'],
        ['invalid percent escape', `postgresql://fixture:private-value%ZZ@localhost:${cluster.port}/fixture_db`],
        ['encoded NUL', controlPostgresURI(cluster, cluster.password) + '&application_name=private-value%00'],
      ]) {
        await t.test(`invalid connection input is rejected without leakage: ${label}`, () => {
          const result = controlPostgresRun(uri, 'control_database_psql reachable', cluster.environment)
          controlPostgresNoSecret(result, uri, cluster.password, 'private-value')
          assert.equal(result.status, 1)
          assert.equal(result.stdout, '')
          assert.equal(result.stderr, 'PostgreSQL connection check failed\n')
        })
      }
      await t.test('only fixed read-only query modes are accepted', () => {
        const uri = controlPostgresURI(cluster, cluster.password)
        const result = controlPostgresRun(uri, 'control_database_psql "DROP DATABASE postgres"', cluster.environment)
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 1)
        assert.equal(result.stdout, '')
        assert.equal(result.stderr, 'PostgreSQL connection check failed\n')
      })
      await t.test('analytics preflight requires exactly the six existing function EXECUTE grants without adding any', () => {
        const signatures = [
          'analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamptz)',
          'analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamptz)',
          'analytics_history_schedule_recovery_098(uuid,text,timestamptz)',
          'analytics_history_claim_recovery_098(uuid,text,uuid,timestamptz,timestamptz)',
          'analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamptz)',
          'analytics_history_complete_recovery_098(uuid,uuid,timestamptz)',
        ]
        const uri = controlPostgresURI(cluster, cluster.password)
        const missing = controlPostgresRun(uri, 'control_database_psql analytics', cluster.environment)
        assert.equal(missing.status, 1); controlPostgresNoSecret(missing, uri, cluster.password)
        controlPostgresQuery(cluster, '\\connect fixture_db\n' + signatures.map((signature) =>
          `CREATE FUNCTION ${signature} RETURNS void LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$; REVOKE ALL ON FUNCTION ${signature} FROM PUBLIC;`).join('\n'))
        for (let count = 0; count <= signatures.length; count++) {
          const checked = controlPostgresRun(uri, 'control_database_psql analytics', cluster.environment)
          assert.equal(checked.status, 0, checked.stderr)
          assert.equal(checked.stdout, count === signatures.length ? 't\n' : 'f\n')
          controlPostgresNoSecret(checked, uri, cluster.password)
          if (count < signatures.length) controlPostgresQuery(cluster, `\\connect fixture_db\nGRANT EXECUTE ON FUNCTION ${signatures[count]} TO fixture_user;`)
        }
        controlPostgresQuery(cluster, `\\connect fixture_db\nREVOKE EXECUTE ON FUNCTION ${signatures[0]} FROM fixture_user;`)
        const denied = controlPostgresRun(uri, 'control_database_psql analytics', cluster.environment)
        assert.equal(denied.status, 0); assert.equal(denied.stdout, 'f\n')
        assert.match(controlPostgresQuery(cluster, `\\connect fixture_db\nSELECT has_function_privilege('fixture_user','${signatures[0]}','EXECUTE');`), /f$/)
      })
      await t.test('existing external business state is refused without mutation', () => {
        controlPostgresQuery(cluster, '\\connect fixture_db\nCREATE TABLE existing_business_state (id int);\nINSERT INTO existing_business_state VALUES (41);')
        const uri = controlPostgresURI(cluster, cluster.password)
        const result = controlPostgresRun(uri, 'prepare_database', cluster.environment)
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 1)
        assert.match(result.stderr, /fresh installation requires an empty external PostgreSQL database/)
        assert.match(controlPostgresQuery(cluster, '\\connect fixture_db\nSELECT id FROM existing_business_state;'), /41$/)
      })
      await t.test('external search_path cannot shadow the empty-database system catalog checks', () => {
        controlPostgresQuery(cluster, '\\connect fixture_db\nCREATE TABLE public.pg_namespace AS SELECT * FROM pg_catalog.pg_namespace WITH NO DATA;\nCREATE TABLE public.pg_depend AS SELECT * FROM pg_catalog.pg_depend WITH NO DATA;\nCREATE TABLE public.pg_extension AS SELECT * FROM pg_catalog.pg_extension WITH NO DATA;\nGRANT SELECT ON public.pg_namespace,public.pg_depend,public.pg_extension TO fixture_user;')
        const uri = controlPostgresURI(cluster, cluster.password, { options: '-c search_path=public,pg_catalog' })
        const result = controlPostgresRun(uri, 'control_database_psql empty', cluster.environment)
        controlPostgresNoSecret(result, uri, cluster.password)
        assert.equal(result.status, 0, result.stderr)
        assert.equal(result.stdout, 'f\n')
      })
      await t.test('successful and failed checks leave no database sessions behind', () => {
        assert.equal(controlPostgresQuery(cluster, "SELECT count(*) FROM pg_stat_activity WHERE usename='fixture_user';"), '0')
      })
    } finally {
      const stopped = spawnSync(join(pgBin, 'pg_ctl'), ['-D', cluster.data, '-m', 'fast', '-w', 'stop'],
        { encoding: 'utf8', timeout: 10000 })
      assert.equal(stopped.status, 0, 'owned PostgreSQL must stop before cleanup')
      rmSync(cluster.root, { recursive: true })
    }
  })
