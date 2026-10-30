#!/usr/bin/env node

import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import {
  AuditConfigurationError,
  auditRepository,
  configurationErrorReport,
  writeReports,
} from './audit.mjs'

function argumentsFrom(argv) {
  const options = {}
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index]
    if (!['--baseline', '--config', '--output-dir', '--root', '--today'].includes(name)) {
      throw new AuditConfigurationError(`unknown argument: ${name}`)
    }
    const value = argv[index + 1]
    if (!value || value.startsWith('--')) throw new AuditConfigurationError(`missing value for ${name}`)
    options[name.slice(2)] = value
    index += 1
  }
  if (!options['output-dir']) throw new AuditConfigurationError('--output-dir is required')
  return options
}

function temporaryOutputDirectory() {
  return mkdtemp(path.join(tmpdir(), 'cdnca-i18n-audit-config-error.'))
}

let outputDirectory
let report
try {
  const options = argumentsFrom(process.argv.slice(2))
  const root = path.resolve(options.root ?? process.cwd())
  outputDirectory = path.resolve(options['output-dir'])
  report = await auditRepository({
    root,
    configPath: path.resolve(options.config ?? path.join(root, 'tools/i18n-audit/config.json')),
    baselinePath: options.baseline ? path.resolve(options.baseline) : undefined,
    today: options.today,
  })
} catch (error) {
  report = configurationErrorReport(error)
  outputDirectory ??= await temporaryOutputDirectory()
}

try {
  await writeReports(report, outputDirectory)
} catch (error) {
  const reason = error && typeof error === 'object' && typeof error.code === 'string' ? error.code : 'WRITE_FAILED'
  report = configurationErrorReport(new AuditConfigurationError(`--output-dir cannot be written (${reason})`))
  outputDirectory = await temporaryOutputDirectory()
  await writeReports(report, outputDirectory)
}
process.stdout.write(`${outputDirectory}\n`)
process.exitCode = report.exitCode
