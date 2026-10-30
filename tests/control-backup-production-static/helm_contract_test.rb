# Render-only fixtures: these identities and digests are not deployment inputs.
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

root = File.expand_path('../..', __dir__)
chart = File.join(root, 'infra/helm/cdnca')
helm = ENV.fetch('HELM', 'helm')
installation = 'e5d9c8b1-a56d-40c8-b83e-5837c6f572fa'
image_digest = "sha256:#{Digest::SHA256.hexdigest('backup chart test image')}"
manifest_digest = Digest::SHA256.hexdigest('backup chart test core manifest')

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

def render(helm, chart, *arguments)
  output, error, status = Open3.capture3(helm, 'template', 'cdnca', chart, '--namespace', 'cdnca', *arguments)
  check(status.success?, "Helm render failed: #{error}")
  YAML.load_stream(output).compact
end

def backup_parts(documents)
  plans = documents.find { |document| document['kind'] == 'ConfigMap' && document.fetch('data', {}).key?('backup-plan.json') }
  cronjob = documents.find { |document| document['kind'] == 'CronJob' }
  check(plans && cronjob, 'enabled backup must render a plan and CronJob')
  [plans, cronjob, JSON.parse(plans.fetch('data').fetch('backup-plan.json'))]
end

Dir.mktmpdir('cdnca-backup-helm-contract-') do |directory|
  overlay = File.join(directory, 'fixture.yaml')
  File.write(overlay, {
    'controlBackup' => { 'enabled' => true },
    'controlBackupTool' => {
      'installationId' => installation, 'image' => { 'digest' => image_digest },
      'appVersion' => '1.2.3', 'sourceClusterId' => 'chart-test-control', 'signingKeyId' => 'chart-test-key',
      'recovery' => { 'schemaVersion' => 254, 'coreManifestSHA256' => manifest_digest,
                      'envelopeKey' => { 'provider' => 'kms', 'name' => 'chart-test/key', 'version' => 'fixture-v1' } }
    }
  }.to_yaml)
  arguments = ['-f', File.join(chart, 'values-production.yaml'), '-f', overlay]
  documents = render(helm, chart, *arguments)
  plans, cronjob, plan = backup_parts(documents)
  check(plan['schema'] == 'cdnca.control-backup.plan/v2', 'backup plan must use the CLI v2 schema')
  check(plan['installation_id'] == installation, 'installation identity must come from the approved value')
  check(plan['backup_id'] == '' && plan['backup_id_environment'] == 'POD_UID', 'backup ID must come from the Pod UID')
  check(plan['source_cluster_id'] == 'chart-test-control' && plan['schema_version'] == 254 && plan['app_version'] == '1.2.3', 'source/version binding was lost')
  check(plan['core_manifest_sha256'] == manifest_digest && plan['envelope_key'] == { 'provider' => 'kms', 'name' => 'chart-test/key', 'version' => 'fixture-v1' }, 'manifest/key binding was lost')
  check(plan['signing_key_id'] == 'chart-test-key' && plan['signing_private_key_file'] == '/var/run/recovery/runtime/source/manifest-signing-private.pem', 'signing key must remain a protected file reference')
  expected_fields = %w[schema installation_id driver_plan_sha256 backup_id backup_id_environment source_cluster_id app_version schema_version core_manifest_sha256 envelope_key target_rpo_seconds target_rto_seconds signing_key_id signing_private_key_file driver_path manifest_directory]
  check(plan.keys.sort == expected_fields.sort, 'backup plan drifted from the strict CLI fields')
  driver_bytes = plans.fetch('data').fetch('driver-plan.json')
  check(!driver_bytes.end_with?("\n"), 'the driver block scalar must not add a trailing newline')
  mounted = File.join(directory, 'driver-plan.json')
  File.binwrite(mounted, driver_bytes)
  check(plan['driver_plan_sha256'] == Digest::SHA256.file(mounted).hexdigest, 'driver digest differs from the exact ConfigMap file bytes')
  driver = JSON.parse(driver_bytes)
  check(driver['schema'] == 'cdnca.control-recovery-driver.plan/v1', 'recovery driver schema changed')
  pod = cronjob.dig('spec', 'jobTemplate', 'spec', 'template', 'spec')
  volume = pod.fetch('volumes').find { |item| item['name'] == 'plan-source' }
  check(plans['immutable'] == true && volume.dig('configMap', 'name') == plans.dig('metadata', 'name'), 'CronJob must reference the immutable plan name')
  container = pod.fetch('containers').find { |item| item['name'] == 'control-backup' }
  check(container['image'].end_with?("@#{image_digest}"), 'backup image must use the supplied digest')
  check(container['args'] == ['--plan', '/var/run/recovery/runtime/backup-plan.json'], 'backup CLI argv changed')
  env = container.fetch('env').to_h { |item| [item['name'], item] }
  check(env.fetch('POD_UID').dig('valueFrom', 'fieldRef', 'fieldPath') == 'metadata.uid', 'Pod UID must use the downward API')
  check(env.fetch('CONTROL_RECOVERY_DRIVER_PLAN')['value'] == '/var/run/recovery/runtime/driver-plan.json', 'driver plan path differs from the copied file')
  init = pod.fetch('initContainers').find { |item| item['name'] == 'prepare-recovery-inputs' }.fetch('args').first
  check(init.include?('cp /etc/recovery-plan-source/driver-plan.json /var/run/recovery/runtime/driver-plan.json'), 'driver plan must be copied without byte changes')
  check(init.include?('find /var/run/recovery/runtime -type f -exec chmod 0400'), 'runtime plans must remain protected regular files')

  repeated, = backup_parts(render(helm, chart, *arguments))
  check(repeated == plans, 'identical inputs must render identical immutable plan bytes/name')
  changed, changed_cron, changed_plan = backup_parts(render(helm, chart, *arguments, '--set', 'controlBackupTool.recovery.driver.operationTimeoutSeconds=300'))
  check(changed_plan['driver_plan_sha256'] != plan['driver_plan_sha256'], 'driver changes must update the digest')
  check(changed_plan['driver_plan_sha256'] == Digest::SHA256.hexdigest(changed.fetch('data').fetch('driver-plan.json')), 'changed driver bytes were not hashed')
  check(changed.dig('metadata', 'name') != plans.dig('metadata', 'name'), 'driver changes must create a new immutable ConfigMap')
  changed_volume = changed_cron.dig('spec', 'jobTemplate', 'spec', 'template', 'spec', 'volumes').find { |item| item['name'] == 'plan-source' }
  check(changed_volume.dig('configMap', 'name') == changed.dig('metadata', 'name'), 'CronJob retained the previous plan reference')
  changed_binding, = backup_parts(render(helm, chart, *arguments, '--set-string', 'controlBackupTool.installationId=e5d9c8b1-a56d-40c8-b83e-5837c6f572fb'))
  check(changed_binding.dig('metadata', 'name') != plans.dig('metadata', 'name'), 'installation binding changes must update the immutable plan name')

  [['default', []], ['production example', ['-f', File.join(chart, 'values-production.yaml')]]].each do |name, extra|
    check(render(helm, chart, *extra).none? { |document| document['kind'] == 'CronJob' }, "#{name} must not enable backups with unconfigured identities/digests")
  end
  {
    'missing installation' => ['--set-string', 'controlBackupTool.installationId='],
    'nil installation' => ['--set-string', 'controlBackupTool.installationId=00000000-0000-0000-0000-000000000000'],
    'noncanonical installation' => ['--set-string', 'controlBackupTool.installationId=E5D9C8B1-A56D-40C8-B83E-5837C6F572FA'],
    'invalid installation' => ['--set-string', 'controlBackupTool.installationId=chart-name'],
    'missing image digest' => ['--set-string', 'controlBackupTool.image.digest='],
    'missing manifest digest' => ['--set-string', "controlBackupTool.recovery.coreManifestSHA256=#{'0' * 64}"],
    'missing schema version' => ['--set', 'controlBackupTool.recovery.schemaVersion=0'],
    'unconfigured envelope key' => ['--set-string', 'controlBackupTool.recovery.envelopeKey.version=unconfigured-1'],
    'invalid signing key ID' => ['--set-string', 'controlBackupTool.signingKeyId=key+invalid']
  }.each do |name, extra|
    _, _, status = Open3.capture3(helm, 'template', 'cdnca', chart, *arguments, *extra)
    check(!status.success?, "#{name} was accepted for an enabled backup")
  end
end
puts 'CONTROL_BACKUP_HELM_CONTRACT PASS'
