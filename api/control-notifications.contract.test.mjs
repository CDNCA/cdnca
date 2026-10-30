import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragmentPath = join(apiDir, "control-notifications.openapi.yaml");
const rootPath = join(apiDir, "openapi/v1/control.yaml");
const fragmentSource = readFileSync(fragmentPath, "utf8");
const rootSource = readFileSync(rootPath, "utf8");
const handler = readFileSync(join(root, "services/control-api/internal/notificationhttp/handler.go"), "utf8");
const store = readFileSync(join(root, "services/control-api/internal/notificationcontrol/store.go"), "utf8");
const controlModel = readFileSync(join(root, "services/control-api/internal/notificationcontrol/model.go"), "utf8");
const notificationModel = readFileSync(join(root, "services/control-api/internal/notification/model.go"), "utf8");
const announcementNotification = readFileSync(join(root, "services/control-api/cmd/control-api/announcement_notification_runtime.go"), "utf8");

const operations = [
  ["GET", "/v1/admin/notifications/channels", "getNotificationChannels", ["200", "400", "401", "403", "405", "500"], ["system_configuration.read"]],
  ["PUT", "/v1/admin/notifications/channels", "updateNotificationChannels", ["200", "400", "401", "403", "405", "409", "415", "500"], ["system_configuration.manage"]],
  ["GET", "/v1/admin/notifications/templates", "listNotificationTemplates", ["200", "400", "401", "403", "405", "500"], ["system_configuration.read"]],
  ["PUT", "/v1/admin/notifications/templates/{template_id}/versions/{version}/{channel}", "putNotificationTemplateVersion", ["200", "400", "401", "403", "405", "409", "415", "500"], ["system_configuration.manage"]],
  ["GET", "/v1/admin/notifications/deliveries", "listNotificationDeliveries", ["200", "400", "401", "403", "405", "500"], ["system_configuration.read"]],
  ["GET", "/v1/admin/notifications/deliveries/{outbox_id}/attempts", "listNotificationDeliveryAttempts", ["200", "400", "401", "403", "404", "405", "500"], ["system_configuration.read"]],
  ["GET", "/v1/account/notification-subscriptions/{event_type}", "getNotificationSubscription", ["200", "400", "401", "403", "404", "405", "500"], []],
  ["PUT", "/v1/account/notification-subscriptions/{event_type}", "updateNotificationSubscription", ["200", "400", "401", "403", "404", "405", "409", "415", "500"], []],
];

for (const [method, path] of operations) {
  assert.ok(handler.includes(`mux.HandleFunc("${method} ${path}",`), `real handler missing ${method} ${path}`);
}
for (const marker of [
  "notification.channels.update", "notification.template.create", "notification.subscription.update",
  "ErrChannelUnsupported", "ErrVersionConflict", "ErrTemplateVersionConflict",
]) {
  assert.ok(store.includes(marker) || controlModel.includes(marker), `notification control contract marker missing: ${marker}`);
}
assert.match(announcementNotification, /notificationcontrol\.ActiveTemplateRefs\(ctx, tx,/);
assert.doesNotMatch(announcementNotification, /announcementPublishedTemplateID, Version:\s*1/);
assert.match(notificationModel, /MaxEmailSubjectSourceBytes\s*=\s*2 \* 1024/);
assert.match(notificationModel, /MaxEmailBodySourceBytes\s*=\s*128 \* 1024/);

const temporaryDirectory = mkdtempSync(join(tmpdir(), "cdnca-notifications-openapi-"));
const bundlePath = join(temporaryDirectory, "control-notifications.json");
try {
  execFileSync("pnpm", ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragmentPath, "--output", bundlePath], {cwd: root, stdio: "pipe"});
  const document = JSON.parse(readFileSync(bundlePath, "utf8"));
  for (const [method, path, operationId, statuses, permissions] of operations) {
    const operation = document.paths?.[path]?.[method.toLowerCase()];
    assert.equal(operation?.operationId, operationId);
    assert.deepEqual(Object.keys(operation?.responses ?? {}).sort(), statuses);
    assert.deepEqual(operation?.["x-required-permissions"], permissions);
    if (method === "PUT") {
      assert.ok(operation?.parameters?.some((parameter) =>
        parameter?.name === "X-Request-ID" || parameter?.$ref === "#/components/parameters/OptionalRequestID"
      ), `${operationId} does not expose the existing optional X-Request-ID`);
    }
  }
  assert.equal(document.components.parameters.OptionalRequestID.name, "X-Request-ID");
  assert.equal(document.components.parameters.OptionalRequestID.required, false);
  assert.doesNotMatch(fragmentSource, /name:\s*Idempotency-Key/);
  // sms/email_supported follow the configuration, not a constant.
  assert.equal(document.components.schemas.ChannelSettings.properties.sms_supported.type, "boolean");
  assert.equal(document.components.schemas.ChannelSettings.properties.sms_supported.const, undefined);
  assert.equal(document.components.schemas.Subscription.properties.email_supported.const, undefined);
  assert.deepEqual(document.components.schemas.SwitchWrite.required.sort(), ["email_enabled", "sms_enabled"]);
  assert.equal(document.components.schemas.SwitchWrite.additionalProperties, false);
  assert.equal(document.components.schemas.Template.type, "object");
  assert.equal(document.components.schemas.Template.additionalProperties, false);
  assert.equal(document.components.schemas.Template.allOf, undefined);
  assert.deepEqual(document.components.schemas.Template.required.sort(), [
    "body", "changed", "channel", "created_at", "subject", "template_id", "variables", "version",
  ]);
  for (const schemaName of ["TemplateWrite", "Template"]) {
    const schema = document.components.schemas[schemaName];
    assert.equal(schema.properties.subject.maxLength, undefined);
    assert.equal(schema.properties.subject["x-max-bytes"], 2048);
    assert.match(schema.properties.subject.description, /UTF-8 bytes/i);
    assert.equal(schema.properties.body.maxLength, undefined);
    assert.equal(schema.properties.body["x-max-bytes"], 131072);
    assert.match(schema.properties.body.description, /UTF-8 bytes/i);
  }
  assert.equal(Buffer.byteLength("a".repeat(2048), "utf8"), 2048);
  assert.equal(Buffer.byteLength(`${"界".repeat(682)}ab`, "utf8"), 2048);
  assert.equal(Buffer.byteLength(`${"界".repeat(682)}abc`, "utf8"), 2049);
  assert.equal(Buffer.byteLength(`${"界".repeat(43690)}ab`, "utf8"), 131072);
  assert.equal(Buffer.byteLength(`${"界".repeat(43690)}abc`, "utf8"), 131073);
  assert.match(document.info.description, /email or SMS provider accepted.*not final delivery/i);

  // 400 validation_error may carry details {field, reason}
  // (notificationhttp writeFieldError); the envelope stays closed.
  const errorBody = document.components.schemas.Error.properties.error;
  assert.equal(errorBody.additionalProperties, false);
  assert.deepEqual(errorBody.required, ["code", "message", "request_id"]);
  const details = errorBody.properties.details;
  assert.equal(details.additionalProperties, false);
  assert.deepEqual(details.required, ["field", "reason"]);
  const fieldPattern = new RegExp(details.properties.field.pattern);
  const reasonPattern = new RegExp(details.properties.reason.pattern);
  for (const field of ["email_enabled", "timezone", "events[2].interval_hours", "variables[0]", "template_id"]) {
    assert.match(field, fieldPattern);
  }
  assert.doesNotMatch("Events[0]", fieldPattern);
  for (const reason of ["required", "too_long", "invalid_format", "out_of_range", "duplicate", "invalid"]) {
    assert.match(reason, reasonPattern);
  }
  assert.match(handler, /func writeFieldError\(w http\.ResponseWriter, r \*http\.Request, field, reason string\)/);
  assert.match(handler, /"details": map\[string\]string\{"field": field, "reason": reason\}/);

  let aggregateCount = 0;
  for (const [method, path, operationId] of operations) {
    const encodedPath = path.replaceAll("~", "~0").replaceAll("/", "~1");
    assert.ok(
      rootSource.includes(`  ${path}:\n    $ref: '../../control-notifications.openapi.yaml#/paths/${encodedPath}'`),
      `root aggregate missing ${method} ${path} (${operationId})`,
    );
    aggregateCount += 1;
  }
  assert.equal(aggregateCount, 8);
} finally {
  rmSync(temporaryDirectory, {recursive: true, force: true});
}

console.log(`notification OpenAPI contract: passed (${operations.length} operations)`);
