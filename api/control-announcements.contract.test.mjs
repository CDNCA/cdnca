import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync, readFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname, join, resolve} from "node:path";
import {fileURLToPath} from "node:url";

const apiDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(apiDir, "..");
const fragmentPath = join(apiDir, "control-announcements.openapi.yaml");
const handlerPath = join(root, "services/control-api/internal/announcementhttp/handler.go");
const storePath = join(root, "services/control-api/internal/announcement/store.go");
const inboxPath = join(root, "services/control-api/internal/announcement/inbox.go");
const modelPath = join(root, "services/control-api/internal/announcement/model.go");

const handler = readFileSync(handlerPath, "utf8");
const store = readFileSync(storePath, "utf8");
const inbox = readFileSync(inboxPath, "utf8");
const model = readFileSync(modelPath, "utf8");

const operations = [
  ["GET", "/v1/admin/announcements/global", "listGlobalAnnouncements", ["200", "400", "401", "403", "500"]],
  ["POST", "/v1/admin/announcements/global", "createGlobalAnnouncement", ["201", "400", "401", "403", "409", "415", "422", "500"]],
  ["GET", "/v1/admin/announcements/global/audience-directory", "searchGlobalAnnouncementAudience", ["200", "400", "401", "403", "500"]],
  ["GET", "/v1/admin/announcements/global/{id}/audience/count", "countGlobalAnnouncementAudience", ["200", "400", "401", "403", "404", "500"]],
  ["GET", "/v1/admin/announcements/global/{id}", "getGlobalAnnouncement", ["200", "400", "401", "403", "404", "500"]],
  ["PATCH", "/v1/admin/announcements/global/{id}", "updateGlobalAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "422", "500"]],
  ["POST", "/v1/admin/announcements/global/{id}/publish", "publishGlobalAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "422", "500"]],
  ["POST", "/v1/admin/announcements/global/{id}/withdraw", "withdrawGlobalAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/global/{id}/archive", "archiveGlobalAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/global/{id}/restore", "restoreGlobalAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["GET", "/v1/admin/announcements", "listAnnouncements", ["200", "400", "401", "403", "500"]],
  ["POST", "/v1/admin/announcements", "createAnnouncementDraft", ["201", "400", "401", "403", "409", "415", "422", "500"]],
  ["GET", "/v1/admin/announcements/audience-directory", "searchAnnouncementAudience", ["200", "400", "401", "403", "500"]],
  ["GET", "/v1/admin/announcements/{id}/audience/count", "countAnnouncementAudience", ["200", "400", "401", "403", "404", "500"]],
  ["GET", "/v1/admin/announcements/{id}", "getAnnouncement", ["200", "400", "401", "403", "404", "500"]],
  ["PATCH", "/v1/admin/announcements/{id}", "updateAnnouncementDraft", ["200", "400", "401", "403", "404", "409", "415", "422", "500"]],
  ["POST", "/v1/admin/announcements/{id}/schedule", "scheduleAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/{id}/publish", "publishAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/{id}/revise", "reviseAnnouncement", ["201", "400", "401", "403", "404", "409", "415", "422", "500"]],
  ["POST", "/v1/admin/announcements/{id}/withdraw", "withdrawAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/{id}/archive", "archiveAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/admin/announcements/{id}/restore", "restoreAnnouncement", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["GET", "/v1/account/messages", "listAccountMessages", ["200", "400", "401", "403", "500"]],
  ["POST", "/v1/account/messages/{event_id}/delivered", "markMessageDelivered", ["200", "400", "401", "403", "404", "409", "415", "500"]],
  ["POST", "/v1/account/messages/{event_id}/read", "markMessageRead", ["200", "400", "401", "403", "404", "409", "415", "500"]],
];

const jsonWriteOperationIds = new Set([
  "createGlobalAnnouncement",
  "updateGlobalAnnouncement",
  "publishGlobalAnnouncement",
  "withdrawGlobalAnnouncement",
  "createAnnouncementDraft",
  "updateAnnouncementDraft",
  "scheduleAnnouncement",
  "publishAnnouncement",
  "reviseAnnouncement",
  "withdrawAnnouncement",
  "archiveAnnouncement",
  "restoreAnnouncement",
  "markMessageDelivered",
  "markMessageRead",
]);

for (const [method, path] of operations) {
  assert.ok(
    handler.includes(`mux.HandleFunc("${method} ${path}",`),
    `real handler route missing: ${method} ${path}`,
  );
}

for (const marker of [
  'http.StatusUnauthorized, "invalid_session"',
  'http.StatusForbidden, "permission_denied"',
  'http.StatusBadRequest, "validation_error"',
  'http.StatusUnsupportedMediaType, "unsupported_media_type"',
  'http.StatusUnprocessableEntity, "audience_scope_denied"',
  'http.StatusConflict, "empty_audience"',
  'http.StatusNotFound, "announcement_not_found"',
  'http.StatusConflict, "version_conflict"',
  'http.StatusConflict, "announcement_state_conflict"',
  'http.StatusConflict, "idempotency_conflict"',
]) {
  assert.ok(handler.includes(marker), `real handler error mapping missing: ${marker}`);
}

for (const marker of [
  "func (s *Store) CreateDraft",
  "func (s *Store) UpdateDraft",
  "func (s *Store) Schedule",
  "func (s *Store) Publish",
  "func (s *Store) Revise",
  "func (s *Store) Withdraw",
  "func (s *Store) Archive",
  "func (s *Store) Restore",
  "return ErrAudienceScopeDenied",
  "return Announcement{}, ErrEmptyAudience",
  "return rootState{}, ErrNotFound",
  "return nil, false, ErrIdempotencyConflict",
]) {
  assert.ok(store.includes(marker), `real announcement store evidence missing: ${marker}`);
}
for (const marker of [
  "func (s *Store) ListInbox",
  "func (s *Store) MarkDelivered",
  "func (s *Store) MarkRead",
  "return ErrNotFound",
  "return ErrRevisionConflict",
]) {
  assert.ok(inbox.includes(marker), `real inbox store evidence missing: ${marker}`);
}
assert.ok(
  model.includes('UserIDs  []uuid.UUID `json:"user_ids,omitempty"`') &&
    model.includes('GroupIDs []uuid.UUID `json:"group_ids,omitempty"`'),
  "real Audience wire arrays must remain optional",
);
assert.ok(
  store.includes("return Audience{All: true}, nil"),
  "real all-audience response must remain expressible as {all:true}",
);

const temporaryDir = mkdtempSync(join(tmpdir(), "cdnca-announcements-openapi-"));
const bundlePath = join(temporaryDir, "control-announcements.json");
try {
  execFileSync(
    "pnpm",
    ["--package=@redocly/cli@1.34.5", "dlx", "redocly", "bundle", fragmentPath, "--output", bundlePath],
    {cwd: root, stdio: "pipe"},
  );
  const document = JSON.parse(readFileSync(bundlePath, "utf8"));

  for (const [method, path, operationId, expectedStatuses] of operations) {
    const operation = document.paths?.[path]?.[method.toLowerCase()];
    assert.ok(operation, `fragment operation missing: ${method} ${path}`);
    assert.equal(operation.operationId, operationId, `${method} ${path} operationId drifted`);
    assert.deepEqual(
      Object.keys(operation.responses ?? {}).sort(),
      expectedStatuses,
      `${operationId} response status matrix does not match the real handler`,
    );
    for (const status of expectedStatuses.filter((value) => Number(value) >= 400)) {
      assert.equal(
        operation.responses[status]?.$ref,
        "#/components/responses/Error",
        `${operationId} ${status} must reuse the stable Error response`,
      );
    }
    if (jsonWriteOperationIds.has(operationId)) {
      assert.equal(
        operation.requestBody?.required,
        true,
        `${operationId} must require the JSON command body handled by decode`,
      );
      assert.ok(
        operation.requestBody?.content?.["application/json"]?.schema,
        `${operationId} must declare application/json`,
      );
      assert.equal(
        operation.responses?.["415"]?.$ref,
        "#/components/responses/Error",
        `${operationId} 415 must use the stable Error response`,
      );
    }
  }

  assert.equal(jsonWriteOperationIds.size, 14, "all production JSON writes must declare 415");

  const audience = document.components?.schemas?.Audience;
  assert.deepEqual(audience?.required, ["all"], "Audience response arrays must be optional");
  assert.equal(audience?.properties?.all?.type, "boolean");
  assert.equal(audience?.properties?.user_ids?.type, "array");
  assert.equal(audience?.properties?.group_ids?.type, "array");
  assert.match(audience?.description ?? "", /all=true requires both arrays to be empty/);
  assert.ok(
    audience?.examples?.some((example) =>
      example?.all === true && !("user_ids" in example) && !("group_ids" in example)),
    "Audience examples must include the real {all:true} wire response",
  );

  const audienceInput = document.components?.schemas?.AnnouncementInput;
  assert.ok(audienceInput?.required?.includes("user_ids"));
  assert.ok(audienceInput?.required?.includes("group_ids"));
  assert.equal(audienceInput?.properties?.user_ids?.type, "array");
  assert.equal(audienceInput?.properties?.group_ids?.type, "array");
  assert.notEqual(audienceInput?.properties?.user_ids?.nullable, true);
  assert.notEqual(audienceInput?.properties?.group_ids?.nullable, true);

  const error = document.components?.schemas?.Error;
  assert.deepEqual(error?.required, ["error"]);
  assert.deepEqual(error?.properties?.error?.required, ["code", "message", "request_id"]);
} finally {
  rmSync(temporaryDir, {recursive: true, force: true});
}

console.log(`announcement OpenAPI contract: passed (${operations.length} operations)`);
