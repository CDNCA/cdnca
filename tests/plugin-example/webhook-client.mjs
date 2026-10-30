import assert from "node:assert/strict";
import {createHash, createHmac, randomUUID} from "node:crypto";
import {readFile} from "node:fs/promises";

function required(name) {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
}

const target = required("CDNCA_PLUGIN_EXAMPLE_URL");
const secret = required("CDNCA_PLUGIN_EXAMPLE_SIGNING_SECRET");
assert.ok(Buffer.byteLength(secret) >= 32, "signing secret must be at least 32 bytes");
const event = JSON.parse(await readFile(new URL("domain-event-v1.json", import.meta.url), "utf8"));
if (process.env.CDNCA_PLUGIN_EXAMPLE_EVENT_ID) event.id = process.env.CDNCA_PLUGIN_EXAMPLE_EVENT_ID;
if (process.env.CDNCA_PLUGIN_EXAMPLE_TENANT_ID) event.tenant_id = process.env.CDNCA_PLUGIN_EXAMPLE_TENANT_ID;
if (process.env.CDNCA_PLUGIN_EXAMPLE_EVENT_TYPE) event.type = process.env.CDNCA_PLUGIN_EXAMPLE_EVENT_TYPE;
if (process.env.CDNCA_PLUGIN_EXAMPLE_SEQUENCE) event.sequence = Number(process.env.CDNCA_PLUGIN_EXAMPLE_SEQUENCE);
if (process.env.CDNCA_PLUGIN_EXAMPLE_DATA) event.data = JSON.parse(process.env.CDNCA_PLUGIN_EXAMPLE_DATA);

const signedBody = Buffer.from(JSON.stringify(event));
const sentBody = process.env.CDNCA_PLUGIN_EXAMPLE_TAMPER === "1" ? Buffer.concat([signedBody, Buffer.from(" ")]) : signedBody;
const timestamp = Math.floor(Date.now() / 1000) + Number(process.env.CDNCA_PLUGIN_EXAMPLE_TIMESTAMP_OFFSET || 0);
const deliveryID = process.env.CDNCA_PLUGIN_EXAMPLE_DELIVERY_ID || randomUUID();
const digest = createHash("sha256").update(signedBody).digest("hex");
const signaturePayload = `cdnca.webhook.signature/v1\n${timestamp}\n${deliveryID}\n${digest}`;
const signature = createHmac("sha256", secret).update(signaturePayload).digest("base64url");
const response = await fetch(target + "/webhooks/cdnca/v1", {
  method: "POST",
  headers: {
    "Content-Type": process.env.CDNCA_PLUGIN_EXAMPLE_CONTENT_TYPE || "application/cloudevents+json",
    "X-CDNCA-Webhook-Id": deliveryID,
    "X-CDNCA-Webhook-Timestamp": String(timestamp),
    "X-CDNCA-Webhook-Content-Sha256": digest,
    "X-CDNCA-Webhook-Signature": `v1=${signature}`,
    "X-CDNCA-Idempotency-Key": `plugin-example-${event.id}`,
    "X-CDNCA-Webhook-Attempt": "1"
  },
  body: sentBody
});
const body = await response.json();
const expected = process.env.CDNCA_PLUGIN_EXAMPLE_EXPECT_STATUS;
if (expected) assert.equal(response.status, Number(expected), JSON.stringify(body));
console.log(`${response.status} ${body.code}`);
