import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const bundledPath = process.argv[2];
assert.ok(bundledPath, "usage: node scripts/verify-signer-revocation-openapi.mjs <bundled-openapi.json>");

const root = new URL("../", import.meta.url);
const [openapi, fixtures] = await Promise.all([
  readFile(bundledPath, "utf8").then(JSON.parse),
  readFile(new URL("tests/contracts/signer-revocation-operator-responses.json", root), "utf8").then(JSON.parse),
]);

function compile(ref) {
  const ajv = new Ajv2020({allErrors: true, strict: false});
  addFormats(ajv);
  return ajv.compile({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $ref: ref,
    components: openapi.components,
  });
}

const validate = compile("#/components/schemas/CurrentSignerRevocationView");

for (const name of ["current_v1", "current_v2"]) {
  assert.equal(validate(fixtures[name]), true, `${name}: ${JSON.stringify(validate.errors)}`);
}

const invalidV2RootPublisher = structuredClone(fixtures.current_v2);
invalidV2RootPublisher.published_by = null;
assert.equal(validate(invalidV2RootPublisher), false, "v2 response with null root publisher was accepted");

const invalidV2NestedPublisher = structuredClone(fixtures.current_v2);
invalidV2NestedPublisher.proposal.publication.published_by = null;
assert.equal(validate(invalidV2NestedPublisher), false, "v2 response with null nested publisher was accepted");

const missingV2Publication = structuredClone(fixtures.current_v2);
delete missingV2Publication.proposal.publication;
assert.equal(validate(missingV2Publication), false, "published v2 response without publication was accepted");

const missingV2Approval = structuredClone(fixtures.current_v2);
delete missingV2Approval.proposal.approval;
assert.equal(validate(missingV2Approval), false, "published v2 response without approval was accepted");

const missingVersion = structuredClone(fixtures.current_v1);
delete missingVersion.workflow_version;
delete missingVersion.proposal.workflow_version;
assert.equal(validate(missingVersion), false, "response without workflow_version was accepted");

const validateProposal = compile("#/components/schemas/SignerRevocationProposal");
assert.equal(validateProposal(fixtures.approved_v2), true, JSON.stringify(validateProposal.errors));
const approvedWithoutApproval = structuredClone(fixtures.approved_v2);
delete approvedWithoutApproval.approval;
assert.equal(validateProposal(approvedWithoutApproval), false, "approved v2 proposal without approval was accepted");

const validateArtifactClasses = compile("#/components/schemas/SignerRevocationArtifactClasses");
assert.equal(validateArtifactClasses(fixtures.schema_cases.artifact_classes_canonical), true, JSON.stringify(validateArtifactClasses.errors));
assert.equal(validateArtifactClasses(fixtures.schema_cases.artifact_classes_noncanonical), false, "non-canonical artifact class order was accepted");

const validateProof = compile("#/components/parameters/SignerRevocationProof/schema");
assert.equal(validateProof(fixtures.schema_cases.proof_canonical), true, JSON.stringify(validateProof.errors));
assert.equal(validateProof(fixtures.schema_cases.proof_noncanonical_unused_bits), false, "proof with non-zero unused base64url bits was accepted");

const validateInstallationID = compile("#/components/parameters/SignerRevocationInstallationId/schema");
assert.equal(validateInstallationID(fixtures.schema_cases.installation_id), true, JSON.stringify(validateInstallationID.errors));
assert.equal(validateInstallationID(fixtures.schema_cases.nil_installation_id), false, "nil installation UUID was accepted");
