#!/usr/bin/env node

import {createHash, createHmac, createPublicKey, verify} from "node:crypto";
import {existsSync, mkdtempSync, readFileSync, readdirSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {basename, dirname, extname, join, relative, resolve, sep} from "node:path";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {isDeepStrictEqual} from "node:util";

import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const HTTP_METHODS = new Set(["delete", "get", "head", "options", "patch", "post", "put", "trace"]);
const REDOCLY_VERSION = "1.34.5";
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function listFiles(root, predicate) {
  if (!existsSync(root)) return [];
  const files = [];
  for (const entry of readdirSync(root, {withFileTypes: true})) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...listFiles(path, predicate));
    else if (entry.isFile() && predicate(path)) files.push(path);
  }
  return files.sort();
}

function pointerToken(value) {
  return String(value).replaceAll("~", "~0").replaceAll("/", "~1");
}

function repoPath(root, path) {
  return relative(root, path).split(sep).join("/");
}

function lineAt(text, offset) {
  return text.slice(0, offset).split("\n").length;
}

function parseJSON(path, errors, root) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    errors.push(`${repoPath(root, path)}:$: invalid JSON: ${error.message}`);
    return null;
  }
}

function resolvePointer(document, reference) {
  if (typeof reference !== "string" || !reference.startsWith("#/")) return null;
  let value = document;
  for (const rawPart of reference.slice(2).split("/")) {
    const part = rawPart.replaceAll("~1", "/").replaceAll("~0", "~");
    if (value === null || typeof value !== "object" || !Object.hasOwn(value, part)) return null;
    value = value[part];
  }
  return value;
}

function dereference(document, value) {
  const seen = new Set();
  let current = value;
  while (current && typeof current === "object" && typeof current.$ref === "string") {
    if (!current.$ref.startsWith("#/") || seen.has(current.$ref)) return null;
    seen.add(current.$ref);
    current = resolvePointer(document, current.$ref);
  }
  return current;
}

function parseAttributes(raw, location, errors) {
  const attributes = {};
  const consumed = [];
  const pattern = /([a-z][a-z0-9_-]*)="([^"]*)"/gi;
  for (const match of raw.matchAll(pattern)) {
    attributes[match[1]] = match[2];
    consumed.push([match.index, match.index + match[0].length]);
  }
  let remainder = raw;
  for (const [start, end] of consumed.reverse()) remainder = remainder.slice(0, start) + remainder.slice(end);
  if (remainder.trim()) errors.push(`${location}: invalid contract-doc marker attributes: ${remainder.trim()}`);
  return attributes;
}

function scanDocumentation(root, errors) {
  const developerRoot = join(root, "docs", "developer");
  const docs = listFiles(developerRoot, (path) => extname(path) === ".md");
  const referenceAPI = join(root, "docs", "reference-api.md");
  if (existsSync(referenceAPI)) docs.push(referenceAPI);
  const markers = [];

  for (const path of docs.sort()) {
    const text = readFileSync(path, "utf8");
    const relativePath = repoPath(root, path);
    const markerPattern = /<!--\s*contract-doc:([a-z][a-z0-9-]*)\s+([\s\S]*?)-->/gi;
    for (const match of text.matchAll(markerPattern)) {
      const line = lineAt(text, match.index);
      const location = `${relativePath}:${line}`;
      markers.push({kind: match[1], attributes: parseAttributes(match[2], location, errors), path, line, location});
    }

    const linkPattern = /!?\[[^\]]*\]\(([^)]+)\)/g;
    for (const match of text.matchAll(linkPattern)) {
      let target = match[1].trim();
      if (target.startsWith("<") && target.includes(">")) target = target.slice(1, target.indexOf(">"));
      else target = target.split(/\s+["']/)[0];
      if (!target || /^(?:[a-z]+:|#)/i.test(target)) continue;
      try {
        target = decodeURIComponent(target.split("#", 1)[0]);
      } catch {
        errors.push(`${relativePath}:${lineAt(text, match.index)}: invalid percent-encoding in local link: ${target}`);
        continue;
      }
      const resolved = resolve(dirname(path), target);
      const location = `${relativePath}:${lineAt(text, match.index)}`;
      if (!resolved.startsWith(root + sep) && resolved !== root) {
        errors.push(`${location}: link escapes repository: ${target}`);
      } else if (!existsSync(resolved)) {
        errors.push(`${location}: linked local file does not exist: ${target}`);
      }
    }
  }
  return {docs, markers};
}

function markerPath(root, marker, attribute, errors) {
  const value = marker.attributes[attribute];
  if (!value) {
    errors.push(`${marker.location}:${attribute}: required marker attribute is missing`);
    return null;
  }
  const path = resolve(dirname(marker.path), value);
  if ((!path.startsWith(root + sep) && path !== root) || !existsSync(path)) {
    errors.push(`${marker.location}:${attribute}: referenced local file does not exist: ${value}`);
    return null;
  }
  return path;
}

function loadOpenAPIDocuments(root, errors) {
  const sources = listFiles(join(root, "api", "openapi"), (path) => [".json", ".yaml", ".yml"].includes(extname(path)));
  if (sources.length === 0) {
    errors.push("api/openapi:$: no OpenAPI documents found");
    return [];
  }
  const temporary = mkdtempSync(join(tmpdir(), "cdnca-contract-doc-"));
  const documents = [];
  try {
    for (const [index, source] of sources.entries()) {
      let path = source;
      if (extname(source) !== ".json") {
        path = join(temporary, `${index}-${basename(source).replace(/\.(?:yaml|yml)$/i, ".json")}`);
        const result = spawnSync(
          "pnpm",
          ["--package", `@redocly/cli@${REDOCLY_VERSION}`, "dlx", "redocly", "bundle", source, "--output", path],
          {
            cwd: root,
            encoding: "utf8",
            env: {...process.env, REDOCLY_TELEMETRY: "off", REDOCLY_SUPPRESS_UPDATE_NOTICE: "true"}
          }
        );
        if (result.status !== 0) {
          errors.push(`${repoPath(root, source)}:$: Redocly bundle failed: ${(result.stderr || result.stdout).trim()}`);
          continue;
        }
      }
      const document = parseJSON(path, errors, path === source ? root : temporary);
      if (document) documents.push({source, relativePath: repoPath(root, source), document});
    }
  } finally {
    rmSync(temporary, {recursive: true, force: true});
  }
  return documents;
}

function schemaHasStableError(document, schema, seen = new Set()) {
  if (!schema || typeof schema !== "object") return false;
  if (schema.$ref) {
    if (seen.has(schema.$ref)) return false;
    seen.add(schema.$ref);
    return schemaHasStableError(document, resolvePointer(document, schema.$ref), seen);
  }
  const properties = schema.properties ?? {};
  if (properties.code && properties.request_id) return true;
  if (Object.values(properties).some((child) => schemaHasStableError(document, child, new Set(seen)))) return true;
  return ["allOf", "anyOf", "oneOf"].some((key) =>
    Array.isArray(schema[key]) && schema[key].some((child) => schemaHasStableError(document, child, new Set(seen)))
  );
}

function absoluteSchemaRefs(value, documentID) {
  if (Array.isArray(value)) return value.map((item) => absoluteSchemaRefs(item, documentID));
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, child] of Object.entries(value)) {
    result[key] = key === "$ref" && typeof child === "string" && child.startsWith("#/")
      ? documentID + child
      : absoluteSchemaRefs(child, documentID);
  }
  return result;
}

function validateOpenAPIExamples(entry, ajv, documentID, errors) {
  const {document, relativePath} = entry;
  const validate = (schema, value, pointer) => {
    try {
      const validator = ajv.compile(absoluteSchemaRefs(schema, documentID));
      if (!validator(value)) {
        const detail = validator.errors?.map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
        errors.push(`${relativePath}#${pointer}: example does not satisfy schema: ${detail}`);
      }
    } catch (error) {
      errors.push(`${relativePath}#${pointer}: example schema could not be compiled: ${error.message}`);
    }
  };

  const scanSchema = (schema, pointer, seen = new Set()) => {
    if (!schema || typeof schema !== "object") return;
    if (schema.$ref) {
      if (seen.has(schema.$ref)) return;
      seen.add(schema.$ref);
      scanSchema(resolvePointer(document, schema.$ref), schema.$ref.slice(1), seen);
      return;
    }
    if (Object.hasOwn(schema, "example")) validate(schema, schema.example, `${pointer}/example`);
    if (Array.isArray(schema.examples)) {
      schema.examples.forEach((example, index) => validate(schema, example, `${pointer}/examples/${index}`));
    }
    for (const [name, child] of Object.entries(schema.properties ?? {})) {
      scanSchema(child, `${pointer}/properties/${pointerToken(name)}`, new Set(seen));
    }
    if (schema.items) scanSchema(schema.items, `${pointer}/items`, new Set(seen));
    for (const key of ["allOf", "anyOf", "oneOf"]) {
      (schema[key] ?? []).forEach((child, index) => scanSchema(child, `${pointer}/${key}/${index}`, new Set(seen)));
    }
  };

  const scanMedia = (media, pointer) => {
    if (!media || typeof media !== "object" || !media.schema) return;
    if (Object.hasOwn(media, "example")) validate(media.schema, media.example, `${pointer}/example`);
    for (const [name, example] of Object.entries(media.examples ?? {})) {
      const resolved = dereference(document, example);
      if (resolved && Object.hasOwn(resolved, "value")) validate(media.schema, resolved.value, `${pointer}/examples/${pointerToken(name)}/value`);
    }
    scanSchema(media.schema, `${pointer}/schema`);
  };

  for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(method)) continue;
      const base = `/paths/${pointerToken(path)}/${method}`;
      const requestBody = dereference(document, operation.requestBody);
      for (const [type, media] of Object.entries(requestBody?.content ?? {})) scanMedia(media, `${base}/requestBody/content/${pointerToken(type)}`);
      for (const [status, rawResponse] of Object.entries(operation.responses ?? {})) {
        const response = dereference(document, rawResponse);
        for (const [type, media] of Object.entries(response?.content ?? {})) scanMedia(media, `${base}/responses/${status}/content/${pointerToken(type)}`);
        for (const [name, rawHeader] of Object.entries(response?.headers ?? {})) {
          const header = dereference(document, rawHeader);
          if (header?.schema) scanSchema(header.schema, `${base}/responses/${status}/headers/${pointerToken(name)}/schema`);
        }
      }
      const parameters = [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])];
      parameters.forEach((rawParameter, index) => {
        const parameter = dereference(document, rawParameter);
        if (!parameter?.schema) return;
        if (Object.hasOwn(parameter, "example")) validate(parameter.schema, parameter.example, `${base}/parameters/${index}/example`);
        scanSchema(parameter.schema, `${base}/parameters/${index}/schema`);
      });
    }
  }
  for (const [name, schema] of Object.entries(document.components?.schemas ?? {})) {
    scanSchema(schema, `/components/schemas/${pointerToken(name)}`);
  }
}

function idempotencyPatternPreservesBounds(schema) {
  if (!schema?.pattern) return true;
  let pattern;
  try {
    pattern = new RegExp(schema.pattern, "u");
  } catch {
    return false;
  }
  const characters = ["A", "a", "0", "_", "-", ".", "!"];
  return [1, 128].every((length) => characters.some((character) => pattern.test(character.repeat(length))));
}

function checkOpenAPI(documents, errors) {
  const crossDocumentOperations = new Map();
  let operationCount = 0;
  for (const entry of documents) {
    const {document, relativePath} = entry;
    if (!/^3\.1\./.test(document.openapi ?? "")) errors.push(`${relativePath}#/openapi: expected OpenAPI 3.1.x`);
    if (!SEMVER.test(document.info?.version ?? "")) errors.push(`${relativePath}#/info/version: expected semantic version`);
    const documentIDs = new Map();
    const documentID = `urn:cdnca:contract-doc:${encodeURIComponent(relativePath)}`;
    const schemaDocument = structuredClone(document);
    schemaDocument.$id = documentID;
    const ajv = new Ajv2020({allErrors: true, strict: false, validateFormats: false});
    addFormats(ajv);
    try {
      ajv.addSchema(schemaDocument, documentID);
    } catch (error) {
      errors.push(`${relativePath}#/: OpenAPI schemas could not be indexed: ${error.message}`);
    }

    for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
      if (path !== "/health/live" && path !== "/health/ready" && !/(?:^|\/)v[1-9][0-9]*(?:\/|:|$)/.test(path)) {
        errors.push(`${relativePath}#/paths/${pointerToken(path)}: public path has no /vN version segment`);
      }
      for (const [method, operation] of Object.entries(pathItem)) {
        if (!HTTP_METHODS.has(method)) continue;
        operationCount += 1;
        const base = `/paths/${pointerToken(path)}/${method}`;
        const operationID = operation.operationId;
        if (typeof operationID !== "string" || !operationID) {
          errors.push(`${relativePath}#${base}/operationId: non-empty operationId is required`);
        } else if (documentIDs.has(operationID)) {
          errors.push(`${relativePath}#${base}/operationId: duplicate operationId ${operationID}; first defined at ${documentIDs.get(operationID)}`);
        } else {
          documentIDs.set(operationID, `${method.toUpperCase()} ${path}`);
          const tuple = `${method.toUpperCase()} ${path}`;
          const previous = crossDocumentOperations.get(operationID);
          if (previous && previous.tuple !== tuple) {
            errors.push(`${relativePath}#${base}/operationId: operationId ${operationID} maps to ${tuple}, but ${previous.file} maps it to ${previous.tuple}`);
          } else if (!previous) {
            crossDocumentOperations.set(operationID, {tuple, file: relativePath});
          }
        }

        const security = operation.security ?? document.security;
        if (!Array.isArray(security)) {
          errors.push(`${relativePath}#${base}/security: operation must explicitly define or inherit an authentication policy`);
        } else {
          for (const requirement of security) {
            for (const scheme of Object.keys(requirement ?? {})) {
              if (!document.components?.securitySchemes?.[scheme]) {
                errors.push(`${relativePath}#${base}/security/${pointerToken(scheme)}: unknown security scheme`);
              }
            }
          }
        }

        if (Object.hasOwn(operation, "x-required-permissions")) {
          const permissions = operation["x-required-permissions"];
          if (!Array.isArray(permissions) || permissions.length === 0 || permissions.some((value) => typeof value !== "string" || !value)) {
            errors.push(`${relativePath}#${base}/x-required-permissions: expected a non-empty string array`);
          }
          if (!operation.responses?.["403"]) errors.push(`${relativePath}#${base}/responses/403: permission-gated operation must document denial`);
        } else if (security?.length > 0 && !operation.responses?.["401"] && !operation.responses?.["403"] && !/(?:^|\/)(?:auth|session)(?:\/|$)/.test(path)) {
          errors.push(`${relativePath}#${base}/responses: protected non-session operation must document authentication or authorization denial with 401 or 403`);
        }

        const effectiveParameters = new Map();
        for (const rawParameter of [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])]) {
          const parameter = dereference(document, rawParameter);
          if (!parameter) continue;
          const name = parameter.in === "header" ? parameter.name?.toLowerCase() : parameter.name;
          effectiveParameters.set(`${parameter.in}\0${name}`, parameter);
        }
        const idempotency = [...effectiveParameters.values()].find(
          (parameter) => parameter?.in === "header" && parameter?.name?.toLowerCase() === "idempotency-key"
        );
        if (idempotency) {
          if (idempotency.required !== true) errors.push(`${relativePath}#${base}/parameters/Idempotency-Key/required: must be true`);
          const schema = dereference(document, idempotency.schema);
          if (schema?.type !== "string" || schema?.minLength !== 1 || schema?.maxLength !== 128) {
            errors.push(`${relativePath}#${base}/parameters/Idempotency-Key/schema: expected type string with minLength 1 and maxLength 128`);
          }
          if (!idempotencyPatternPreservesBounds(schema)) {
            errors.push(`${relativePath}#${base}/parameters/Idempotency-Key/schema/pattern: must preserve accepted values at lengths 1 and 128`);
          }
          const hasSuccessResponse = Object.keys(operation.responses ?? {}).some((status) => /^[23][0-9X]{2}$/.test(status));
          if (hasSuccessResponse && !operation.responses?.["409"]) {
            errors.push(`${relativePath}#${base}/responses/409: idempotent operation must document key/payload conflict`);
          }
        }

        for (const [status, rawResponse] of Object.entries(operation.responses ?? {})) {
          if (!/^[45][0-9X]{2}$/.test(status) && status !== "default") continue;
          const response = dereference(document, rawResponse);
          const mediaEntries = Object.entries(response?.content ?? {});
          const validErrorContent = mediaEntries.length > 0 && mediaEntries.every(([type, media]) => {
            const schema = dereference(document, media?.schema);
            if (!schema || typeof schema !== "object" || Array.isArray(schema)) return false;
            const mediaType = type.split(";", 1)[0].trim();
            if (/(?:\/|\+)json$/i.test(mediaType)) return schemaHasStableError(document, schema);
            // Only an explicit non-JSON media type can opt out; wildcards cannot.
            return /^[a-z0-9!#$%&'+.^_`|~-]+\/[a-z0-9!#$%&'+.^_`|~-]+$/i.test(mediaType);
          });
          if (!validErrorContent) {
            errors.push(`${relativePath}#${base}/responses/${status}: error response must expose stable code and request_id fields`);
          }
        }

        if (operation.deprecated === true) {
          for (const field of ["x-deprecated-since", "x-sunset-after", "x-replacement-operation-id"]) {
            if (typeof operation[field] !== "string" || !operation[field]) errors.push(`${relativePath}#${base}/${field}: required for deprecated operation`);
          }
        }
      }
    }
    validateOpenAPIExamples(entry, ajv, documentID, errors);
  }
  return operationCount;
}

function checkOpenAPIDocumentation(root, markers, documents, errors) {
  const documented = new Set();
  for (const marker of markers.filter(({kind}) => kind === "openapi")) {
    const path = markerPath(root, marker, "file", errors);
    if (!path) continue;
    if (![".json", ".yaml", ".yml"].includes(extname(path))) {
      errors.push(`${marker.location}:file: OpenAPI marker must reference a JSON or YAML document`);
      continue;
    }
    documented.add(path);
  }
  for (const {source, relativePath} of documents) {
    if (!documented.has(source)) errors.push(`${relativePath}:$: no contract-doc:openapi documentation marker found`);
  }
}

function matchingBrace(text, open) {
  let depth = 0;
  for (let index = open; index < text.length; index += 1) {
    if (text[index] === "{") depth += 1;
    else if (text[index] === "}" && --depth === 0) return index;
  }
  return -1;
}

function parseProto(path, root, errors) {
  const source = readFileSync(path, "utf8");
  const clean = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  const packageName = /^\s*package\s+([A-Za-z0-9_.]+)\s*;/m.exec(clean)?.[1];
  if (!packageName) errors.push(`${repoPath(root, path)}:1:package: package declaration is required`);
  else if (!/\.v[1-9][0-9]*$/.test(packageName)) errors.push(`${repoPath(root, path)}:1:package: package must end in .vN`);
  const messages = new Set([...clean.matchAll(/\b(?:message|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/g)].map((match) => match[1]));
  const services = new Map();
  for (const match of clean.matchAll(/\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/g)) {
    const open = match.index + match[0].lastIndexOf("{");
    const close = matchingBrace(clean, open);
    if (close < 0) {
      errors.push(`${repoPath(root, path)}:${lineAt(clean, match.index)}:service: unclosed service ${match[1]}`);
      continue;
    }
    const body = clean.slice(open + 1, close);
    const methods = new Map();
    for (const rpc of body.matchAll(/\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:stream\s+)?([.A-Za-z0-9_]+)\s*\)\s*returns\s*\(\s*(?:stream\s+)?([.A-Za-z0-9_]+)\s*\)\s*;/g)) {
      methods.set(rpc[1], {request: rpc[2], response: rpc[3]});
    }
    services.set(match[1], methods);
  }
  for (const match of source.matchAll(/(?:\[\s*deprecated\s*=\s*true\s*\]|option\s+deprecated\s*=\s*true\s*;)/g)) {
    const prefix = source.slice(0, match.index).split("\n").slice(-3).join("\n");
    if (!/Deprecated:\s*since=v[1-9][0-9]*\s+replacement=[A-Za-z0-9_.]+/.test(prefix)) {
      errors.push(`${repoPath(root, path)}:${lineAt(source, match.index)}:deprecated: marker requires "Deprecated: since=vN replacement=Symbol" comment`);
    }
  }
  return {path, relativePath: repoPath(root, path), packageName, messages, services};
}

function checkProto(root, markers, errors) {
  const files = listFiles(join(root, "proto"), (path) => extname(path) === ".proto");
  if (files.length === 0) errors.push("proto:$: no protobuf contracts found");
  const parsed = new Map(files.map((path) => [path, parseProto(path, root, errors)]));
  const packageSymbols = new Map();
  for (const file of parsed.values()) {
    const symbols = packageSymbols.get(file.packageName) ?? new Set();
    for (const message of file.messages) symbols.add(message);
    packageSymbols.set(file.packageName, symbols);
  }
  const documentedServices = new Set();
  for (const marker of markers.filter(({kind}) => kind === "proto")) {
    const path = markerPath(root, marker, "file", errors);
    if (!path) continue;
    const file = parsed.get(path);
    if (!file) {
      errors.push(`${marker.location}:file: referenced file is not a discovered .proto contract`);
      continue;
    }
    const serviceName = marker.attributes.service;
    const service = file.services.get(serviceName);
    if (!service) {
      errors.push(`${marker.location}:service: ${serviceName || "<missing>"} does not exist in ${file.relativePath}`);
      continue;
    }
    documentedServices.add(`${file.relativePath}#${serviceName}`);
    const methods = (marker.attributes.methods ?? "").split(",").filter(Boolean);
    if (methods.length === 0) errors.push(`${marker.location}:methods: at least one method reference is required`);
    for (const method of methods) {
      if (!service.has(method)) errors.push(`${marker.location}:methods: ${serviceName}.${method} does not exist in ${file.relativePath}`);
    }
    for (const method of service.keys()) {
      if (!methods.includes(method)) errors.push(`${marker.location}:methods: ${serviceName}.${method} is not referenced by the documentation marker`);
    }
    const messages = (marker.attributes.messages ?? "").split(",").filter(Boolean);
    if (messages.length === 0) errors.push(`${marker.location}:messages: at least one message reference is required`);
    for (const message of messages) {
      const localName = message.split(".").at(-1);
      if (!packageSymbols.get(file.packageName)?.has(localName)) {
        errors.push(`${marker.location}:messages: ${message} does not exist in protobuf package ${file.packageName}`);
      }
    }
    for (const [method, signature] of service) {
      if (!methods.includes(method)) continue;
      for (const type of [signature.request, signature.response]) {
        const localName = type.split(".").at(-1);
        if (!packageSymbols.get(file.packageName)?.has(localName)) {
          errors.push(`${file.relativePath}:service.${serviceName}.${method}: referenced message ${type} does not exist in package ${file.packageName}`);
        }
        if (!messages.includes(localName) && !messages.includes(type)) {
          errors.push(`${marker.location}:messages: ${serviceName}.${method} message ${type} is not referenced by the documentation marker`);
        }
      }
    }
  }
  for (const file of parsed.values()) {
    for (const service of file.services.keys()) {
      if (!documentedServices.has(`${file.relativePath}#${service}`)) {
        errors.push(`${file.relativePath}:service.${service}: no contract-doc:proto documentation marker found`);
      }
    }
  }
  return [...parsed.values()].reduce((count, file) => count + file.services.size, 0);
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function rawEd25519PublicKey(value) {
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32) throw new Error("public key must decode to 32 bytes");
  return createPublicKey({key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki"});
}

function checkManifestSignature(root, marker, manifest, errors) {
  const publisherPath = markerPath(root, marker, "publisher", errors);
  if (!publisherPath) return;
  const publisher = parseJSON(publisherPath, errors, root);
  if (!publisher) return;
  const unsigned = structuredClone(manifest);
  delete unsigned.integrity;
  const digest = createHash("sha256").update(canonicalize(unsigned), "utf8").digest();
  if (manifest.integrity?.payload_sha256 !== digest.toString("hex")) {
    errors.push(`${repoPath(root, markerPath(root, marker, "file", errors))}#/integrity/payload_sha256: manifest digest mismatch`);
    return;
  }
  if (publisher.key_id !== manifest.integrity?.key_id || publisher.algorithm !== manifest.integrity?.algorithm) {
    errors.push(`${repoPath(root, publisherPath)}#/: publisher key metadata does not match manifest integrity envelope`);
    return;
  }
  try {
    const message = Buffer.concat([Buffer.from("cdnca-plugin-manifest/v1\n"), digest]);
    if (!verify(null, message, rawEd25519PublicKey(publisher.public_key_base64url), Buffer.from(manifest.integrity.signature, "base64url"))) {
      errors.push(`${repoPath(root, markerPath(root, marker, "file", errors))}#/integrity/signature: Ed25519 signature mismatch`);
    }
  } catch (error) {
    errors.push(`${repoPath(root, publisherPath)}#/public_key_base64url: ${error.message}`);
  }
}

function checkWebhookVector(root, marker, errors) {
  const vectorPath = markerPath(root, marker, "vector", errors);
  if (!vectorPath) return;
  const vector = parseJSON(vectorPath, errors, root);
  if (!vector) return;
  const body = Buffer.from(vector.body_utf8 ?? "", "utf8");
  const digest = createHash("sha256").update(body).digest("hex");
  if (vector.domain !== "cdnca.webhook.signature/v1") errors.push(`${repoPath(root, vectorPath)}#/domain: unsupported Webhook signature domain`);
  if (vector.content_sha256 !== digest) errors.push(`${repoPath(root, vectorPath)}#/content_sha256: body digest mismatch`);
  const payload = `${vector.domain}\n${vector.timestamp}\n${vector.delivery_id}\n${digest}`;
  const expected = `v1=${createHmac("sha256", Buffer.from(vector.secret_utf8 ?? "", "utf8")).update(payload).digest("base64url")}`;
  if (vector.signature !== expected) errors.push(`${repoPath(root, vectorPath)}#/signature: HMAC-SHA256 signature mismatch`);
  if (Buffer.byteLength(vector.secret_utf8 ?? "", "utf8") < 32) errors.push(`${repoPath(root, vectorPath)}#/secret_utf8: test secret must be at least 32 bytes`);
}

function checkPluginExamples(root, markers, errors) {
  const examples = markers.filter(({kind}) => kind === "plugin-example");
  if (examples.length === 0) errors.push("docs/developer:$: no contract-doc:plugin-example markers found");
  if (!examples.some((marker) => marker.attributes.signature === "manifest-ed25519-v1")) {
    errors.push("docs/developer:$: no signed manifest plugin example marker found");
  }
  for (const marker of examples) {
    const examplePath = markerPath(root, marker, "file", errors);
    const schemaPath = markerPath(root, marker, "schema", errors);
    if (!examplePath || !schemaPath) continue;
    const example = parseJSON(examplePath, errors, root);
    const schema = parseJSON(schemaPath, errors, root);
    if (!example || !schema) continue;
    const ajv = new Ajv({allErrors: true, strict: true});
    addFormats(ajv);
    if (!ajv.validateSchema(schema)) {
      errors.push(`${repoPath(root, schemaPath)}#/: invalid JSON Schema: ${ajv.errorsText(ajv.errors)}`);
      continue;
    }
    const validate = ajv.compile(schema);
    if (!validate(example)) {
      for (const error of validate.errors ?? []) {
        errors.push(`${repoPath(root, examplePath)}#${error.instancePath || "/"}: ${error.message}`);
      }
      continue;
    }
    if (marker.attributes.signature === "manifest-ed25519-v1") checkManifestSignature(root, marker, example, errors);
  }
  const signatureMarkers = markers.filter(({kind}) => kind === "plugin-signature");
  if (signatureMarkers.length === 0) errors.push("docs/developer:$: no Webhook signature vector marker found");
  for (const marker of signatureMarkers) {
    if (marker.attributes.algorithm !== "webhook-hmac-sha256-v1") {
      errors.push(`${marker.location}:algorithm: unsupported plugin signature check`);
    } else {
      checkWebhookVector(root, marker, errors);
    }
  }

  const catalogPath = join(root, "api", "schemas", "marketplace", "v1", "extension-catalog.json");
  if (existsSync(catalogPath)) {
    const catalog = parseJSON(catalogPath, errors, root);
    for (const [collection, items] of Object.entries({events: catalog?.events, permissions: catalog?.permissions})) {
      for (const [index, item] of (items ?? []).entries()) {
        if (item.status !== "deprecated") continue;
        if (typeof item.deprecated_since !== "string" || !item.deprecated_since) errors.push(`${repoPath(root, catalogPath)}#/${collection}/${index}/deprecated_since: required for deprecated catalog item`);
        if (typeof item.replacement !== "string" || !item.replacement) errors.push(`${repoPath(root, catalogPath)}#/${collection}/${index}/replacement: required for deprecated catalog item`);
      }
    }
  }
  return examples.length;
}

function checkPolicy(root, markers, errors) {
  const policyMarkers = markers.filter(({kind}) => kind === "policy");
  if (policyMarkers.length !== 1) errors.push(`docs/developer:$: expected exactly one contract-doc:policy marker, found ${policyMarkers.length}`);
  if (policyMarkers.length === 0) return;
  const policyPath = markerPath(root, policyMarkers[0], "file", errors);
  if (!policyPath) return;
  const policy = parseJSON(policyPath, errors, root);
  const expected = {
    schema_version: 1,
    status: "active",
    openapi: {version: "info.version+path-/vN", deprecation: "deprecated+x-deprecated-since+x-sunset-after+x-replacement-operation-id"},
    protobuf: {version: "package-.vN", deprecation: "deprecated=true+comment-since+replacement"},
    plugin: {version: "api_version/event-vN", deprecation: "status=deprecated+deprecated_since+replacement"}
  };
  if (!isDeepStrictEqual(policy, expected)) {
    errors.push(`${repoPath(root, policyPath)}#/: policy marker structure or values do not match contract-doc-check v1`);
  }
}

function runMarketplaceValidator(root, errors) {
  const script = join(root, "scripts", "validate-marketplace-contracts.mjs");
  if (!existsSync(script)) {
    errors.push("scripts/validate-marketplace-contracts.mjs:$: existing marketplace validator is required");
    return;
  }
  const result = spawnSync(process.execPath, [script], {cwd: root, encoding: "utf8"});
  if (result.status !== 0) {
    errors.push(`scripts/validate-marketplace-contracts.mjs:$: marketplace validation failed: ${(result.stderr || result.stdout).trim()}`);
  }
}

export function checkRepository(root, {runMarketplace = true} = {}) {
  root = resolve(root);
  const errors = [];
  const {markers} = scanDocumentation(root, errors);
  checkPolicy(root, markers, errors);
  const documents = loadOpenAPIDocuments(root, errors);
  checkOpenAPIDocumentation(root, markers, documents, errors);
  const operationCount = checkOpenAPI(documents, errors);
  const serviceCount = checkProto(root, markers, errors);
  const pluginExampleCount = checkPluginExamples(root, markers, errors);
  if (runMarketplace) runMarketplaceValidator(root, errors);
  return {
    errors,
    stats: {openapiDocuments: documents.length, operations: operationCount, protoServices: serviceCount, pluginExamples: pluginExampleCount}
  };
}

function main() {
  const args = process.argv.slice(2);
  let root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  let runMarketplace = true;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--repo-root") root = resolve(args[++index]);
    else if (args[index] === "--skip-marketplace") runMarketplace = false;
    else {
      console.error(`contract-doc-check: unknown argument: ${args[index]}`);
      process.exit(2);
    }
  }
  const result = checkRepository(root, {runMarketplace});
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(error);
    console.error(`contract-doc-check: failed with ${result.errors.length} error(s)`);
    process.exit(1);
  }
  const {openapiDocuments, operations, protoServices, pluginExamples} = result.stats;
  console.log(`contract-doc-check: passed (${openapiDocuments} OpenAPI documents, ${operations} operations, ${protoServices} protobuf services, ${pluginExamples} plugin examples)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
