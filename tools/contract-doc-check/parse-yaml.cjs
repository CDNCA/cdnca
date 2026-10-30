const {readFileSync} = require("node:fs");
const {delimiter, dirname} = require("node:path");

// pnpm dlx puts the pinned package's bin directory first on PATH.
const paths = process.env.PATH.split(delimiter).map(dirname);
const packagePath = require.resolve("yaml/package.json", {paths});
const {version} = require(packagePath);
if (version !== process.argv[2]) throw new Error(`Unexpected YAML version: ${version}`);
const {parseAllDocuments} = require(dirname(packagePath));

// Buffer the complete source to avoid yaml@2.8.1's incremental CLI lexer bug.
const documents = parseAllDocuments(readFileSync(0, "utf8"), {strict: true});
if (documents.length !== 1) throw new Error("Input must contain exactly one YAML document");
const [document] = documents;
if (document.errors.length > 0) throw document.errors[0];
for (const warning of document.warnings) console.error(warning.message);
process.stdout.write(JSON.stringify(document.toJS()) + "\n");
