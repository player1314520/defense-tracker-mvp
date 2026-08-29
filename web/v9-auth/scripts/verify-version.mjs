import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SEMANTIC_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const authDir = path.resolve(scriptDir, "..");
const repositoryRoot = path.resolve(authDir, "..", "..");

function readJson(filePath, label) {
  let source;
  try {
    source = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`Missing ${label}`);
    }
    throw new Error(`Cannot read ${label}`);
  }

  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(`Invalid JSON in ${label}`);
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${label} must contain a JSON object`);
  }
  return value;
}

function requireSemanticVersion(value, label) {
  if (typeof value !== "string" || !SEMANTIC_VERSION.test(value)) {
    throw new Error(`${label} must be a valid semantic version`);
  }
  return value;
}

export function verifyVersion({
  rootVersionPath = path.join(repositoryRoot, "version.json"),
  packagePath = path.join(authDir, "package.json"),
} = {}) {
  const rootVersion = readJson(rootVersionPath, "root version.json");
  const packageJson = readJson(packagePath, "web/v9-auth/package.json");
  const expected = requireSemanticVersion(
    rootVersion.semantic_version,
    "root version.json semantic_version",
  );
  const actual = requireSemanticVersion(
    packageJson.version,
    "web/v9-auth/package.json version",
  );

  if (actual !== expected) {
    throw new Error(
      `Version mismatch: web/v9-auth/package.json is ${actual}, expected ${expected}`,
    );
  }
  return expected;
}

const invokedPath = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href
  : "";
if (invokedPath === import.meta.url) {
  try {
    const version = verifyVersion();
    process.stdout.write(`Version verification passed: ${version}\n`);
  } catch (error) {
    process.stderr.write(`Version verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
