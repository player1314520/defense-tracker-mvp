import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { verifyVersion } from "../../web/v9-auth/scripts/verify-version.mjs";

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, "utf8");
}

function createFixture(t, { rootVersion = "9.0.0", packageVersion = "9.0.0" } = {}) {
  const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "defense-tracker-version-"));
  t.after(() => fs.rmSync(fixtureDir, { recursive: true, force: true }));

  const rootVersionPath = path.join(fixtureDir, "version.json");
  const packagePath = path.join(fixtureDir, "package.json");
  writeJson(rootVersionPath, { semantic_version: rootVersion });
  writeJson(packagePath, { version: packageVersion });
  return { rootVersionPath, packagePath };
}

test("accepts an exact semantic version match", (t) => {
  const paths = createFixture(t);
  assert.equal(verifyVersion(paths), "9.0.0");
});

test("fails closed when package.json drifts from root version.json", (t) => {
  const paths = createFixture(t, { packageVersion: "9.0.1" });
  assert.throws(() => verifyVersion(paths), /version mismatch/i);
});

test("fails closed when either version file is missing", (t) => {
  const paths = createFixture(t);
  fs.unlinkSync(paths.rootVersionPath);
  assert.throws(() => verifyVersion(paths), /missing root version\.json/i);

  const second = createFixture(t);
  fs.unlinkSync(second.packagePath);
  assert.throws(() => verifyVersion(second), /missing web\/v9-auth\/package\.json/i);
});

test("fails closed for invalid JSON", (t) => {
  const paths = createFixture(t);
  fs.writeFileSync(paths.rootVersionPath, "{", "utf8");
  assert.throws(() => verifyVersion(paths), /invalid json in root version\.json/i);

  const second = createFixture(t);
  fs.writeFileSync(second.packagePath, "null", "utf8");
  assert.throws(() => verifyVersion(second), /must contain a json object/i);
});

test("fails closed for missing or malformed semantic versions", (t) => {
  const paths = createFixture(t, { rootVersion: "09.0.0" });
  assert.throws(() => verifyVersion(paths), /semantic_version.*valid semantic version/i);

  const second = createFixture(t, { packageVersion: "v9" });
  assert.throws(() => verifyVersion(second), /package\.json version.*valid semantic version/i);

  const third = createFixture(t);
  writeJson(third.rootVersionPath, {});
  assert.throws(() => verifyVersion(third), /semantic_version.*valid semantic version/i);
});

test("npm build is wired to verify the authoritative version first", () => {
  const packagePath = path.resolve("web", "v9-auth", "package.json");
  const packageJson = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  assert.equal(packageJson.scripts?.prebuild, "node scripts/verify-version.mjs");
});
