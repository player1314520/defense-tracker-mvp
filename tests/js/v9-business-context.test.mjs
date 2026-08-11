import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const source = await readFile(
  new URL("../../web/v9-auth/src/index.js", import.meta.url),
  "utf8",
);


test("桌面云面板仅在设备 active 后发布已解锁业务上下文", () => {
  assert.match(source, /publishCloudBusinessContext/);
  assert.match(source, /device\.status === "active"/);
  assert.match(source, /unlocked:\s*true/);
  assert.match(source, /unlocked:\s*false/);
  assert.match(source, /X-V9-Context-Mode/);
  assert.match(source, /X-V9-Organization-ID/);
});


test("组织切换先锁定旧上下文并确定性重载清空业务缓存", () => {
  const changeStart = source.indexOf(
    'byId("v9CloudOrganization")?.addEventListener("change"',
  );
  const changeEnd = source.indexOf(
    'byId("v9CloudBootstrap")?.addEventListener',
    changeStart,
  );
  const block = source.slice(changeStart, changeEnd);

  assert.ok(changeStart >= 0 && changeEnd > changeStart);
  assert.match(block, /lockCloudBusinessContext/);
  assert.match(block, /sessionStorage\.setItem/);
  assert.match(block, /window\.location\.reload\(\)/);
  assert.ok(
    block.indexOf("lockCloudBusinessContext")
      < block.indexOf("window.location.reload()"),
  );
});


test("注销或会话失效的历史云组织不会回退个人默认", () => {
  assert.match(source, /response\.status === 401/);
  assert.match(source, /session_expired/);
  assert.match(source, /lockCloudBusinessContext/);
  const storedBranch = source.slice(
    source.indexOf("else if (storedBusinessOrganization())"),
    source.indexOf("async function prepareAuthenticatedWorkspace"),
  );
  assert.doesNotMatch(storedBranch, /publishPersonalBusinessContext/);
});


test("未配置 Supabase 时发布显式个人上下文并释放初始化门", () => {
  assert.match(source, /publishPersonalBusinessContext/);
  assert.match(source, /\/api\/v9\/business-context\/personal/);
  assert.match(source, /mode:\s*"personal"/);
  const unconfigured = source.slice(
    source.indexOf("if (!publicConfig.configured)"),
    source.indexOf("supabase = createClient"),
  );
  assert.match(unconfigured, /activatePersonalBusinessContext/);
  assert.match(source, /settleBusinessContextGate/);
});


test("初始化失败会锁定上下文并释放请求门", () => {
  assert.match(source, /failBusinessContextInitialization/);
  const failureHandler = source.slice(
    source.indexOf("function failBusinessContextInitialization"),
    source.indexOf("function renderSession"),
  );
  assert.match(failureHandler, /lockCloudBusinessContext/);
  assert.match(failureHandler, /lockPersonalBusinessContext/);
  assert.match(source, /initialize\(\)\.catch\(failBusinessContextInitialization\)/);
});


test("首次个人工作区通过受控 bootstrap 展示恢复码后才解锁", () => {
  assert.match(source, /bootstrapPersonalBusinessContext/);
  assert.match(source, /\/api\/v9\/organizations\/bootstrap/);
  assert.match(source, /showRecoveryCodeGate/);
  const bootstrap = source.slice(
    source.indexOf("async function bootstrapPersonalBusinessContext"),
    source.indexOf("async function activatePersonalBusinessContext"),
  );
  assert.match(bootstrap, /recovery_code/);
  assert.match(bootstrap, /await showRecoveryCodeGate/);
  assert.match(bootstrap, /organizations\/bootstrap\/acknowledge/);
  assert.match(bootstrap, /publishPersonalBusinessContext/);
  assert.ok(
    bootstrap.indexOf("organizations/bootstrap/acknowledge")
      < bootstrap.indexOf("publishPersonalBusinessContext"),
  );
});


test("恢复码界面不可关闭且必须确认已保存", () => {
  const template = readFileSync(
    join(root, "templates", "index.html"),
    "utf8",
  );
  assert.match(template, /id="v9RecoveryPanel"/);
  assert.match(template, /id="v9RecoveryCode"/);
  assert.match(template, /id="v9RecoverySaved"/);
  assert.match(template, /id="v9RecoveryConfirm"/);
  assert.doesNotMatch(
    template.slice(
      template.indexOf('id="v9RecoveryPanel"'),
      template.indexOf('id="v9CloudPanel"'),
    ),
    /v9-cloud-close/,
  );
});
