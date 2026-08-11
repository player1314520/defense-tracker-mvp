import { createClient } from "@supabase/supabase-js";
import { initializePersonalBusinessContext } from "./business-context.js";

const byId = (id) => document.getElementById(id);
const memory = new Map();
const pkceStorage = {
  getItem(key) {
    return memory.get(key) || null;
  },
  setItem(key, value) {
    memory.set(key, value);
  },
  removeItem(key) {
    memory.delete(key);
  },
};

let supabase = null;
let publicConfig = null;
let wakeChannel = null;
let currentCloudUserId = "";
let currentCloudDeviceId = "";
const BUSINESS_ORGANIZATION_KEY = "defense-tracker-v9-cloud-organization";
let businessContextReadyResolve = null;
let businessContextReadySettled = false;
let recoveryGateResolve = null;
window.__V9_BUSINESS_CONTEXT_READY__ = new Promise((resolve) => {
  businessContextReadyResolve = resolve;
});

function storedBusinessOrganization() {
  try {
    return sessionStorage.getItem(BUSINESS_ORGANIZATION_KEY) || "";
  } catch (_) {
    return "";
  }
}

function storeBusinessOrganization(organizationId) {
  try {
    if (organizationId) {
      sessionStorage.setItem(BUSINESS_ORGANIZATION_KEY, organizationId);
    } else {
      sessionStorage.removeItem(BUSINESS_ORGANIZATION_KEY);
    }
  } catch (_) {
    // The in-memory lock below remains authoritative if storage is disabled.
  }
}

function settleBusinessContextGate() {
  if (businessContextReadySettled) return;
  businessContextReadySettled = true;
  businessContextReadyResolve?.();
}

function emitBusinessContextState(state) {
  window.dispatchEvent(new CustomEvent("v9:business-context", {
    detail: state,
  }));
}

function lockCloudBusinessContext(
  reason,
  organizationId = storedBusinessOrganization(),
) {
  const state = Object.freeze({
    mode: "cloud",
    organizationId,
    unlocked: false,
    reason,
  });
  window.__V9_BUSINESS_CONTEXT__ = state;
  emitBusinessContextState(state);
  if (reason !== "initializing") settleBusinessContextGate();
}

function publishCloudBusinessContext(organizationId, device) {
  if (!organizationId || device?.status !== "active") {
    lockCloudBusinessContext("pending_device", organizationId);
    return;
  }
  const state = Object.freeze({
    mode: "cloud",
    organizationId,
    unlocked: true,
    headers: Object.freeze({
      "X-V9-Context-Mode": "cloud",
      "X-V9-Organization-ID": organizationId,
    }),
  });
  window.__V9_BUSINESS_CONTEXT__ = state;
  storeBusinessOrganization(organizationId);
  emitBusinessContextState(state);
  settleBusinessContextGate();
}

function publishPersonalBusinessContext(organizationId) {
  const state = Object.freeze({
    mode: "personal",
    organizationId,
    unlocked: true,
    headers: Object.freeze({
      "X-V9-Context-Mode": "personal",
      "X-V9-Organization-ID": organizationId,
    }),
  });
  window.__V9_BUSINESS_CONTEXT__ = state;
  emitBusinessContextState(state);
  settleBusinessContextGate();
}

function lockPersonalBusinessContext(reason) {
  const state = Object.freeze({
    mode: "personal",
    organizationId: "",
    unlocked: false,
    reason,
  });
  window.__V9_BUSINESS_CONTEXT__ = state;
  emitBusinessContextState(state);
  settleBusinessContextGate();
}

function failBusinessContextInitialization(error) {
  const organizationId = storedBusinessOrganization();
  if (organizationId) {
    lockCloudBusinessContext("initialization_failed", organizationId);
  } else {
    lockPersonalBusinessContext("initialization_failed");
  }
  showError(error);
}

lockCloudBusinessContext("initializing");

function status(message, bad = false) {
  const target = byId("v9CloudStatus");
  if (!target) return;
  target.textContent = message;
  target.dataset.bad = bad ? "1" : "0";
}

function cookieValue(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const part of document.cookie.split(";")) {
    const value = part.trim();
    if (value.startsWith(prefix)) {
      return decodeURIComponent(value.slice(prefix.length));
    }
  }
  return "";
}

async function jsonRequest(path, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const requestPath = new URL(path, window.location.origin).pathname;
  const contextExempt = (
    requestPath.startsWith("/api/v9/auth/")
    || requestPath === "/api/v9/business-context/personal"
    || requestPath === "/api/v9/organizations"
    || requestPath === "/api/v9/organizations/bootstrap"
    || requestPath === "/api/v9/organizations/bootstrap/acknowledge"
    || requestPath === "/api/v9/situation"
    || requestPath === "/api/v9/pairing-sessions/claim"
  );
  const context = window.__V9_BUSINESS_CONTEXT__;
  if (
    !contextExempt
    && (
      !context
      || !["personal", "cloud"].includes(context.mode)
      || !context.organizationId
    )
  ) {
    throw new Error("业务上下文尚未选择");
  }
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (!contextExempt) {
    headers["X-V9-Context-Mode"] = context.mode;
    headers["X-V9-Organization-ID"] = context.organizationId;
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = cookieValue("csrf_token");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers,
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    lockCloudBusinessContext(
      "session_expired",
      byId("v9CloudOrganization")?.value
        || storedBusinessOrganization(),
    );
  }
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function showRecoveryCodeGate(recoveryCode) {
  if (typeof recoveryCode !== "string" || !recoveryCode.trim()) {
    throw new Error("个人工作区恢复码无效");
  }
  if (recoveryGateResolve) {
    throw new Error("已有个人工作区初始化等待确认");
  }
  const panel = byId("v9RecoveryPanel");
  const code = byId("v9RecoveryCode");
  const saved = byId("v9RecoverySaved");
  const confirm = byId("v9RecoveryConfirm");
  if (!panel || !code || !saved || !confirm) {
    throw new Error("恢复码安全确认界面不可用");
  }
  code.textContent = recoveryCode;
  saved.checked = false;
  confirm.disabled = true;
  panel.hidden = false;
  byId("v9RecoveryCopy")?.focus();
  return new Promise((resolve) => {
    recoveryGateResolve = resolve;
  });
}

async function bootstrapPersonalBusinessContext({ publish = true } = {}) {
  const context = await jsonRequest("/api/v9/organizations/bootstrap", {
    method: "POST",
    body: JSON.stringify({
      name: "个人工作区",
      device_name: "本机桌面",
    }),
  });
  if (
    typeof context.organization_id !== "string"
    || !context.organization_id
    || typeof context.recovery_code !== "string"
    || !context.recovery_code
  ) {
    throw new Error(
      "个人工作区已建立但本窗口没有恢复码；请先在原初始化窗口完成保存",
    );
  }
  await showRecoveryCodeGate(context.recovery_code);
  const acknowledged = await jsonRequest(
    "/api/v9/organizations/bootstrap/acknowledge",
    {
      method: "POST",
      body: JSON.stringify({
        organization_id: context.organization_id,
      }),
    },
  );
  if (
    acknowledged.recovery_acknowledged !== true
    || acknowledged.organization_id !== context.organization_id
  ) {
    throw new Error("个人工作区恢复码确认状态无效");
  }
  byId("v9RecoveryCode").textContent = "";
  byId("v9RecoveryPanel").hidden = true;
  if (publish) publishPersonalBusinessContext(context.organization_id);
  return { ...context, mode: "personal" };
}

async function activatePersonalBusinessContext({ publish = true } = {}) {
  return initializePersonalBusinessContext(
    {
      discover: () => jsonRequest(
        "/api/v9/business-context/personal",
      ),
      bootstrap: bootstrapPersonalBusinessContext,
      validate: (context) => {
        if (
          context.mode !== "personal"
          || typeof context.organization_id !== "string"
          || !context.organization_id
        ) {
          throw new Error("个人工作区上下文无效");
        }
      },
      publish: publishPersonalBusinessContext,
      lock: lockPersonalBusinessContext,
    },
    { publishContext: publish },
  );
}

function renderSession(session) {
  const authenticated = Boolean(session?.authenticated);
  currentCloudUserId = authenticated ? String(session.user_id || "") : "";
  if (!authenticated) currentCloudDeviceId = "";
  byId("v9CloudIdentity").textContent = authenticated
    ? `已登录 · ${session.email || session.user_id || "成员"}`
    : "未登录";
  byId("v9CloudLoginForm").hidden = authenticated;
  byId("v9CloudWorkspace").hidden = !authenticated;
  if (authenticated) {
    prepareAuthenticatedWorkspace().catch((error) => {
      lockCloudBusinessContext(
        "cloud_context_error",
        storedBusinessOrganization(),
      );
      showError(error);
    });
  } else if (storedBusinessOrganization()) {
    lockCloudBusinessContext(
      "session_expired",
      storedBusinessOrganization(),
    );
  } else {
    activatePersonalBusinessContext().catch(showError);
  }
}

async function prepareAuthenticatedWorkspace() {
  await activatePersonalBusinessContext({ publish: false });
  const token = await jsonRequest("/api/v9/auth/realtime-token");
  supabase.realtime.setAuth(token.access_token);
  await loadOrganizations();
}

async function loadOrganizations() {
  const payload = await jsonRequest("/api/v9/organizations");
  const select = byId("v9CloudOrganization");
  select.replaceChildren();
  for (const row of payload.organizations || []) {
    const option = document.createElement("option");
    option.value = row.organization_id;
    option.dataset.role = row.role;
    option.dataset.membershipStatus = row.status;
    option.textContent = `${row.role} · ${row.organization_id.slice(0, 8)}`
      + (row.status === "invited" ? " · 待设备配对" : "");
    select.append(option);
  }
  const restoredOrganization = storedBusinessOrganization();
  if (
    restoredOrganization
    && Array.from(select.options).some(
      (option) => option.value === restoredOrganization,
    )
  ) {
    select.value = restoredOrganization;
  }
  if (!select.options.length) {
    const option = document.createElement("option");
    option.textContent = "尚未加入组织";
    option.value = "";
    select.append(option);
  }
  if (select.value) {
    storeBusinessOrganization(select.value);
    lockCloudBusinessContext("initializing", select.value);
  } else {
    lockCloudBusinessContext("no_organization", "");
  }
  byId("v9CloudBootstrap").hidden = Boolean(select.value);
  const selectedRole = select.selectedOptions[0]?.dataset.role;
  const selectedMembership =
    select.selectedOptions[0]?.dataset.membershipStatus;
  byId("v9CloudInviteForm").hidden =
    !select.value
    || selectedMembership !== "active"
    || !["owner", "admin"].includes(selectedRole);
  subscribeToWakeups(select.value);
  const device = await advanceSelectedDevice();
  byId("v9CloudSync").disabled = device.status !== "active";
  await loadDevices();
  await loadInvitations();
  if (device.status === "active") {
    publishCloudBusinessContext(select.value, device);
    await loadSyncStatus();
  } else {
    lockCloudBusinessContext("pending_device", select.value);
    byId("v9CloudSyncStatus").textContent = "设备待配对，尚未解锁同步";
  }
}

function invitationContainer() {
  let target = byId("v9CloudInvitations");
  if (target) return target;
  target = document.createElement("div");
  target.id = "v9CloudInvitations";
  target.className = "v9-cloud-device-line";
  byId("v9CloudInviteForm").insertAdjacentElement("afterend", target);
  return target;
}

async function loadInvitations() {
  const select = byId("v9CloudOrganization");
  const organizationId = select.value;
  const role = select.selectedOptions[0]?.dataset.role;
  const membershipStatus =
    select.selectedOptions[0]?.dataset.membershipStatus;
  const canManage = Boolean(
    organizationId
    && membershipStatus === "active"
    && ["owner", "admin"].includes(role),
  );
  byId("v9CloudInviteForm").hidden = !canManage;
  const target = invitationContainer();
  target.hidden = !canManage;
  target.replaceChildren();
  if (!canManage) return;
  const payload = await jsonRequest(
    `/api/v9/members/invitations?organization_id=${
      encodeURIComponent(organizationId)
    }`,
  );
  const invitations = payload.invitations || [];
  if (!invitations.length) {
    target.textContent = "暂无邀请请求";
    return;
  }
  for (const invitation of invitations) {
    const line = document.createElement("div");
    const summary = document.createElement("span");
    summary.textContent =
      `${invitation.invitation_role} · ${invitation.invitation_status}`
      + ` · ${invitation.expires_at || "无到期时间"}`;
    line.append(summary);
    if (["requested", "finalized"].includes(invitation.invitation_status)) {
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "v9-secondary";
      cancel.textContent = "取消";
      cancel.addEventListener("click", async () => {
        try {
          await jsonRequest(
            `/api/v9/members/invitations/${
              encodeURIComponent(invitation.invitation_id)
            }`,
            { method: "DELETE" },
          );
          await loadInvitations();
          status("邀请已取消");
        } catch (error) {
          showError(error);
        }
      });
      line.append(cancel);
    }
    target.append(line);
  }
}

async function advanceSelectedDevice() {
  const organizationId = byId("v9CloudOrganization").value;
  if (!organizationId) return { status: "unavailable" };
  const result = await jsonRequest("/api/v9/devices/self", {
    method: "POST",
    body: JSON.stringify({ organization_id: organizationId }),
  });
  currentCloudDeviceId = String(result.device_id || "");
  if (result.status === "pending") {
    status("本机设备已登记，等待 Owner/Admin 配对组织密钥");
  }
  return result;
}

function subscribeToWakeups(organizationId) {
  if (wakeChannel) {
    supabase.removeChannel(wakeChannel);
    wakeChannel = null;
  }
  if (!organizationId) return;
  wakeChannel = supabase
    .channel(`v9-wakeup:${organizationId}`)
    .on(
      "postgres_changes",
      {
        event: "*",
        schema: "public",
        table: "sync_wakeups",
        filter: `organization_id=eq.${organizationId}`,
      },
      () => {
        status("检测到新密文；请执行游标同步");
        loadSyncStatus().catch(showError);
      },
    )
    .subscribe();
}

async function rewrapAiCredentialsForDevice(organizationId, device) {
  if (
    device.device_kind !== "desktop"
    || device.key_algorithm !== "p256"
  ) {
    return {rewrapped: 0, reentryRequired: [], differentUser: false};
  }
  if (!currentCloudUserId || device.user_id !== currentCloudUserId) {
    return {rewrapped: 0, reentryRequired: [], differentUser: true};
  }
  const state = await jsonRequest(
    `/api/v9/ai/credentials?organization_id=${encodeURIComponent(organizationId)}`,
  );
  const result = {rewrapped: 0, reentryRequired: [], differentUser: false};
  for (const credential of state.credentials || []) {
    try {
      await jsonRequest(
        `/api/v9/ai/credentials/${encodeURIComponent(credential.provider)}/rewrap`,
        {
          method: "POST",
          body: JSON.stringify({
            organization_id: organizationId,
            target_device_id: device.id,
          }),
        },
      );
      result.rewrapped += 1;
    } catch (error) {
      if (
        error.status === 409
        && error.payload?.status === "reentry_required"
      ) {
        result.reentryRequired.push(credential.provider);
        continue;
      }
      throw error;
    }
  }
  return result;
}

async function loadDevices() {
  const organizationId = byId("v9CloudOrganization").value;
  const target = byId("v9CloudDevices");
  if (!organizationId) {
    target.textContent = "等待 Owner/Admin 邀请加入组织";
    return;
  }
  const payload = await jsonRequest(
    `/api/v9/devices?organization_id=${encodeURIComponent(organizationId)}`,
  );
  const devices = payload.devices || [];
  const selected = byId("v9CloudOrganization").selectedOptions[0];
  const canApprove = ["owner", "admin"].includes(selected?.dataset.role);
  target.replaceChildren();
  const summary = document.createElement("span");
  summary.textContent = `${devices.length} 台设备 · ${
    devices.filter((item) => item.status === "active").length
  } 台有效`;
  target.append(summary);
  for (const device of devices.filter(
    (item) => item.status === "pending" && canApprove,
  )) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "v9-secondary";
    button.textContent = `批准 ${device.key_algorithm} · ${device.id.slice(0, 8)}`;
    button.addEventListener("click", async () => {
      let approved = false;
      try {
        await jsonRequest(`/api/v9/devices/${device.id}/approve`, {
          method: "POST",
          body: JSON.stringify({
            organization_id: byId("v9CloudOrganization").value,
          }),
        });
        approved = true;
        const credentialResult = await rewrapAiCredentialsForDevice(
          organizationId,
          device,
        );
        await loadDevices();
        if (credentialResult.differentUser) {
          status("设备已批准；新成员需在自己的桌面录入 BYOK 凭据");
        } else if (credentialResult.reentryRequired.length) {
          status(
            `设备已批准；${credentialResult.reentryRequired.join("、")} 凭据需重新输入后才能供新设备使用`,
            true,
          );
        } else if (credentialResult.rewrapped) {
          status(
            `设备已批准；已为 ${credentialResult.rewrapped} 个 BYOK 凭据补发设备信封`,
          );
        } else {
          status("设备已批准并收到独立组织密钥信封");
        }
      } catch (error) {
        if (approved) {
          try {
            await loadDevices();
          } catch (refreshError) {
            showError(refreshError);
            return;
          }
        }
        showError(error);
      }
    });
    target.append(button);
  }
  for (const device of devices.filter((item) => (
    item.status === "active"
    && item.device_kind === "desktop"
    && item.key_algorithm === "p256"
    && item.user_id === currentCloudUserId
    && item.id !== currentCloudDeviceId
  ))) {
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "v9-secondary";
    retry.textContent = `补发 BYOK · ${device.id.slice(0, 8)}`;
    retry.addEventListener("click", async () => {
      try {
        const result = await rewrapAiCredentialsForDevice(
          organizationId,
          device,
        );
        if (result.reentryRequired.length) {
          status(
            `${result.reentryRequired.join("、")} 凭据需重新输入后才能补发`,
            true,
          );
        } else {
          status(`BYOK 设备信封已对账：${result.rewrapped} 个凭据`);
        }
      } catch (error) {
        showError(error);
      }
    });
    target.append(retry);
  }
}

async function loadSyncStatus() {
  const organizationId = byId("v9CloudOrganization").value;
  if (!organizationId) {
    byId("v9CloudSyncStatus").textContent = "尚未选择组织";
    return;
  }
  const payload = await jsonRequest(
    `/api/v9/sync/status?organization_id=${encodeURIComponent(organizationId)}`,
  );
  const pending = Number(payload.outbox?.pending || 0)
    + Number(payload.outbox?.retry || 0);
  const conflicts = Number(payload.conflicts?.open || 0);
  byId("v9CloudSyncStatus").textContent =
    `游标 ${payload.cursor || 0} · 积压 ${pending} · 冲突 ${conflicts}`;
}

function showError(error) {
  status(error?.message || "Supabase 操作失败", true);
}

async function initialize() {
  publicConfig = await jsonRequest("/api/v9/auth/start");
  if (!publicConfig.configured) {
    if (storedBusinessOrganization()) {
      lockCloudBusinessContext(
        "cloud_config_unavailable",
        storedBusinessOrganization(),
      );
    } else {
      await activatePersonalBusinessContext();
    }
    status("Supabase V9 尚未配置；当前使用本机个人工作区");
    return;
  }
  supabase = createClient(
    publicConfig.url,
    publicConfig.publishable_key,
    {
      auth: {
        flowType: "pkce",
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
        storage: pkceStorage,
      },
    },
  );
  const session = await jsonRequest("/api/v9/auth/session");
  renderSession(session);
  const pageUrl = new URL(window.location.href);
  if (
    pageUrl.searchParams.get("v9-auth") === "complete"
    && session.authenticated
  ) {
    pageUrl.search = "";
    history.replaceState({}, "", pageUrl);
    status("邮箱验证成功；会话密钥已由本机 DPAPI 保护");
  }
}

byId("v9CloudBtn")?.addEventListener("click", async () => {
  byId("v9CloudPanel").hidden = false;
  try {
    renderSession(await jsonRequest("/api/v9/auth/session"));
  } catch (error) {
    showError(error);
  }
});
byId("v9CloudClose")?.addEventListener("click", () => {
  byId("v9CloudPanel").hidden = true;
});
byId("v9RecoverySaved")?.addEventListener("change", () => {
  byId("v9RecoveryConfirm").disabled = !byId("v9RecoverySaved").checked;
});
byId("v9RecoveryCopy")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(byId("v9RecoveryCode").textContent);
    status("恢复码已复制；请保存到离线安全位置");
  } catch (_) {
    status("复制失败，请手工抄录恢复码并核对", true);
  }
});
byId("v9RecoveryConfirm")?.addEventListener("click", () => {
  if (!byId("v9RecoverySaved").checked || !recoveryGateResolve) return;
  const resolve = recoveryGateResolve;
  recoveryGateResolve = null;
  byId("v9RecoveryConfirm").disabled = true;
  resolve();
});
byId("v9CloudLoginForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const email = byId("v9CloudEmail").value.trim();
    await jsonRequest("/api/v9/auth/start", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
    status(
      "登录链接已发送；可在默认浏览器打开，本机 loopback 将完成 PKCE 交换",
    );
  } catch (error) {
    showError(error);
  }
});
byId("v9CloudOrganization")?.addEventListener("change", () => {
  const organizationId = byId("v9CloudOrganization").value;
  lockCloudBusinessContext("organization_switch", organizationId);
  try {
    sessionStorage.setItem(BUSINESS_ORGANIZATION_KEY, organizationId);
  } catch (_) {
    // The locked in-memory context still prevents cross-workspace reads.
  }
  window.location.reload();
});
byId("v9CloudBootstrap")?.addEventListener("click", async () => {
  try {
    await jsonRequest("/api/v9/organizations", {
      method: "POST",
      body: "{}",
    });
    await loadOrganizations();
    status("个人组织已用原 UUID 建立，未上传任何明文");
  } catch (error) {
    showError(error);
  }
});
byId("v9CloudSync")?.addEventListener("click", async () => {
  try {
    const organizationId = byId("v9CloudOrganization").value;
    const device = await advanceSelectedDevice();
    if (device.status !== "active") {
      lockCloudBusinessContext("pending_device", organizationId);
      byId("v9CloudSync").disabled = true;
      return;
    }
    publishCloudBusinessContext(organizationId, device);
    const result = await jsonRequest("/api/v9/sync/run", {
      method: "POST",
      body: JSON.stringify({ organization_id: organizationId }),
    });
    byId("v9CloudSync").disabled = false;
    await loadSyncStatus();
    status(
      `同步完成：上传 ${result.pushed}，拉取 ${result.pulled}，冲突 ${result.conflicts}`,
      Boolean(result.failed),
    );
  } catch (error) {
    showError(error);
  }
});
byId("v9CloudInviteForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await jsonRequest("/api/v9/members/invite", {
      method: "POST",
      body: JSON.stringify({
        organization_id: byId("v9CloudOrganization").value,
        email: byId("v9CloudInviteEmail").value.trim(),
        role: byId("v9CloudInviteRole").value,
      }),
    });
    byId("v9CloudInviteEmail").value = "";
    await loadInvitations();
    status("邀请请求已创建；请通知对方使用受邀邮箱登录");
  } catch (error) {
    showError(error);
  }
});
byId("v9CloudLogout")?.addEventListener("click", async () => {
  let remoteSignOutError = null;
  try {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
  } catch (error) {
    remoteSignOutError = error;
  } finally {
    lockCloudBusinessContext(
      "session_expired",
      byId("v9CloudOrganization")?.value
        || storedBusinessOrganization(),
    );
    try {
      await jsonRequest("/api/v9/auth/session", { method: "DELETE" });
    } catch (error) {
      remoteSignOutError ||= error;
    }
    if (wakeChannel) {
      try {
        await supabase.removeChannel(wakeChannel);
      } catch (error) {
        remoteSignOutError ||= error;
      }
      wakeChannel = null;
    }
    memory.clear();
    renderSession({ authenticated: false });
  }
  if (remoteSignOutError) {
    status(
      "本机会话已清除；远程会话撤销未确认，请联网后重新登录再退出",
      true,
    );
  } else {
    status("本机 Supabase 会话已清除");
  }
});

initialize().catch(failBusinessContextInitialization);
