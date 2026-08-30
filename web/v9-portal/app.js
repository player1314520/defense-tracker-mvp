import { createPortalClient } from "./supabase-client.mjs";
import {
  bytesToBase64url,
  createBrowserDeviceKeyPair,
  decryptRecord,
  encryptRecord,
  openOrgKeyForP256,
  sealOrgKeyForP256,
} from "./crypto.mjs";
import {
  decideAccessApplication,
  listAccessApplications,
  submitAccessApplication,
} from "./portal-api.mjs";
import {
  canManageAccess,
  safeApplicationSummary,
  workflowRequest,
  workflowTargets,
} from "./policy.mjs";
import {
  clearLegacyAuthSessions,
  createPortalAuthStorage,
  logoutPortalSession,
} from "./session.mjs";

const byId = (id) => document.getElementById(id);
const state = {
  client: null,
  session: null,
  records: [],
  organizationId: "",
  orgKey: null,
  orgKeyVersion: 0,
  role: "",
  workflowStates: new Map(),
  cursor: 0,
  wakeChannel: null,
  refreshPromise: null,
  refreshRequested: false,
  workflowRefreshPromise: null,
  generation: 0,
  busyActions: new Set(),
  accessApplications: [],
  accessNextCursor: null,
  pendingDevices: [],
  quarantineReports: [],
  quarantineCount: 0,
  pendingQuarantineReports: 0,
  accessApplicationsEnabled: false,
};

const MAX_SYNC_PAGE_ENCODED_BYTES = 24 * 1024 * 1024;
const SYNC_PROCESS_YIELD_BYTES = 1024 * 1024;
const textEncoder = new TextEncoder();

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("defense-tracker-v9", 3);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("auth")) db.createObjectStore("auth");
      if (!db.objectStoreNames.contains("devices")) db.createObjectStore("devices");
      if (!db.objectStoreNames.contains("recordHeads")) {
        db.createObjectStore("recordHeads");
      }
      if (!db.objectStoreNames.contains("syncState")) {
        db.createObjectStore("syncState");
      }
      if (!db.objectStoreNames.contains("syncQuarantine")) {
        db.createObjectStore("syncQuarantine");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function databaseOperation(storeName, mode, action) {
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, mode);
      const request = action(transaction.objectStore(storeName));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

const authStorage = {
  getItem: (key) => databaseOperation("auth", "readonly", (store) => store.get(key)),
  setItem: (key, value) => databaseOperation(
    "auth", "readwrite", (store) => store.put(value, key),
  ),
  removeItem: (key) => databaseOperation(
    "auth", "readwrite", (store) => store.delete(key),
  ),
  keys: () => databaseOperation(
    "auth", "readonly", (store) => store.getAllKeys(),
  ),
  clear: () => databaseOperation(
    "auth", "readwrite", (store) => store.clear(),
  ),
};
const portalAuthStorage = createPortalAuthStorage(authStorage);

function safeStatusMessage(message) {
  return String(message || "")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[邮箱已隐藏]")
    .replace(/\b(?:sk-[A-Za-z0-9_-]+|eyJ[A-Za-z0-9._-]+)\b/g, "[凭据已隐藏]");
}

function setStatus(message, bad = false) {
  byId("status").textContent = safeStatusMessage(message);
  byId("status").dataset.bad = bad ? "1" : "0";
}

async function runBusyAction(key, button, action) {
  if (state.busyActions.has(key)) return false;
  state.busyActions.add(key);
  const wasDisabled = Boolean(button?.disabled);
  if (button) button.disabled = true;
  button?.setAttribute?.("aria-busy", "true");
  try {
    await action();
    return true;
  } catch (error) {
    setStatus(error?.message || "操作失败", true);
    return false;
  } finally {
    state.busyActions.delete(key);
    button?.removeAttribute?.("aria-busy");
    if (button?.isConnected !== false) {
      if (button) button.disabled = wasDisabled;
    } else if (state.session) {
      render();
      if (canManageAccess(state.role) && state.orgKey) renderAdminQueues();
    }
  }
}

async function databaseWriteTransaction(storeNames, action) {
  const db = await openDatabase();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(storeNames, "readwrite");
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(
        transaction.error || new Error("浏览器缓存写入失败"),
      );
      transaction.onabort = () => reject(
        transaction.error || new Error("浏览器缓存事务已中止"),
      );
      try {
        action(transaction);
      } catch (error) {
        transaction.abort();
        reject(error);
      }
    });
  } finally {
    db.close();
  }
}

function card(title, subtitle, actions = []) {
  const item = document.createElement("article");
  const heading = document.createElement("h3");
  const detail = document.createElement("p");
  heading.textContent = title;
  detail.textContent = subtitle;
  item.append(heading, detail);
  if (actions.length) {
    const controls = document.createElement("div");
    controls.className = "record-actions";
    controls.append(...actions);
    item.append(controls);
  }
  return item;
}

function actionButton(label, action, value, recordId) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.dataset.action = action;
  if (value) button.dataset.value = value;
  if (recordId) button.dataset.recordId = recordId;
  button.disabled = state.busyActions.has(`${action}:${recordId || value || ""}`);
  return button;
}

function renderList(id, items, emptyMessage) {
  const target = byId(id);
  if (!target) return;
  target.replaceChildren(...items);
  if (!target.children.length) {
    const empty = card(emptyMessage, "数据只在已批准设备中解密显示。");
    empty.className = "empty-state";
    target.append(empty);
  }
}

function workflowFor(record) {
  return state.workflowStates.get(record.record_id) || null;
}

function workflowLabel(value) {
  return {
    editing: "退回编辑",
    pending_approval: "提交待审",
    signed: "核验并签发",
    recalled: "撤回签发",
  }[value] || value;
}

function render() {
  const groups = {
    alerts: state.records.filter((item) => item.record_type === "alert"),
    publications: state.records.filter(
      (item) => item.record_type === "publication_item",
    ),
    jobs: state.records.filter((item) => ["job", "scenario"].includes(item.record_type)),
  };
  const pendingApprovals = groups.publications.filter(
    (item) => workflowFor(item)?.state === "pending_approval",
  );
  if (byId("metric-records")) {
    byId("metric-records").textContent = String(state.records.length);
    byId("metric-alerts").textContent = String(groups.alerts.length);
    byId("metric-approvals").textContent = String(pendingApprovals.length);
  }
  if (byId("current-role")) {
    byId("current-role").textContent = state.role || "未解锁";
  }
  renderList(
    "alert-list",
    groups.alerts.map((item) => {
      const content = item.content || {};
      return card(
        content.title || "共享告警",
        `${content.status || content.state || "已同步"} · V${item.version}`,
      );
    }),
    "暂无共享告警",
  );
  renderList(
    "job-list",
    groups.jobs.map((item) => {
      const content = item.content || {};
      return card(
        content.title || content.name || "共享任务",
        `${content.status || content.state || "已同步"} · V${item.version}`,
      );
    }),
    "暂无共享任务",
  );
  renderList(
    "publication-list",
    groups.publications.map((item) => {
      const content = item.content || {};
      const workflow = workflowFor(item);
      const currentState = workflow?.state || content.status || "未建立工作流";
      const actions = workflow
        ? workflowTargets(state.role, currentState).map((targetState) => (
          actionButton(
            workflowLabel(targetState),
            "workflow",
            targetState,
            item.record_id,
          )
        ))
        : [];
      return card(
        content.title || content.name || "待审稿件",
        `${currentState} · 内容 V${item.version}`,
        actions,
      );
    }),
    "暂无签发事项",
  );
  const adminPanel = byId("admin-panel");
  if (adminPanel) {
    adminPanel.hidden = !(canManageAccess(state.role) && state.orgKey);
  }
}

function deviceStorageKey(organizationId, userId) {
  if (!organizationId || !userId) {
    throw new Error("设备存储身份无效");
  }
  return JSON.stringify([organizationId, userId]);
}

async function storedDevice(organizationId, userId) {
  return databaseOperation(
    "devices",
    "readonly",
    (store) => store.get(deviceStorageKey(organizationId, userId)),
  );
}

async function storeDevice(device) {
  await databaseOperation(
    "devices",
    "readwrite",
    (store) => store.put(
      device,
      deviceStorageKey(device.organizationId, device.userId),
    ),
  );
  return device;
}

function createOpaqueDeviceMetadata() {
  return {
    deviceNameCiphertext: bytesToBase64url(
      crypto.getRandomValues(new Uint8Array(32)),
    ),
    deviceNameNonce: bytesToBase64url(
      crypto.getRandomValues(new Uint8Array(12)),
    ),
  };
}

async function registerStoredDevice(device) {
  const pendingDevice = {
    ...device,
    ...(
      device.deviceNameCiphertext && device.deviceNameNonce
        ? {}
        : createOpaqueDeviceMetadata()
    ),
    pending_registration: true,
    registrationStatus: "pending",
  };
  await storeDevice(pendingDevice);
  const { error } = await state.client.rpc("register_device", {
    organization_id: pendingDevice.organizationId,
    device_id: pendingDevice.id,
    key_algorithm: "p256",
    device_public_key: pendingDevice.publicKey,
    device_name_ciphertext: pendingDevice.deviceNameCiphertext,
    device_name_nonce: pendingDevice.deviceNameNonce,
    device_kind: "browser",
  });
  if (error) throw error;
  pendingDevice.pending_registration = false;
  pendingDevice.registrationStatus = "registered";
  await storeDevice(pendingDevice);
  return pendingDevice;
}

async function createAndStoreDevice(organizationId, userId) {
  const keys = await createBrowserDeviceKeyPair();
  const device = {
    id: crypto.randomUUID(),
    organizationId,
    userId,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    keyAlgorithm: keys.keyAlgorithm,
    ...createOpaqueDeviceMetadata(),
    pending_registration: true,
    registrationStatus: "pending",
  };
  await storeDevice(device);
  return registerStoredDevice(device);
}

function byteaToBase64url(value) {
  const raw = String(value || "");
  if (!/^\\x(?:[0-9a-fA-F]{2})+$/.test(raw)) {
    throw new Error("无效的密钥信封编码");
  }
  const bytes = Uint8Array.from(
    raw.slice(2).match(/.{2}/g),
    (part) => parseInt(part, 16),
  );
  return bytesToBase64url(bytes);
}

function remoteDeviceMatchesLocal(remoteDevice, device, userId) {
  if (
    remoteDevice.id !== device.id
    || remoteDevice.user_id !== userId
    || device.keyAlgorithm !== "p256"
    || remoteDevice.key_algorithm !== device.keyAlgorithm
  ) {
    return false;
  }
  try {
    return byteaToBase64url(remoteDevice.public_key) === device.publicKey;
  } catch {
    return false;
  }
}

function isCurrentGeneration(generation) {
  return generation === state.generation;
}

async function lockWorkspace() {
  const wakeChannel = state.wakeChannel;
  state.generation += 1;
  const generation = state.generation;
  state.records = [];
  state.organizationId = "";
  state.orgKey = null;
  state.orgKeyVersion = 0;
  state.role = "";
  state.workflowStates = new Map();
  state.cursor = 0;
  state.wakeChannel = null;
  state.refreshPromise = null;
  state.refreshRequested = false;
  state.workflowRefreshPromise = null;
  state.accessApplications = [];
  state.accessNextCursor = null;
  state.pendingDevices = [];
  state.quarantineReports = [];
  state.quarantineCount = 0;
  state.pendingQuarantineReports = 0;
  render();
  if (wakeChannel) {
    await state.client.removeChannel(wakeChannel);
  }
  return generation;
}

function workspaceCacheKey(organizationId, userId) {
  if (!organizationId || !userId) {
    throw new Error("同步缓存身份无效");
  }
  return JSON.stringify([organizationId, userId]);
}

function recordCacheKey(organizationId, userId, recordId) {
  if (!recordId) throw new Error("同步缓存记录无效");
  return JSON.stringify([organizationId, userId, recordId]);
}

function quarantineCacheKey(organizationId, userId, eventId) {
  if (!eventId) throw new Error("同步隔离事件无效");
  return JSON.stringify([organizationId, userId, eventId]);
}

function quarantineFailureCode(error) {
  const code = String(error?.code || "");
  return new Set([
    "invalid_json",
    "invalid_schema",
    "unsupported_schema",
    "integrity_failure",
  ]).has(code) ? code : "decrypt_failure";
}

function syncEventRecordId(event) {
  return String(event?.payload?.record_id || event?.record_id || "");
}

function quarantineEvent(organizationId, userId, event, error) {
  return {
    organizationId,
    userId,
    eventId: String(event?.event_id || ""),
    recordId: syncEventRecordId(event),
    versionId: String(event?.payload?.version_id || ""),
    recordType: String(event?.payload?.record_type || "").slice(0, 64),
    cursor: Number(event?.cursor || 0),
    failureCode: quarantineFailureCode(error),
    quarantinedAt: new Date().toISOString(),
  };
}

function tombstonePlaintext(recordType) {
  const content = {
    schema_version: 1,
    deleted: true,
  };
  if ([
    "alert", "job", "scenario", "document", "publication_item",
  ].includes(recordType)) {
    content.title = "已删除的隔离记录";
  }
  if (recordType === "alert_rule") content.name = "已删除的隔离规则";
  if (recordType === "publication_item") content.status = "deleted";
  if (recordType === "audit_event") content.action = "quarantine_tombstone";
  return content;
}

async function buildQuarantineTombstoneEvent(report) {
  const organizationId = state.organizationId;
  const userId = state.session?.user?.id || "";
  const recordId = String(report?.record_id || "");
  const baseVersionId = String(report?.version_id || "");
  const recordType = String(report?.record_type || "");
  const previousVersion = Number(report?.logical_version);
  if (
    !organizationId
    || !userId
    || !state.orgKey
    || !Number.isInteger(state.orgKeyVersion)
    || state.orgKeyVersion < 1
    || !recordId
    || !baseVersionId
    || !recordType
    || !Number.isSafeInteger(previousVersion)
    || previousVersion < 1
  ) {
    throw new Error("隔离报告或当前加密工作区状态无效");
  }
  const device = await storedDevice(organizationId, userId);
  if (!device?.id) throw new Error("当前浏览器设备身份不可用");
  const version = previousVersion + 1;
  const encrypted = await encryptRecord(state.orgKey, {
    organizationId,
    recordId,
    recordType,
    version,
    keyVersion: state.orgKeyVersion,
    content: tombstonePlaintext(recordType),
  });
  return {
    event_id: crypto.randomUUID(),
    organization_id: organizationId,
    record_id: recordId,
    operation: "delete",
    payload: {
      organization_id: organizationId,
      record_id: recordId,
      record_type: recordType,
      version,
      version_id: crypto.randomUUID(),
      base_version_id: baseVersionId,
      key_version: state.orgKeyVersion,
      device_id: device.id,
      deleted: true,
      ...encrypted,
    },
  };
}

async function reportQuarantineEvent(item) {
  try {
    const { data, error } = await state.client.rpc(
      "report_sync_event_quarantine",
      {
        p_organization_id: item.organizationId,
        p_event_cursor: item.cursor,
        p_event_id: item.eventId,
        p_record_id: item.recordId,
        p_version_id: item.versionId,
        p_failure_code: item.failureCode,
      },
    );
    return !error && Boolean(data?.report_id);
  } catch {
    return false;
  }
}

async function markQuarantineReported(item) {
  await databaseOperation(
    "syncQuarantine",
    "readwrite",
    (store) => store.put(
      { ...item, reportedAt: new Date().toISOString() },
      quarantineCacheKey(item.organizationId, item.userId, item.eventId),
    ),
  );
}

async function retryPendingQuarantineReports(organizationId, userId) {
  let entries;
  try {
    entries = await databaseOperation(
      "syncQuarantine",
      "readonly",
      (store) => store.getAll(),
    );
  } catch {
    return 0;
  }
  const pendingEntries = (entries || []).filter((entry) => (
    entry.organizationId === organizationId
    && entry.userId === userId
    && !entry.reportedAt
  ));
  let unreported = pendingEntries.length;
  for (const item of pendingEntries.slice(0, 50)) {
    if (await reportQuarantineEvent(item)) {
      try {
        await markQuarantineReported(item);
        unreported -= 1;
      } catch {
        // The durable entry remains unreported and is counted for a later retry.
      }
    }
  }
  return unreported;
}

async function clearCachedWorkspace(organizationId, userId) {
  await databaseWriteTransaction(["recordHeads", "syncState"], (transaction) => {
    const headsStore = transaction.objectStore("recordHeads");
    const allHeadsRequest = headsStore.getAll();
    const allHeadKeysRequest = headsStore.getAllKeys();
    let allHeads = null;
    let allHeadKeys = null;
    const deleteWorkspaceHeads = () => {
      if (!allHeads || !allHeadKeys) return;
      for (let index = 0; index < allHeads.length; index += 1) {
        const entry = allHeads[index];
        if (
          entry.organizationId === organizationId
          && entry.userId === userId
        ) {
          headsStore.delete(allHeadKeys[index]);
        }
      }
    };
    allHeadsRequest.onsuccess = () => {
      allHeads = allHeadsRequest.result || [];
      deleteWorkspaceHeads();
    };
    allHeadKeysRequest.onsuccess = () => {
      allHeadKeys = allHeadKeysRequest.result || [];
      deleteWorkspaceHeads();
    };
    transaction.objectStore("syncState").delete(
      workspaceCacheKey(organizationId, userId),
    );
  });
}

async function restoreCachedWorkspace(
  organizationId,
  userId,
  orgKey,
  generation = state.generation,
) {
  const [allHeads, syncState, quarantineEntries] = await Promise.all([
    databaseOperation(
      "recordHeads",
      "readonly",
      (store) => store.getAll(),
    ),
    databaseOperation(
      "syncState",
      "readonly",
      (store) => store.get(workspaceCacheKey(organizationId, userId)),
    ),
    databaseOperation(
      "syncQuarantine",
      "readonly",
      (store) => store.getAll(),
    ),
  ]);
  if (!isCurrentGeneration(generation)) return false;
  const records = [];
  let invalidCache = false;
  for (const entry of allHeads || []) {
    if (
      entry.organizationId !== organizationId
      || entry.userId !== userId
    ) {
      continue;
    }
    try {
      const content = await decryptRecord(orgKey, entry.payload);
      if (!isCurrentGeneration(generation)) return false;
      records.push({
        record_id: entry.recordId,
        record_type: entry.payload.record_type,
        version: entry.payload.version,
        content_hash: entry.payload.content_hash,
        content,
      });
    } catch {
      invalidCache = true;
      break;
    }
  }
  if (invalidCache) {
    if (!isCurrentGeneration(generation)) return false;
    await clearCachedWorkspace(organizationId, userId);
    if (!isCurrentGeneration(generation)) return false;
    state.records = [];
    state.cursor = 0;
    state.pendingQuarantineReports = (quarantineEntries || []).filter(
      (entry) => entry.organizationId === organizationId
        && entry.userId === userId
        && !entry.reportedAt,
    ).length;
    render();
    return true;
  }
  const cursor = Number(syncState?.cursor || 0);
  state.records = records;
  state.cursor = Number.isSafeInteger(cursor) && cursor >= 0 ? cursor : 0;
  state.pendingQuarantineReports = (quarantineEntries || []).filter(
    (entry) => entry.organizationId === organizationId
      && entry.userId === userId
      && !entry.reportedAt,
  ).length;
  render();
  return true;
}

function cacheableCiphertextPayload(payload) {
  return {
    organization_id: payload?.organization_id,
    record_id: payload?.record_id,
    record_type: payload?.record_type,
    version: payload?.version,
    key_version: payload?.key_version,
    ciphertext: payload?.ciphertext,
    nonce: payload?.nonce,
    wrapped_data_key: payload?.wrapped_data_key,
    wrap_nonce: payload?.wrap_nonce,
    content_hash: payload?.content_hash,
  };
}

async function persistCiphertextPage(
  organizationId,
  userId,
  events,
  cursor,
) {
  if (!userId) return;
  const latest = new Map();
  const quarantined = [];
  for (const processed of events || []) {
    const { event, disposition, quarantine } = processed;
    const recordId = syncEventRecordId(event);
    if (event.applied === false) continue;
    if (disposition === "keep") {
      latest.set(recordId, cacheableCiphertextPayload(event.payload));
    } else if (disposition === "delete" || disposition === "quarantine") {
      latest.set(recordId, null);
    }
    if (quarantine) quarantined.push(quarantine);
  }
  await databaseWriteTransaction(
    ["recordHeads", "syncState", "syncQuarantine"],
    (transaction) => {
      const headsStore = transaction.objectStore("recordHeads");
      for (const [recordId, payload] of latest) {
        const key = recordCacheKey(organizationId, userId, recordId);
        if (payload === null) {
          headsStore.delete(key);
        } else {
          headsStore.put({
            organizationId,
            userId,
            recordId,
            payload,
          }, key);
        }
      }
      transaction.objectStore("syncState").put(
        { cursor },
        workspaceCacheKey(organizationId, userId),
      );
      const quarantineStore = transaction.objectStore("syncQuarantine");
      for (const item of quarantined) {
        quarantineStore.put(
          item,
          quarantineCacheKey(organizationId, userId, item.eventId),
        );
      }
    },
  );
}

async function loadWorkflowStates(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.organizationId
    || !state.orgKey
    || typeof state.client?.from !== "function"
  ) {
    return false;
  }
  const { data, error } = await state.client
    .from("workflow_states")
    .select("record_id,state,version,content_hash,updated_at")
    .eq("organization_id", state.organizationId)
    .order("updated_at", { ascending: false })
    .limit(1000);
  if (!isCurrentGeneration(generation)) return false;
  if (error) throw error;
  state.workflowStates = new Map(
    (data || []).map((item) => [item.record_id, item]),
  );
  return true;
}

async function pullCiphertextChanges(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.organizationId
    || !state.orgKey
  ) {
    return false;
  }
  const organizationId = state.organizationId;
  const userId = state.session?.user?.id || "";
  const orgKey = state.orgKey;
  const heads = new Map(
    state.records.map((record) => [record.record_id, record]),
  );
  let cursor = state.cursor;
  let conflicts = 0;
  let quarantines = 0;
  let unreportedQuarantines = state.pendingQuarantineReports > 0
    ? await retryPendingQuarantineReports(organizationId, userId)
    : 0;
  state.pendingQuarantineReports = unreportedQuarantines;
  let finished = false;
  while (!finished) {
    for (let page = 0; page < 100; page += 1) {
      const pageStartCursor = cursor;
      let result;
      try {
        result = await state.client.rpc(
          "pull_sync_events",
          {
            organization_id: organizationId,
            after_cursor: cursor,
            page_size: 100,
          },
        );
      } catch (error) {
        if (!isCurrentGeneration(generation)) return false;
        throw error;
      }
      if (!isCurrentGeneration(generation)) return false;
      const { data: events, error: syncError } = result;
      if (syncError) throw syncError;
      const eventPage = events || [];
      if (eventPage.length === 0) {
        finished = true;
        break;
      }
      const encodedPageBytes = textEncoder.encode(
        JSON.stringify(eventPage),
      ).byteLength;
      if (encodedPageBytes > MAX_SYNC_PAGE_ENCODED_BYTES) {
        throw new Error("同步页超过 24 MiB 编码上限，已拒绝处理");
      }
      const processedPage = [];
      const pageQuarantines = [];
      let processedBytes = 0;
      for (const event of eventPage) {
        const recordId = syncEventRecordId(event);
        if (!recordId) throw new Error("同步事件记录身份无效");
        const eventCursor = Number(event.cursor);
        if (!Number.isSafeInteger(eventCursor) || eventCursor <= cursor) {
          throw new Error("同步事件游标无效或未严格递增");
        }
        cursor = Math.max(cursor, eventCursor);
        if (event.applied === false) {
          conflicts += 1;
          processedPage.push({ event, disposition: "ignore" });
          continue;
        }
        if (event.payload?.deleted === true) {
          heads.delete(recordId);
          processedPage.push({ event, disposition: "delete" });
          continue;
        }
        let content;
        try {
          content = await decryptRecord(orgKey, event.payload);
        } catch (error) {
          if (!isCurrentGeneration(generation)) return false;
          const quarantine = quarantineEvent(
            organizationId,
            userId,
            event,
            error,
          );
          heads.delete(recordId);
          processedPage.push({
            event,
            disposition: "quarantine",
            quarantine,
          });
          pageQuarantines.push(quarantine);
          quarantines += 1;
          continue;
        }
        if (!isCurrentGeneration(generation)) return false;
        heads.set(recordId, {
          record_id: recordId,
          record_type: event.payload.record_type,
          version: event.payload.version,
          content_hash: event.payload.content_hash,
          content,
        });
        processedPage.push({ event, disposition: "keep" });
        processedBytes += textEncoder.encode(JSON.stringify(event)).byteLength;
        if (processedBytes >= SYNC_PROCESS_YIELD_BYTES) {
          processedBytes = 0;
          await new Promise((resolve) => setTimeout(resolve, 0));
          if (!isCurrentGeneration(generation)) return false;
        }
      }
      if (!isCurrentGeneration(generation)) return false;
      await persistCiphertextPage(
        organizationId,
        userId,
        processedPage,
        cursor,
      );
      if (!isCurrentGeneration(generation)) return false;
      for (const quarantine of pageQuarantines) {
        if (await reportQuarantineEvent(quarantine)) {
          try {
            await markQuarantineReported(quarantine);
          } catch {
            unreportedQuarantines += 1;
          }
        } else {
          unreportedQuarantines += 1;
          state.pendingQuarantineReports += 1;
        }
        if (!isCurrentGeneration(generation)) return false;
      }
      state.records = [...heads.values()];
      state.cursor = cursor;
      state.quarantineCount = quarantines;
      state.pendingQuarantineReports = unreportedQuarantines;
      if (cursor <= pageStartCursor) {
        throw new Error("同步游标未前进，已停止以避免重复拉取");
      }
    }
    if (!finished) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (!isCurrentGeneration(generation)) return false;
  await loadWorkflowStates(generation);
  if (!isCurrentGeneration(generation)) return false;
  render();
  setStatus(
    `已在本页内存解锁 ${state.records.length} 条记录 · 游标 ${cursor}`
      + (conflicts ? ` · 待桌面合并冲突 ${conflicts}` : "")
      + (quarantines ? ` · 已隔离异常记录 ${quarantines}` : "")
      + (unreportedQuarantines ? ` · ${unreportedQuarantines} 条待联网审计` : ""),
  );
  return true;
}

function beginCiphertextRefresh(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.orgKey
  ) {
    return null;
  }
  if (state.refreshPromise) {
    state.refreshRequested = true;
    return state.refreshPromise;
  }
  const refreshPromise = pullCiphertextChanges(generation)
  const finish = () => {
    if (state.refreshPromise === refreshPromise) {
      state.refreshPromise = null;
    }
    if (isCurrentGeneration(generation) && state.refreshRequested) {
      state.refreshRequested = false;
      queueMicrotask(() => refreshFromWakeup(generation));
    }
  };
  state.refreshPromise = refreshPromise;
  refreshPromise.then(finish, finish);
  return refreshPromise;
}

function refreshFromWakeup(generation = state.generation) {
  const alreadyRefreshing = Boolean(state.refreshPromise);
  const refreshPromise = beginCiphertextRefresh(generation);
  if (!refreshPromise || alreadyRefreshing) return;
  refreshPromise.catch((error) => {
    if (isCurrentGeneration(generation)) setStatus(error.message, true);
  });
}

function refreshWorkflowFromWakeup(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.orgKey
    || state.workflowRefreshPromise
  ) {
    return;
  }
  const promise = loadWorkflowStates(generation)
    .then((loaded) => {
      if (loaded && isCurrentGeneration(generation)) render();
    })
    .catch((error) => {
      if (isCurrentGeneration(generation)) setStatus(error.message, true);
    })
    .finally(() => {
      if (state.workflowRefreshPromise === promise) {
        state.workflowRefreshPromise = null;
      }
    });
  state.workflowRefreshPromise = promise;
}

async function subscribeToWakeups(generation = state.generation) {
  if (!isCurrentGeneration(generation)) return false;
  if (state.wakeChannel) {
    const wakeChannel = state.wakeChannel;
    state.wakeChannel = null;
    await state.client.removeChannel(wakeChannel);
    if (!isCurrentGeneration(generation)) return false;
  }
  const organizationId = state.organizationId;
  const wakeChannel = state.client
    .channel(`v9-mobile-wakeup:${organizationId}`)
    .on(
      "postgres_changes",
      {
        event: "*",
        schema: "public",
        table: "sync_wakeups",
        filter: `organization_id=eq.${organizationId}`,
      },
      () => refreshFromWakeup(generation),
    )
    .on(
      "postgres_changes",
      {
        event: "*",
        schema: "public",
        table: "workflow_states",
        filter: `organization_id=eq.${organizationId}`,
      },
      () => refreshWorkflowFromWakeup(generation),
    )
    .subscribe();
  if (!isCurrentGeneration(generation)) {
    await state.client.removeChannel(wakeChannel);
    return false;
  }
  state.wakeChannel = wakeChannel;
  return true;
}

function renderAdminQueues() {
  const applications = state.accessApplications.map((application) => {
    const retryable = application.status === "approved"
      && application.provisioningStatus === "retryable";
    const role = document.createElement("select");
    role.setAttribute("aria-label", "批准后的角色");
    for (const value of ["collector", "analyst", "editor", "approver"]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      role.append(option);
    }
    role.value = application.requestedRole || "collector";
    role.disabled = retryable;
    const approve = actionButton(
      retryable ? "重试发送邀请" : "批准并邀请",
      "application-decision",
      "approved",
      application.id,
    );
    const reject = actionButton(
      "拒绝",
      "application-decision",
      "rejected",
      application.id,
    );
    const actions = retryable ? [role, approve] : [role, approve, reject];
    return card(
      application.emailMasked || "申请人已隐藏",
      `${retryable ? "邀请待重试" : application.status} · ${
        application.createdAt || "时间未提供"
      }`,
      actions,
    );
  });
  if (state.accessNextCursor) {
    applications.push(card(
      "还有更多待处理申请",
      "继续加载下一页，不会遗漏较早的申请。",
      [actionButton(
        "加载更多申请",
        "application-load-more",
        "load",
        state.accessNextCursor,
      )],
    ));
  }
  renderList("application-list", applications, "暂无待审申请");

  const devices = state.pendingDevices.map((device) => {
    const supported = device.key_algorithm === "p256";
    const approve = actionButton(
      supported ? "批准并封装组织密钥" : "请在桌面端批准",
      "device-approve",
      "approve",
      device.id,
    );
    approve.disabled = approve.disabled || !supported;
    return card(
      `${device.device_kind || "device"} · ${String(device.id).slice(0, 8)}`,
      `用户 ${String(device.user_id).slice(0, 8)} · ${device.key_algorithm}`,
      [approve],
    );
  });
  renderList("device-list", devices, "暂无待批准设备");

  const quarantines = state.quarantineReports.map((report) => {
    const actions = [];
    if (report.status === "open") {
      actions.push(actionButton(
        "创建端到端加密墓碑",
        "quarantine-tombstone",
        "tombstone",
        report.report_id,
      ));
      actions.push(actionButton(
        "确认桌面端已修复",
        "quarantine-repaired",
        "repair",
        report.report_id,
      ));
    }
    return card(
      `${String(report.record_type || "record")} · ${String(report.record_id).slice(0, 8)}`,
      `${String(report.failure_code || "invalid_schema")} · 游标 ${Number(report.event_cursor || 0)} · ${String(report.status || "open")}`,
      actions,
    );
  });
  renderList("quarantine-list", quarantines, "暂无异常密文记录");
}

async function loadAdminQueues(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.session
    || !state.orgKey
    || !canManageAccess(state.role)
  ) {
    return false;
  }
  const [applications, deviceResult, quarantineResult] = await Promise.all([
    listAccessApplications(state.client, null),
    state.client
      .from("devices")
      .select("id,user_id,status,key_algorithm,public_key,device_kind,created_at")
      .eq("organization_id", state.organizationId)
      .eq("status", "pending")
      .order("created_at", { ascending: true })
      .limit(50),
    state.client.rpc("list_sync_quarantine_reports", {
      p_organization_id: state.organizationId,
      p_limit: 50,
    }),
  ]);
  if (!isCurrentGeneration(generation)) return false;
  if (deviceResult.error) throw deviceResult.error;
  if (quarantineResult.error) throw quarantineResult.error;
  state.accessApplications = (applications.applications || []).map(
    safeApplicationSummary,
  );
  state.accessNextCursor = typeof applications.next_cursor === "string"
    && applications.next_cursor
    ? applications.next_cursor
    : null;
  state.pendingDevices = (deviceResult.data || []).map((device) => ({
    id: device.id,
    user_id: device.user_id,
    status: device.status,
    key_algorithm: device.key_algorithm,
    public_key: device.public_key,
    device_kind: device.device_kind,
    created_at: device.created_at,
  }));
  state.quarantineReports = (quarantineResult.data || []).map((report) => ({
    report_id: String(report.report_id || ""),
    event_cursor: Number(report.event_cursor || 0),
    record_id: String(report.record_id || ""),
    version_id: String(report.version_id || ""),
    logical_version: Number(report.logical_version || 0),
    record_type: String(report.record_type || "").slice(0, 64),
    failure_code: String(report.failure_code || "").slice(0, 64),
    status: String(report.status || "").slice(0, 32),
  }));
  renderAdminQueues();
  return true;
}

async function loadMoreAccessApplications(generation = state.generation) {
  if (
    !isCurrentGeneration(generation)
    || !state.session
    || !state.orgKey
    || !canManageAccess(state.role)
    || !state.accessNextCursor
  ) {
    return false;
  }
  const requestedCursor = state.accessNextCursor;
  const applications = await listAccessApplications(state.client, state.accessNextCursor);
  if (
    !isCurrentGeneration(generation)
    || state.accessNextCursor !== requestedCursor
  ) {
    return false;
  }
  const nextCursor = typeof applications.next_cursor === "string"
    && applications.next_cursor
    ? applications.next_cursor
    : null;
  if (nextCursor && nextCursor === requestedCursor) {
    throw new Error("申请队列游标未前进，请刷新后重试");
  }
  const knownIds = new Set(state.accessApplications.map((item) => item.id));
  for (const rawApplication of applications.applications || []) {
    const application = safeApplicationSummary(rawApplication);
    if (application.id && !knownIds.has(application.id)) {
      state.accessApplications.push(application);
      knownIds.add(application.id);
    }
  }
  state.accessNextCursor = nextCursor;
  renderAdminQueues();
  return true;
}

async function performWorkflowTransition(recordId, targetState) {
  if (!state.session || !state.orgKey) {
    throw new Error("工作区尚未在已批准设备中解锁");
  }
  const record = state.records.find((item) => item.record_id === recordId);
  const workflow = state.workflowStates.get(recordId);
  if (!record || !workflow) throw new Error("工作流状态尚未同步");
  if (!workflowTargets(state.role, workflow.state).includes(targetState)) {
    throw new Error("当前角色不能执行该工作流动作");
  }
  const { data, error } = await state.client.rpc(
    "transition_workflow",
    workflowRequest(
      state.organizationId,
      record,
      workflow,
      targetState,
    ),
  );
  if (error) throw error;
  const nextVersion = Number(data);
  if (!Number.isSafeInteger(nextVersion) || nextVersion <= workflow.version) {
    throw new Error("工作流响应版本无效");
  }
  await loadWorkflowStates();
  render();
  setStatus(`${workflowLabel(targetState)}成功 · 工作流 V${nextVersion}`);
}

async function approvePendingDevice(deviceId) {
  if (
    !state.session
    || !state.orgKey
    || !canManageAccess(state.role)
    || !Number.isSafeInteger(state.orgKeyVersion)
    || state.orgKeyVersion <= 0
  ) {
    throw new Error("只有已解锁的 Owner/Admin 可以批准设备");
  }
  const device = state.pendingDevices.find((item) => item.id === deviceId);
  if (!device || device.key_algorithm !== "p256") {
    throw new Error("待批准浏览器设备无效");
  }
  const envelope = await sealOrgKeyForP256(
    state.orgKey,
    byteaToBase64url(device.public_key),
    {
      organizationId: state.organizationId,
      deviceId: device.id,
      keyVersion: state.orgKeyVersion,
    },
  );
  const { error } = await state.client.rpc("pair_device", {
    organization_id: state.organizationId,
    device_id: device.id,
    target_user_id: device.user_id,
    envelope_key_version: state.orgKeyVersion,
    envelope_algorithm: "p256",
    ephemeral_public_key: envelope.ephemeralPublicKey,
    envelope_nonce: envelope.nonce,
    envelope_ciphertext: envelope.ciphertext,
  });
  if (error) throw error;
  await loadAdminQueues();
  setStatus("浏览器设备已批准并收到新的组织密钥信封");
}

async function handlePortalAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  const recordId = button.dataset.recordId || "";
  if (action === "workflow") {
    const targetState = button.dataset.value;
    if (
      ["signed", "recalled"].includes(targetState)
      && !window.confirm(`确认执行“${workflowLabel(targetState)}”？`)
    ) {
      return;
    }
    await runBusyAction(`workflow:${recordId}`, button, () => (
      performWorkflowTransition(recordId, targetState)
    ));
    return;
  }
  if (action === "device-approve") {
    await runBusyAction(`device-approve:${recordId}`, button, () => (
      approvePendingDevice(recordId)
    ));
    return;
  }
  if (action === "application-load-more") {
    await runBusyAction(
      `application-load-more:${recordId}`,
      button,
      () => loadMoreAccessApplications(),
    );
    return;
  }
  if (action === "application-decision") {
    const decision = button.dataset.value;
    const role = button.closest("article")?.querySelector("select")?.value
      || "collector";
    await runBusyAction(`application-decision:${recordId}`, button, async () => {
      const result = await decideAccessApplication(
        state.client,
        recordId,
        decision,
        role,
      );
      await loadAdminQueues();
      if (decision === "rejected") {
        setStatus("申请已拒绝");
      } else if (result?.status === "invited") {
        setStatus("申请已批准，邀请已发送");
      } else if (result?.status === "retryable") {
        setStatus("邀请发送暂未完成，请重试", true);
      } else if (result?.status === "cancelled") {
        setStatus("邀请未发送，申请已安全关闭", true);
      } else {
        setStatus("邀请状态未确认，请刷新后重试", true);
      }
    });
    return;
  }
  if (action === "quarantine-tombstone") {
    if (!window.confirm("确认删除当前异常记录头？此操作会写入可审计墓碑。")) {
      return;
    }
    await runBusyAction(`quarantine-tombstone:${recordId}`, button, async () => {
      const report = state.quarantineReports.find(
        (item) => item.report_id === recordId && item.status === "open",
      );
      if (!report) throw new Error("隔离报告已刷新，请重新加载");
      const tombstoneEvent = await buildQuarantineTombstoneEvent(report);
      const { data, error } = await state.client.rpc(
        "admin_tombstone_quarantined_record",
        { p_report_id: recordId, p_event: tombstoneEvent },
      );
      if (error) throw error;
      if (!data?.tombstoned) throw new Error("墓碑写入未确认");
      await loadAdminQueues();
      await pullCiphertextChanges();
      setStatus("异常记录已创建可审计墓碑");
    });
    return;
  }
  if (action === "quarantine-repaired") {
    await runBusyAction(`quarantine-repaired:${recordId}`, button, async () => {
      const { data, error } = await state.client.rpc(
        "admin_mark_quarantine_repaired",
        { p_report_id: recordId },
      );
      if (error) throw error;
      if (!data?.repaired) throw new Error("修复状态未确认");
      await loadAdminQueues();
      setStatus("桌面端替换版本已核验，隔离报告关闭");
    });
  }
}

async function unlockAndRefresh() {
  const organizationSelect = byId("organization");
  const organizationId = organizationSelect.value;
  if (!organizationId) throw new Error("请选择组织");
  const userId = state.session?.user?.id;
  if (!userId) throw new Error("登录会话已失效，请重新登录");
  const generation = await lockWorkspace();
  if (!isCurrentGeneration(generation)) return;
  state.organizationId = organizationId;
  const selectedOption = organizationSelect.selectedOptions?.[0]
    || [...(organizationSelect.children || [])].find(
      (option) => option.value === organizationId,
    );
  state.role = String(selectedOption?.dataset?.role || "").toLowerCase();
  render();
  let device;
  try {
    device = await storedDevice(organizationId, userId);
  } catch (error) {
    if (!isCurrentGeneration(generation)) return;
    throw error;
  }
  if (!isCurrentGeneration(generation)) return;
  if (!device) {
    try {
      device = await createAndStoreDevice(organizationId, userId);
    } catch (error) {
      if (!isCurrentGeneration(generation)) return;
      throw error;
    }
    if (!isCurrentGeneration(generation)) return;
    setStatus("浏览器设备已登记，等待 Owner/Admin 在桌面端批准配对");
    return;
  }
  if (
    device.organizationId !== organizationId
    || device.userId !== userId
  ) {
    throw new Error("本地设备身份无效；已保留私钥并拒绝解锁");
  }
  if (
    device.pending_registration === true
    || device.registrationStatus === "pending"
  ) {
    device = await registerStoredDevice(device);
    if (!isCurrentGeneration(generation)) return;
  }
  let bindError = null;
  let bindResult;
  try {
    bindResult = await state.client.rpc("bind_device_session", {
      p_organization_id: organizationId,
      p_device_id: device.id,
    });
  } catch (error) {
    if (!isCurrentGeneration(generation)) return;
    bindError = error;
  }
  if (!isCurrentGeneration(generation)) return;
  if (bindResult?.error) bindError = bindResult.error;
  if (!bindError) {
    const binding = bindResult?.data;
    if (
      binding?.organization_id !== organizationId
      || binding?.device_id !== device.id
      || binding?.status !== "active"
    ) {
      throw new Error("设备会话绑定响应无效");
    }
  }
  let remoteResult;
  try {
    remoteResult = await state.client
      .from("devices")
      .select("id,user_id,status,key_algorithm,public_key")
      .eq("organization_id", organizationId)
      .eq("user_id", userId)
      .eq("id", device.id)
      .maybeSingle();
  } catch (error) {
    if (!isCurrentGeneration(generation)) return;
    throw error;
  }
  if (!isCurrentGeneration(generation)) return;
  const { data: remoteDevice, error: deviceError } = remoteResult;
  if (deviceError) throw deviceError;
  if (!remoteDevice) {
    if (!device.registrationStatus) {
      await registerStoredDevice(device);
      if (!isCurrentGeneration(generation)) return;
      setStatus("浏览器设备已重新提交，等待 Owner/Admin 批准配对");
      return;
    }
    throw new Error(
      "远端设备记录暂不可见或设备会话未激活；已保留本地私钥，请稍后重试",
    );
  }
  if (!remoteDeviceMatchesLocal(remoteDevice, device, userId)) {
    throw new Error("远端设备身份与本地私钥不匹配；已保留私钥并拒绝解锁");
  }
  if (remoteDevice.status !== "active") {
    setStatus("设备仍待 Owner/Admin 批准配对");
    return;
  }
  if (bindError) {
    throw new Error("设备已批准，但当前登录会话未能绑定该设备；请安全退出后重试");
  }
  let envelopeResult;
  try {
    envelopeResult = await state.client
      .from("key_envelopes")
      .select("organization_id,device_id,key_version,key_algorithm,ephemeral_public_key,nonce,ciphertext")
      .eq("organization_id", organizationId)
      .eq("device_id", device.id)
      .order("key_version", { ascending: false })
      .limit(1);
  } catch (error) {
    if (!isCurrentGeneration(generation)) return;
    throw error;
  }
  if (!isCurrentGeneration(generation)) return;
  const { data: envelopes, error: envelopeError } = envelopeResult;
  if (envelopeError) throw envelopeError;
  const envelope = envelopes?.[0];
  if (!envelope || envelope.key_algorithm !== "p256") {
    throw new Error("尚未收到 P-256 组织密钥信封");
  }
  let orgKey;
  try {
    orgKey = await openOrgKeyForP256(device.privateKey, {
      ...envelope,
      ephemeral_public_key: byteaToBase64url(envelope.ephemeral_public_key),
      nonce: byteaToBase64url(envelope.nonce),
      ciphertext: byteaToBase64url(envelope.ciphertext),
    });
  } catch (error) {
    if (!isCurrentGeneration(generation)) return;
    throw error;
  }
  if (!isCurrentGeneration(generation)) return;
  state.orgKey = orgKey;
  state.orgKeyVersion = Number(envelope.key_version);
  await restoreCachedWorkspace(
    organizationId,
    userId,
    orgKey,
    generation,
  );
  if (!isCurrentGeneration(generation)) return;
  await subscribeToWakeups(generation);
  if (!isCurrentGeneration(generation)) return;
  const initialRefresh = beginCiphertextRefresh(generation);
  if (!initialRefresh) return;
  await initialRefresh;
  if (!isCurrentGeneration(generation)) return;
  if (canManageAccess(state.role)) await loadAdminQueues(generation);
}

async function loadOrganizations() {
  const { data, error } = await state.client
    .from("memberships")
    .select("organization_id,user_id,role,status")
    .eq("user_id", state.session.user.id)
    .in("status", ["active", "invited"]);
  if (error) throw error;
  const select = byId("organization");
  select.replaceChildren();
  for (const item of data || []) {
    const option = document.createElement("option");
    const waitingForPairing = item.status === "invited";
    option.value = item.organization_id;
    option.dataset.membershipStatus = item.status;
    option.dataset.role = item.role;
    option.textContent = `${item.role} · ${item.organization_id.slice(0, 8)}`
      + (waitingForPairing ? " · 待设备配对" : "");
    select.append(option);
  }
  if (data?.length) {
    select.value = data[0].organization_id;
    state.role = String(data[0].role || "").toLowerCase();
  }
  byId("authenticated-dashboard").hidden = false;
  byId("anonymous-access").hidden = true;
  byId("unlock").disabled = !data?.length;
  render();
  if (!data?.length) {
    setStatus("账号已登录，但尚无获批组织；请等待人工审核");
  } else {
    setStatus("账号已登录，请选择组织并在本机解锁");
  }
}

async function handleCallback() {
  const url = new URL(window.location.href);
  const codes = url.searchParams.getAll("code");
  const forbidden = ["token_hash", "access_token", "refresh_token", "type"];
  if (
    codes.length > 1
    || forbidden.some((name) => url.searchParams.has(name))
  ) {
    throw new Error("登录回调参数无效，仅接受 PKCE 授权码");
  }
  if (codes.length === 0) return;
  url.search = "";
  history.replaceState({}, "", url);
  const result = await state.client.auth.exchangeCodeForSession(codes[0]);
  if (result?.error) throw result.error;
}

async function acceptPendingInvitations() {
  const { data, error } = await state.client.rpc(
    "accept_member_invitation",
    {},
  );
  if (error) throw error;
  if (
    !data
    || !Number.isInteger(data.accepted_count)
    || data.accepted_count < 0
  ) {
    throw new Error("邀请接受响应无效");
  }
  return data.accepted_count;
}

async function initialize() {
  const config = await fetch("./config.json", { cache: "no-store" }).then(
    (response) => response.json(),
  );
  if (!config.configured) throw new Error("移动门户尚未配置生产协作服务");
  if (typeof config.display_version === "string") {
    byId("product-version").textContent = config.display_version;
  }
  state.accessApplicationsEnabled = config.access_applications_enabled === true;
  // v9.1 and earlier persisted the full Supabase session.  Keep only the
  // one-time PKCE verifier required across the emailed callback navigation.
  await clearLegacyAuthSessions(authStorage);
  state.client = createPortalClient(
    config.url,
    config.publishable_key,
    portalAuthStorage,
  );
  byId("login-submit").disabled = false;
  byId("application-submit").disabled = !state.accessApplicationsEnabled;
  await handleCallback();
  const { data, error } = await state.client.auth.getSession();
  if (error) throw error;
  state.session = data.session;
  if (state.session) {
    await acceptPendingInvitations();
    await loadOrganizations();
  } else {
    setStatus("登录入口已就绪，请使用获批邮箱登录");
  }
}

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  await runBusyAction("login", button, async () => {
    const { error } = await state.client.auth.signInWithOtp({
      email: byId("email").value.trim(),
      options: {
        shouldCreateUser: false,
        emailRedirectTo: `${window.location.origin}/portal/`,
      },
    });
    if (error) throw error;
    byId("email").value = "";
    setStatus("登录链接已发送，仅受邀成员可登录");
  });
});
byId("application-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  await runBusyAction("access-application", button, async () => {
    if (!state.accessApplicationsEnabled) {
      throw new Error("公测申请通道尚未开放");
    }
    if (!byId("application-consent").checked) {
      throw new Error("请先同意公测使用规则与隐私说明");
    }
    await submitAccessApplication(
      state.client,
      byId("application-email").value,
      "mvp-2026-08",
    );
    byId("application-email").value = "";
    byId("application-consent").checked = false;
    setStatus("申请已提交；审核结果将通过邮件通知");
  });
});
byId("unlock").addEventListener("click", async (event) => {
  await runBusyAction("unlock", event.currentTarget, unlockAndRefresh);
});
byId("logout").addEventListener("click", async (event) => {
  await runBusyAction("logout", event.currentTarget, async () => {
    const wakeChannel = state.wakeChannel;
    const result = await logoutPortalSession({
      revokeDeviceSession: () => state.client.rpc(
        "revoke_current_device_session",
        {},
      ),
      signOut: () => state.client.auth.signOut({ scope: "local" }),
      removeWakeChannel: async () => {
        if (wakeChannel) await state.client.removeChannel(wakeChannel);
      },
      clearAuth: () => portalAuthStorage.clear(),
      clearMemory: () => {
        state.session = null;
        state.records = [];
        state.organizationId = "";
        state.orgKey = null;
        state.orgKeyVersion = 0;
        state.role = "";
        state.workflowStates = new Map();
        state.cursor = 0;
        state.wakeChannel = null;
        state.refreshPromise = null;
        state.refreshRequested = false;
        state.workflowRefreshPromise = null;
        state.accessApplications = [];
        state.accessNextCursor = null;
        state.pendingDevices = [];
        state.quarantineReports = [];
        state.quarantineCount = 0;
        state.pendingQuarantineReports = 0;
        state.busyActions.clear();
        byId("authenticated-dashboard").hidden = true;
        byId("anonymous-access").hidden = false;
        render();
      },
    });
    if (!result.localCleared) {
      setStatus(
        "内存已锁定，但浏览器会话清理失败；请关闭此页面并清理站点数据",
        true,
      );
    } else if (!result.deviceSessionRevoked) {
      setStatus(
        "本地会话已清除；服务端设备会话撤销失败，请联网后重新登录再退出",
        true,
      );
    } else if (!result.authSignedOut) {
      setStatus(
        "设备会话已撤销且本地已清除；Supabase 注销未确认",
        true,
      );
    } else {
      setStatus("浏览器会话已安全清除；设备私钥仍保留用于下次配对");
    }
  });
});
byId("organization").addEventListener("change", async () => {
  await lockWorkspace();
  const option = byId("organization").selectedOptions?.[0];
  state.role = String(option?.dataset?.role || "").toLowerCase();
  render();
  setStatus("组织已切换，请在本机重新解锁");
});
byId("refresh-admin").addEventListener("click", async (event) => {
  await runBusyAction("refresh-admin", event.currentTarget, async () => {
    await loadAdminQueues();
    setStatus("准入与设备队列已刷新");
  });
});
byId("authenticated-dashboard").addEventListener("click", (event) => {
  handlePortalAction(event).catch((error) => setStatus(error.message, true));
});
window.addEventListener("pagehide", () => {
  if (state.wakeChannel) state.client.removeChannel(state.wakeChannel);
  state.records = [];
  state.orgKey = null;
  state.orgKeyVersion = 0;
  state.workflowStates = new Map();
  state.cursor = 0;
  state.refreshRequested = false;
});
render();
initialize().catch((error) => setStatus(error.message, true));
