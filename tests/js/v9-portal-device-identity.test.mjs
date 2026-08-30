import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";


const appSource = await readFile(
  new URL("../../web/v9-portal/app.js", import.meta.url),
  "utf8",
);


function installFakeIndexedDb() {
  const stores = new Map();
  let openCount = 0;
  const db = {
    objectStoreNames: {
      contains: (name) => stores.has(name),
    },
    createObjectStore(name) {
      stores.set(name, new Map());
    },
    transaction(storeNames) {
      const transaction = {
        error: null,
        objectStore(name) {
          const values = stores.get(name);
          const requestFor = (operation) => {
            pending += 1;
            const request = {};
            queueMicrotask(() => {
              try {
                request.result = operation();
                request.onsuccess?.();
              } catch (error) {
                request.error = error;
                transaction.error = error;
                request.onerror?.();
                transaction.onerror?.();
              } finally {
                pending -= 1;
                maybeComplete();
              }
            });
            return request;
          };
          return {
            get: (key) => requestFor(() => values.get(key)),
            getAll: () => requestFor(() => [...values.values()]),
            getAllKeys: () => requestFor(() => [...values.keys()]),
            put: (value, key) => requestFor(() => {
              values.set(key, value);
              return key;
            }),
            delete: (key) => requestFor(() => values.delete(key)),
            clear: () => requestFor(() => values.clear()),
          };
        },
        abort() {
          transaction.onabort?.();
        },
      };
      let pending = 0;
      let readyToComplete = false;
      let completed = false;
      const maybeComplete = () => {
        if (readyToComplete && pending === 0 && !completed) {
          completed = true;
          queueMicrotask(() => transaction.oncomplete?.());
        }
      };
      const defaultStore = Array.isArray(storeNames) ? storeNames[0] : storeNames;
      const namedObjectStore = transaction.objectStore.bind(transaction);
      transaction.objectStore = (name = defaultStore) => namedObjectStore(name);
      queueMicrotask(() => {
        readyToComplete = true;
        maybeComplete();
      });
      return transaction;
    },
    close() {},
  };
  globalThis.indexedDB = {
    open() {
      openCount += 1;
      const request = {};
      queueMicrotask(() => {
        request.result = db;
        request.onupgradeneeded?.();
        request.onsuccess?.();
      });
      return request;
    },
  };
  stores.getOpenCount = () => openCount;
  return stores;
}


async function loadPortal(organizationId) {
  const stores = installFakeIndexedDb();
  let keyNumber = 0;
  const behaviors = {
    decryptRecord: async () => ({}),
    encryptRecord: async () => ({
      ciphertext: "ciphertext",
      nonce: "nonce",
      wrapped_data_key: "wrapped-data-key",
      wrap_nonce: "wrap-nonce",
      content_hash: "a".repeat(64),
    }),
    openOrgKeyForP256: async () => new Uint8Array(32),
  };
  globalThis.__portalTestDeps = {
    createPortalClient: () => {
      throw new Error("not used");
    },
    base64urlToBytes: () => new Uint8Array(),
    bytesToBase64url: (value) => Buffer.from(value).toString("base64url"),
    createBrowserDeviceKeyPair: async () => {
      keyNumber += 1;
      const publicKey = Buffer.alloc(65, keyNumber);
      publicKey[0] = 4;
      return {
        privateKey: { keyNumber },
        publicKey: publicKey.toString("base64url"),
        keyAlgorithm: "p256",
      };
    },
    decryptRecord: (...args) => behaviors.decryptRecord(...args),
    encryptRecord: (...args) => behaviors.encryptRecord(...args),
    openOrgKeyForP256: (...args) => behaviors.openOrgKeyForP256(...args),
    sealOrgKeyForP256: async () => ({}),
    decideAccessApplication: async () => ({}),
    listAccessApplications: async () => ({ applications: [] }),
    submitAccessApplication: async () => ({}),
    canManageAccess: () => false,
    safeApplicationSummary: (value) => value,
    workflowRequest: () => ({}),
    workflowTargets: () => [],
    createPortalAuthStorage: (storage) => storage,
    clearLegacyAuthSessions: async () => {},
    logoutPortalSession: async () => ({}),
  };
  const createElement = (value = "") => ({
    value,
    dataset: {},
    textContent: "",
    hidden: false,
    children: [],
    replaceChildren(...children) {
      this.children = children;
    },
    append(...children) {
      this.children.push(...children);
    },
  });
  const elements = new Map([
    ["organization", createElement(organizationId)],
    ["status", createElement()],
    ["metric-records", createElement()],
    ["metric-alerts", createElement()],
    ["metric-approvals", createElement()],
    ["record-list", createElement()],
  ]);
  globalThis.document = {
    getElementById: (id) => elements.get(id),
    createElement: () => createElement(),
  };
  const imports = /^import[\s\S]*?from "\.\/session\.mjs";\r?\n/;
  const sourceWithoutImports = appSource.replace(
    imports,
    `const {
        createPortalClient,
        base64urlToBytes,
        bytesToBase64url,
        createBrowserDeviceKeyPair,
        decryptRecord,
        encryptRecord,
        openOrgKeyForP256,
        sealOrgKeyForP256,
        decideAccessApplication,
        listAccessApplications,
        submitAccessApplication,
        canManageAccess,
        safeApplicationSummary,
        workflowRequest,
        workflowTargets,
        createPortalAuthStorage,
        clearLegacyAuthSessions,
        logoutPortalSession,
      } = globalThis.__portalTestDeps;\n`,
  );
  const bootstrapStart = sourceWithoutImports.indexOf(
    'byId("login-form").addEventListener',
  );
  assert.ok(bootstrapStart > 0);
  const testableSource = sourceWithoutImports.slice(0, bootstrapStart)
    + `\nexport {
      state,
      byteaToBase64url,
      storedDevice,
      createAndStoreDevice,
      buildQuarantineTombstoneEvent,
      restoreCachedWorkspace,
      retryPendingQuarantineReports,
      pullCiphertextChanges,
      refreshFromWakeup,
      subscribeToWakeups,
      unlockAndRefresh,
    };\n`;
  const moduleUrl = "data:text/javascript;base64,"
    + Buffer.from(testableSource).toString("base64")
    + `#${crypto.randomUUID()}`;
  const portal = await import(moduleUrl);
  return { ...portal, behaviors, elements, stores };
}


function remoteDeviceClient(remoteDevice, selectedColumns) {
  let envelopeQueries = 0;
  const removedChannels = [];
  const operations = [];
  const bindRequests = [];
  return {
    rpc: async (name, request) => {
      operations.push(`rpc:${name}`);
      if (name === "register_device") return { error: null };
      if (name === "bind_device_session") {
        bindRequests.push(request);
        if (remoteDevice?.status === "active") {
          return {
            data: {
              organization_id: request.p_organization_id,
              device_id: request.p_device_id,
              status: "active",
            },
            error: null,
          };
        }
        return { data: null, error: new Error("active owned device required") };
      }
      throw new Error(`unexpected RPC: ${name}`);
    },
    from(table) {
      operations.push(`from:${table}`);
      const query = {
        select(columns) {
          if (table === "devices") selectedColumns.push(columns);
          return query;
        },
        eq() {
          return query;
        },
        maybeSingle: async () => ({ data: remoteDevice, error: null }),
        order() {
          envelopeQueries += 1;
          return query;
        },
        limit: async () => ({ data: [], error: null }),
      };
      return query;
    },
    removeChannel: async (channel) => {
      removedChannels.push(channel);
    },
    envelopeQueryCount: () => envelopeQueries,
    removedChannels: () => removedChannels,
    operations: () => operations,
    bindRequests: () => bindRequests,
  };
}


function remoteDeviceFor(device, overrides = {}) {
  return {
    id: device.id,
    user_id: device.userId,
    status: "active",
    key_algorithm: "p256",
    public_key: `\\x${Buffer.from(device.publicKey, "base64url").toString("hex")}`,
    ...overrides,
  };
}


test("同一组织的第二个浏览器用户既不复用也不删除首个用户的私钥", async () => {
  const organizationId = "org-1";
  const firstUserId = "user-1";
  const secondUserId = "user-2";
  const portal = await loadPortal(organizationId);
  const rpcClient = remoteDeviceClient(null, []);
  portal.state.client = rpcClient;

  const firstDevice = await portal.createAndStoreDevice(
    organizationId,
    firstUserId,
  );
  portal.state.session = { user: { id: secondUserId } };

  await assert.doesNotReject(portal.unlockAndRefresh());
  const preservedFirstDevice = await portal.storedDevice(
    organizationId,
    firstUserId,
  );
  const secondDevice = await portal.storedDevice(
    organizationId,
    secondUserId,
  );

  assert.equal(preservedFirstDevice.id, firstDevice.id);
  assert.notEqual(secondDevice.id, firstDevice.id);
  assert.notEqual(secondDevice.privateKey, firstDevice.privateKey);
});


test("IndexedDB 丢失当前设备时新建 browser pending 而不枚举远端 active 设备", async () => {
  const organizationId = "org-lost-indexeddb";
  const userId = "user-lost-indexeddb";
  const portal = await loadPortal(organizationId);
  const client = remoteDeviceClient({ status: "active" }, []);
  let registration;
  const originalRpc = client.rpc;
  client.rpc = async (name, request) => {
    if (name === "register_device") registration = request;
    return originalRpc(name, request);
  };
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };

  await portal.unlockAndRefresh();

  const created = await portal.storedDevice(organizationId, userId);
  assert.ok(created);
  assert.equal(registration.device_id, created.id);
  assert.equal(registration.device_public_key, created.publicKey);
  assert.equal(registration.device_kind, "browser");
  assert.equal(client.operations().includes("from:devices"), false);
  assert.equal(client.operations().includes("rpc:bind_device_session"), false);
  assert.match(portal.elements.get("status").textContent, /等待.*批准/);
});


test("远端设备所有者不匹配时拒绝复用本地私钥", async () => {
  const organizationId = "org-2";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  const selectedColumns = [];
  const client = remoteDeviceClient({
    id: device.id,
    user_id: "user-2",
    status: "active",
    key_algorithm: "p256",
    public_key: `\\x${Buffer.from(device.publicKey, "base64url").toString("hex")}`,
  }, selectedColumns);
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };

  await assert.rejects(
    portal.unlockAndRefresh(),
    /设备身份.*不匹配/,
  );

  assert.match(selectedColumns[0], /user_id/);
  assert.match(selectedColumns[0], /public_key/);
  assert.equal(client.envelopeQueryCount(), 0);
  const preservedDevice = await portal.storedDevice(organizationId, userId);
  assert.ok(preservedDevice);
  assert.equal(preservedDevice.id, device.id);
});


test("远端设备公钥不匹配时拒绝复用本地私钥", async () => {
  const organizationId = "org-3";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  const selectedColumns = [];
  const wrongPublicKey = Buffer.alloc(65, 9);
  wrongPublicKey[0] = 4;
  const client = remoteDeviceClient({
    id: device.id,
    user_id: userId,
    status: "active",
    key_algorithm: "p256",
    public_key: `\\x${wrongPublicKey.toString("hex")}`,
  }, selectedColumns);
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };

  await assert.rejects(
    portal.unlockAndRefresh(),
    /设备身份.*不匹配/,
  );

  assert.match(selectedColumns[0], /user_id/);
  assert.match(selectedColumns[0], /public_key/);
  assert.equal(client.envelopeQueryCount(), 0);
  const preservedDevice = await portal.storedDevice(organizationId, userId);
  assert.ok(preservedDevice);
  assert.equal(preservedDevice.id, device.id);
});


test("远端设备暂时不可见时拒绝解锁但保留本地私钥", async () => {
  const organizationId = "org-4";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  portal.state.session = { user: { id: userId } };

  await assert.rejects(
    portal.unlockAndRefresh(),
    /远端设备记录.*不可见/,
  );

  const preservedDevice = await portal.storedDevice(organizationId, userId);
  assert.ok(preservedDevice);
  assert.equal(preservedDevice.id, device.id);
});


test("已批准设备先绑定当前 Auth session 再读取敏感表", async () => {
  const organizationId = "org-session-binding";
  const userId = "user-session-binding";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  const client = remoteDeviceClient(remoteDeviceFor(device), []);
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };

  await assert.rejects(portal.unlockAndRefresh(), /组织密钥信封/);

  assert.deepEqual(client.bindRequests(), [{
    p_organization_id: organizationId,
    p_device_id: device.id,
  }]);
  assert.ok(
    client.operations().indexOf("rpc:bind_device_session")
      < client.operations().indexOf("from:devices"),
  );
});


test("首次设备登记响应失败后用同一设备身份幂等重试", async () => {
  const organizationId = "org-registration-retry";
  const userId = "user-registration-retry";
  const portal = await loadPortal(organizationId);
  let firstRequest;
  portal.state.client = remoteDeviceClient(null, []);
  portal.state.client.rpc = async (name, request) => {
    assert.equal(name, "register_device");
    firstRequest = request;
    throw new Error("registration response lost");
  };
  portal.state.session = { user: { id: userId } };

  await assert.rejects(portal.unlockAndRefresh(), /response lost/);
  const pendingDevice = await portal.storedDevice(organizationId, userId);
  assert.ok(pendingDevice);
  assert.equal(pendingDevice.pending_registration, true);

  let retryRequest;
  const retryClient = remoteDeviceClient(
    remoteDeviceFor(pendingDevice, { status: "pending" }),
    [],
  );
  retryClient.rpc = async (name, request) => {
    assert.equal(name, "register_device");
    retryRequest = request;
    return { data: pendingDevice.id, error: null };
  };
  portal.state.client = retryClient;

  await portal.unlockAndRefresh();

  assert.equal(retryRequest.device_id, firstRequest.device_id);
  assert.equal(retryRequest.device_public_key, firstRequest.device_public_key);
  assert.equal(
    (await portal.storedDevice(organizationId, userId)).id,
    pendingDevice.id,
  );
  assert.equal(
    (await portal.storedDevice(organizationId, userId)).pending_registration,
    false,
  );
  assert.match(portal.elements.get("status").textContent, /仍待.*批准/);
});


test("从已解锁组织切到待批准组织时先清空旧工作区", async () => {
  const organizationId = "org-pending";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  const oldChannel = { topic: "org-a" };
  const oldRefresh = Promise.resolve();
  const client = remoteDeviceClient(
    remoteDeviceFor(device, { status: "pending" }),
    [],
  );
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };
  portal.state.organizationId = "org-a";
  portal.state.orgKey = { organization: "org-a" };
  portal.state.records = [{ record_id: "secret-a" }];
  portal.state.cursor = 41;
  portal.state.wakeChannel = oldChannel;
  portal.state.refreshPromise = oldRefresh;

  await portal.unlockAndRefresh();

  assert.equal(portal.state.organizationId, organizationId);
  assert.equal(portal.state.orgKey, null);
  assert.deepEqual(portal.state.records, []);
  assert.equal(portal.state.cursor, 0);
  assert.equal(portal.state.wakeChannel, null);
  assert.equal(portal.state.refreshPromise, null);
  assert.deepEqual(client.removedChannels(), [oldChannel]);
});


test("切到身份不匹配组织时清空旧工作区且保留当前用户私钥", async () => {
  const organizationId = "org-mismatch";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  const client = remoteDeviceClient(
    remoteDeviceFor(device, { user_id: "user-2" }),
    [],
  );
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };
  portal.state.organizationId = "org-a";
  portal.state.orgKey = { organization: "org-a" };
  portal.state.records = [{ record_id: "secret-a" }];
  portal.state.cursor = 8;

  await assert.rejects(
    portal.unlockAndRefresh(),
    /设备身份.*不匹配/,
  );

  assert.equal(portal.state.organizationId, organizationId);
  assert.equal(portal.state.orgKey, null);
  assert.deepEqual(portal.state.records, []);
  assert.equal(portal.state.cursor, 0);
  assert.equal(
    (await portal.storedDevice(organizationId, userId)).id,
    device.id,
  );
});


test("旧组织延迟同步响应不能写回新组织", async () => {
  const organizationId = "org-b";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  let resolvePull;
  let markPullStarted;
  const pullStarted = new Promise((resolve) => {
    markPullStarted = resolve;
  });
  const delayedPull = new Promise((resolve) => {
    resolvePull = resolve;
  });
  const client = remoteDeviceClient(
    remoteDeviceFor(device, { status: "pending" }),
    [],
  );
  client.rpc = async (name) => {
    if (name === "pull_sync_events") {
      markPullStarted();
      return delayedPull;
    }
    if (name === "register_device") return { error: null };
    throw new Error(`unexpected RPC: ${name}`);
  };
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };
  portal.state.organizationId = "org-a";
  portal.state.orgKey = { organization: "org-a" };
  portal.state.records = [];
  portal.state.cursor = 0;

  const stalePull = portal.pullCiphertextChanges();
  await pullStarted;
  portal.elements.get("organization").value = organizationId;
  await portal.unlockAndRefresh();
  resolvePull({
    data: [{
      applied: true,
      cursor: 99,
      operation: "upsert",
      record_id: "secret-a",
      payload: { record_type: "alert", version: 1 },
    }],
    error: null,
  });
  await stalePull;

  assert.equal(portal.state.organizationId, organizationId);
  assert.equal(portal.state.orgKey, null);
  assert.deepEqual(portal.state.records, []);
  assert.equal(portal.state.cursor, 0);
  assert.match(portal.elements.get("status").textContent, /仍待.*批准/);
});


test("旧组织 Realtime 回调在切换后不能启动同步", async () => {
  const organizationId = "org-b-realtime";
  const userId = "user-1";
  const portal = await loadPortal(organizationId);
  portal.state.client = remoteDeviceClient(null, []);
  const device = await portal.createAndStoreDevice(organizationId, userId);
  let wakeCallback;
  let pullCalls = 0;
  const client = remoteDeviceClient(
    remoteDeviceFor(device, { status: "pending" }),
    [],
  );
  client.channel = () => {
    const channel = {
      on(event, config, callback) {
        wakeCallback = callback;
        return channel;
      },
      subscribe() {
        return channel;
      },
    };
    return channel;
  };
  client.rpc = async (name) => {
    if (name === "pull_sync_events") {
      pullCalls += 1;
      return { data: [], error: null };
    }
    if (name === "register_device") return { error: null };
    throw new Error(`unexpected RPC: ${name}`);
  };
  portal.state.client = client;
  portal.state.session = { user: { id: userId } };
  portal.state.organizationId = "org-a";
  portal.state.orgKey = { organization: "org-a" };
  await portal.subscribeToWakeups();

  portal.elements.get("organization").value = organizationId;
  await portal.unlockAndRefresh();
  wakeCallback();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(pullCalls, 0);
  assert.equal(portal.state.organizationId, organizationId);
  assert.equal(portal.state.orgKey, null);
});


test("同步繁忙期间的 Realtime 唤醒会合并为一次尾部补拉", async () => {
  const portal = await loadPortal("org-coalesced-wakeup");
  portal.state.organizationId = "org-coalesced-wakeup";
  portal.state.orgKey = { key: "in-memory-only" };
  let resolveFirst;
  let calls = 0;
  portal.state.client = {
    rpc: async () => {
      calls += 1;
      if (calls === 1) {
        return new Promise((resolve) => {
          resolveFirst = resolve;
        });
      }
      return { data: [], error: null };
    },
  };

  portal.refreshFromWakeup();
  portal.refreshFromWakeup();
  resolveFirst({ data: [], error: null });
  await new Promise((resolve) => setTimeout(resolve, 20));

  assert.equal(calls, 2);
});


test("增量同步可以越过五万事件且要求满页游标持续前进", async () => {
  const portal = await loadPortal("org-large-sync");
  portal.state.organizationId = "org-large-sync";
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async (_key, payload) => ({
    title: `事件 ${payload.version}`,
  });
  let calls = 0;
  portal.state.client = {
    rpc: async (name, request) => {
      assert.equal(name, "pull_sync_events");
      calls += 1;
      if (calls > 101) return { data: [], error: null };
      const start = Number(request.after_cursor) + 1;
      return {
        data: Array.from({ length: 500 }, (_, index) => ({
          applied: true,
          cursor: start + index,
          record_id: "record-large-sync",
          payload: {
            organization_id: "org-large-sync",
            record_id: "record-large-sync",
            record_type: "alert",
            version: start + index,
          },
        })),
        error: null,
      };
    },
  };

  await portal.pullCiphertextChanges();

  assert.equal(calls, 102);
  assert.equal(portal.state.cursor, 50_500);
  assert.equal(portal.state.records.length, 1);
});


test("服务端按响应体截断的非空短页不会被误判为同步结束", async () => {
  const portal = await loadPortal("org-size-bounded-sync");
  portal.state.organizationId = "org-size-bounded-sync";
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async () => ({ title: "已校验" });
  let calls = 0;
  portal.state.client = {
    rpc: async () => {
      calls += 1;
      if (calls === 1) {
        return {
          data: [1, 2].map((cursor) => ({
            applied: true,
            cursor,
            record_id: `record-short-${cursor}`,
            payload: {
              organization_id: "org-size-bounded-sync",
              record_id: `record-short-${cursor}`,
              record_type: "alert",
              version: 1,
            },
          })),
          error: null,
        };
      }
      if (calls === 2) {
        return {
          data: [{
            applied: true,
            cursor: 3,
            record_id: "record-short-3",
            payload: {
              organization_id: "org-size-bounded-sync",
              record_id: "record-short-3",
              record_type: "alert",
              version: 1,
            },
          }],
          error: null,
        };
      }
      return { data: [], error: null };
    },
  };

  await portal.pullCiphertextChanges();

  assert.equal(calls, 3);
  assert.equal(portal.state.cursor, 3);
  assert.equal(portal.state.records.length, 3);
});


test("同步中断时保留最后完整页游标并从该游标恢复", async () => {
  const portal = await loadPortal("org-resume-sync");
  portal.state.organizationId = "org-resume-sync";
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async () => ({ title: "已校验" });
  let calls = 0;
  const observedCursors = [];
  portal.state.client = {
    rpc: async (_name, request) => {
      calls += 1;
      observedCursors.push(request.after_cursor);
      if (calls === 1) {
        return {
          data: Array.from({ length: 500 }, (_, index) => ({
            applied: true,
            cursor: index + 1,
            record_id: "record-resume-sync",
            payload: {
              organization_id: "org-resume-sync",
              record_id: "record-resume-sync",
              record_type: "job",
              version: index + 1,
            },
          })),
          error: null,
        };
      }
      if (calls === 2) throw new Error("network interrupted");
      return { data: [], error: null };
    },
  };

  await assert.rejects(portal.pullCiphertextChanges(), /network interrupted/);
  assert.equal(portal.state.cursor, 500);

  await portal.pullCiphertextChanges();
  assert.deepEqual(observedCursors, [0, 500, 500]);
});


test("密文缓存恢复记录头且 IndexedDB 不落盘解密正文", async () => {
  const organizationId = "org-cached-sync";
  const userId = "user-cached-sync";
  const portal = await loadPortal(organizationId);
  portal.state.organizationId = organizationId;
  portal.state.session = { user: { id: userId } };
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async (_key, payload) => ({
    title: `只在内存解密 ${payload.version}`,
  });
  let cachePulls = 0;
  portal.state.client = {
    rpc: async () => (++cachePulls === 1 ? {
      data: [{
        applied: true,
        cursor: 9,
        record_id: "record-cached-sync",
        payload: {
          organization_id: organizationId,
          record_id: "record-cached-sync",
          record_type: "alert",
          version: 3,
          content_hash: "a".repeat(64),
          ciphertext: "opaque",
          content: { title: "绝不能落盘的明文" },
          email: "plaintext@example.com",
        },
      }],
      error: null,
    } : { data: [], error: null }),
  };

  await portal.pullCiphertextChanges();
  const cached = [...portal.stores.get("recordHeads").values()];
  assert.equal(cached.length, 1);
  assert.equal(cached[0].content, undefined);
  assert.equal(cached[0].payload.ciphertext, "opaque");
  assert.equal(cached[0].payload.content, undefined);
  assert.equal(cached[0].payload.email, undefined);

  portal.state.records = [];
  portal.state.cursor = 0;
  await portal.restoreCachedWorkspace(
    organizationId,
    userId,
    portal.state.orgKey,
  );

  assert.equal(portal.state.cursor, 9);
  assert.equal(portal.state.records[0].content.title, "只在内存解密 3");
});


test("任一缓存头解密失败时原子清空当前工作区并从游标零重放", async () => {
  const organizationId = "org-invalid-cache";
  const userId = "user-invalid-cache";
  const otherOrganizationId = "org-unrelated-cache";
  const portal = await loadPortal(organizationId);
  await portal.storedDevice(organizationId, userId);
  const recordHeads = portal.stores.get("recordHeads");
  const syncState = portal.stores.get("syncState");
  const currentWorkspaceKey = JSON.stringify([organizationId, userId]);
  const otherWorkspaceKey = JSON.stringify([otherOrganizationId, userId]);

  recordHeads.set(JSON.stringify([organizationId, userId, "record-valid"]), {
    organizationId,
    userId,
    recordId: "record-valid",
    payload: { record_type: "alert", version: 1 },
  });
  recordHeads.set(JSON.stringify([organizationId, userId, "record-invalid"]), {
    organizationId,
    userId,
    payload: { record_type: "alert", version: 2 },
  });
  recordHeads.set(JSON.stringify([otherOrganizationId, userId, "record-other"]), {
    organizationId: otherOrganizationId,
    userId,
    recordId: "record-other",
    payload: { record_type: "alert", version: 1 },
  });
  syncState.set(currentWorkspaceKey, { cursor: 321 });
  syncState.set(otherWorkspaceKey, { cursor: 654 });
  portal.state.records = [{ record_id: "stale-memory-record" }];
  portal.state.cursor = 999;
  portal.behaviors.decryptRecord = async (_key, payload) => {
    if (payload.version === 2) throw new Error("cache authentication failed");
    return { title: "不应保留的部分恢复记录" };
  };

  await portal.restoreCachedWorkspace(
    organizationId,
    userId,
    { key: "in-memory-only" },
  );

  assert.deepEqual(portal.state.records, []);
  assert.equal(portal.state.cursor, 0);
  assert.equal(
    [...recordHeads.values()].some((entry) => (
      entry.organizationId === organizationId && entry.userId === userId
    )),
    false,
  );
  assert.equal(syncState.has(currentWorkspaceKey), false);
  assert.equal(
    [...recordHeads.values()].some((entry) => (
      entry.organizationId === otherOrganizationId
    )),
    true,
  );
  assert.deepEqual(syncState.get(otherWorkspaceKey), { cursor: 654 });
});


test("隔离上报每批五十条时保留未处理尾部并可继续重试", async () => {
  const organizationId = "org-quarantine-retry";
  const userId = "user-quarantine-retry";
  const portal = await loadPortal(organizationId);
  await portal.storedDevice(organizationId, userId);
  const quarantine = portal.stores.get("syncQuarantine");
  for (let index = 0; index < 51; index += 1) {
    const eventId = `event-${String(index).padStart(2, "0")}`;
    quarantine.set(JSON.stringify([organizationId, userId, eventId]), {
      organizationId,
      userId,
      eventId,
      cursor: index + 1,
      recordId: `record-${index}`,
      versionId: `version-${index}`,
      failureCode: "invalid_schema",
    });
  }
  let reports = 0;
  portal.state.client = {
    rpc: async (name) => {
      assert.equal(name, "report_sync_event_quarantine");
      reports += 1;
      return { data: { report_id: `report-${reports}` }, error: null };
    },
  };

  const afterFirstBatch = await portal.retryPendingQuarantineReports(
    organizationId,
    userId,
  );
  assert.equal(afterFirstBatch, 1);
  assert.equal(reports, 50);
  assert.equal(
    [...quarantine.values()].filter((entry) => !entry.reportedAt).length,
    1,
  );

  const afterSecondBatch = await portal.retryPendingQuarantineReports(
    organizationId,
    userId,
  );
  assert.equal(afterSecondBatch, 0);
  assert.equal(reports, 51);
});


test("完整同步页以单次 IndexedDB 事务提交记录头与游标", async () => {
  const organizationId = "org-page-transaction";
  const userId = "user-page-transaction";
  const portal = await loadPortal(organizationId);
  portal.state.organizationId = organizationId;
  portal.state.session = { user: { id: userId } };
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async () => ({ title: "事务内解密" });
  let transactionPulls = 0;
  portal.state.client = {
    rpc: async () => (++transactionPulls === 1 ? {
      data: Array.from({ length: 3 }, (_, index) => ({
        applied: true,
        cursor: index + 1,
        record_id: `record-page-${index}`,
        payload: {
          organization_id: organizationId,
          record_id: `record-page-${index}`,
          record_type: "alert",
          version: 1,
          content_hash: "d".repeat(64),
          ciphertext: `opaque-${index}`,
        },
      })),
      error: null,
    } : { data: [], error: null }),
  };
  const before = portal.stores.getOpenCount();

  await portal.pullCiphertextChanges();

  assert.equal(portal.stores.getOpenCount() - before, 1);
  assert.equal(portal.state.cursor, 3);
});


test("单条已认证但非 JSON 的事件被隔离且后继游标继续提交", async () => {
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const userId = "00000000-0000-4000-8000-000000000001";
  const portal = await loadPortal(organizationId);
  portal.state.organizationId = organizationId;
  portal.state.session = { user: { id: userId } };
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async (_key, payload) => {
    if (payload.version === 1) {
      const error = new Error("must-not-be-reported");
      error.code = "invalid_json";
      throw error;
    }
    return { title: "安全后继记录", status: "new" };
  };
  const reports = [];
  let pulls = 0;
  portal.state.client = {
    rpc: async (name, request) => {
      if (name === "report_sync_event_quarantine") {
        reports.push(request);
        return {
          data: { report_id: "90000000-0000-4000-8000-000000000001" },
          error: null,
        };
      }
      assert.equal(name, "pull_sync_events");
      pulls += 1;
      if (pulls > 1) return { data: [], error: null };
      return {
        data: [1, 2].map((cursor) => ({
          applied: true,
          cursor,
          event_id: `50000000-0000-4000-8000-00000000000${cursor}`,
          operation: "upsert",
          payload: {
            organization_id: organizationId,
            record_id: `30000000-0000-4000-8000-00000000000${cursor}`,
            version_id: `40000000-0000-4000-8000-00000000000${cursor}`,
            record_type: "alert",
            version: cursor,
            content_hash: "a".repeat(64),
            ciphertext: `opaque-${cursor}`,
          },
        })),
        error: null,
      };
    },
  };

  await portal.pullCiphertextChanges();

  assert.equal(portal.state.cursor, 2);
  assert.deepEqual(
    portal.state.records.map((record) => record.content.title),
    ["安全后继记录"],
  );
  assert.equal(reports.length, 1);
  assert.equal(reports[0].p_failure_code, "invalid_json");
  assert.equal(Object.hasOwn(reports[0], "message"), false);
  const quarantine = [...portal.stores.get("syncQuarantine").values()][0];
  assert.equal(quarantine.cursor, 1);
  assert.equal(quarantine.failureCode, "invalid_json");
  assert.equal(Object.hasOwn(quarantine, "ciphertext"), false);
  assert.ok(quarantine.reportedAt);
});


test("管理员隔离墓碑由当前浏览器设备加密且绑定报告版本", async () => {
  const organizationId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const userId = "00000000-0000-4000-8000-000000000001";
  const portal = await loadPortal(organizationId);
  portal.state.organizationId = organizationId;
  portal.state.session = { user: { id: userId } };
  portal.state.orgKey = new Uint8Array(32).fill(7);
  portal.state.orgKeyVersion = 3;
  portal.state.client = {
    rpc: async (name) => {
      assert.equal(name, "register_device");
      return { data: null, error: null };
    },
  };
  const device = await portal.createAndStoreDevice(organizationId, userId);
  let encryptionRequest;
  portal.behaviors.encryptRecord = async (_key, request) => {
    encryptionRequest = request;
    return {
      ciphertext: "safe-ciphertext",
      nonce: "safe-nonce",
      wrapped_data_key: "safe-wrapped-key",
      wrap_nonce: "safe-wrap-nonce",
      content_hash: "b".repeat(64),
    };
  };

  const event = await portal.buildQuarantineTombstoneEvent({
    record_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    version_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    logical_version: 8,
    record_type: "alert",
  });

  assert.equal(encryptionRequest.version, 9);
  assert.equal(encryptionRequest.keyVersion, 3);
  assert.equal(encryptionRequest.content.schema_version, 1);
  assert.equal(event.organization_id, organizationId);
  assert.equal(event.record_id, encryptionRequest.recordId);
  assert.equal(event.operation, "delete");
  assert.equal(event.payload.version, 9);
  assert.equal(event.payload.base_version_id, "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
  assert.equal(event.payload.device_id, device.id);
  assert.equal(event.payload.deleted, true);
  assert.equal(event.payload.ciphertext, "safe-ciphertext");
  assert.equal(JSON.stringify(event).includes("已删除的隔离记录"), false);
});


test("实时拉取记录保留服务端校验过的内容哈希供工作流乐观锁使用", async () => {
  const portal = await loadPortal("org-workflow-hash");
  portal.state.organizationId = "org-workflow-hash";
  portal.state.orgKey = { key: "in-memory-only" };
  portal.behaviors.decryptRecord = async () => ({ title: "待审稿件" });
  let workflowPulls = 0;
  portal.state.client = {
    rpc: async () => (++workflowPulls === 1 ? {
      data: [{
        applied: true,
        cursor: 1,
        record_id: "record-workflow-hash",
        payload: {
          organization_id: "org-workflow-hash",
          record_id: "record-workflow-hash",
          record_type: "publication_item",
          version: 2,
          content_hash: "c".repeat(64),
        },
      }],
      error: null,
    } : { data: [], error: null }),
  };

  await portal.pullCiphertextChanges();

  assert.equal(portal.state.records[0].content_hash, "c".repeat(64));
});


test("Postgres bytea 解码严格拒绝奇数长度和非十六进制", async () => {
  const portal = await loadPortal("org-bytea");

  assert.throws(
    () => portal.byteaToBase64url("\\x001"),
    /无效的密钥信封编码/,
  );
  assert.throws(
    () => portal.byteaToBase64url("\\x0g"),
    /无效的密钥信封编码/,
  );
  assert.equal(
    portal.byteaToBase64url("\\x00ff"),
    Buffer.from([0, 255]).toString("base64url"),
  );
});
