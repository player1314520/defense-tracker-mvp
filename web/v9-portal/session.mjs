function isPkceVerifierKey(key) {
  return typeof key === "string" && key.endsWith("-code-verifier");
}


export function createPortalAuthStorage(storage) {
  const memory = new Map();
  return {
    async getItem(key) {
      if (isPkceVerifierKey(key)) return (await storage.getItem(key)) ?? null;
      return memory.get(key) ?? null;
    },
    async setItem(key, value) {
      if (isPkceVerifierKey(key)) return storage.setItem(key, value);
      memory.set(key, value);
    },
    async removeItem(key) {
      if (isPkceVerifierKey(key)) return storage.removeItem(key);
      memory.delete(key);
    },
    async clear() {
      memory.clear();
      await storage.clear();
    },
  };
}


export async function clearLegacyAuthSessions(storage) {
  const keys = await storage.keys();
  await Promise.all(
    keys
      .filter((key) => !isPkceVerifierKey(key))
      .map((key) => storage.removeItem(key)),
  );
}


export async function logoutPortalSession({
  revokeDeviceSession,
  signOut,
  removeWakeChannel,
  clearAuth,
  clearMemory,
}) {
  let revocationError = null;
  let signOutError = null;
  let localError = null;

  try {
    const result = await revokeDeviceSession();
    if (result?.error) {
      revocationError = result.error;
    } else if (result?.data?.revoked !== true) {
      revocationError = new Error("device session revocation was not confirmed");
    }
  } catch (error) {
    revocationError = error;
  }

  try {
    const result = await signOut({ scope: "local" });
    if (result?.error) signOutError = result.error;
  } catch (error) {
    signOutError = error;
  }

  try {
    await removeWakeChannel();
  } catch (error) {
    localError = error;
  }
  try {
    await clearAuth();
  } catch (error) {
    localError ||= error;
  }
  try {
    clearMemory();
  } catch (error) {
    localError ||= error;
  }

  return {
    remoteConfirmed: revocationError === null && signOutError === null,
    deviceSessionRevoked: revocationError === null,
    authSignedOut: signOutError === null,
    localCleared: localError === null,
    revocationError,
    signOutError,
    localError,
  };
}
