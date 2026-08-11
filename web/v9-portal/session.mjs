export async function logoutPortalSession({
  signOut,
  removeWakeChannel,
  clearAuth,
  clearMemory,
}) {
  let remoteError = null;
  let localError = null;

  try {
    const result = await signOut();
    if (result?.error) remoteError = result.error;
  } catch (error) {
    remoteError = error;
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
    remoteConfirmed: remoteError === null,
    localCleared: localError === null,
    remoteError,
    localError,
  };
}
