import { createClient } from "@supabase/supabase-js";

export function createPortalClient(url, publishableKey, storage) {
  return createClient(url, publishableKey, {
    auth: {
      flowType: "pkce",
      // Supabase must use the supplied storage so PKCE survives the emailed
      // callback navigation.  The Portal adapter persists only the verifier;
      // access and refresh sessions stay in memory. Supabase auth events may
      // still be broadcast to concurrently open same-origin contexts.
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      storage,
    },
  });
}
