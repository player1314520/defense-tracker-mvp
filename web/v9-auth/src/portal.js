import { createClient } from "@supabase/supabase-js";

export function createPortalClient(url, publishableKey, storage) {
  return createClient(url, publishableKey, {
    auth: {
      flowType: "pkce",
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      storage,
    },
  });
}
