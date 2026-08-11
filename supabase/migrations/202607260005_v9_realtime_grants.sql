-- Existing Staging projects may have inherited Supabase default table grants.
revoke all on table public.sync_wakeups from public, anon, authenticated;
grant select on table public.sync_wakeups to authenticated;
