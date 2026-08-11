-- Realtime publishes metadata-only wakeups; ciphertext remains cursor-pulled.
create table if not exists public.sync_wakeups (
    organization_id uuid primary key
        references public.organizations(id) on delete cascade,
    latest_cursor bigint not null check (latest_cursor > 0),
    updated_at timestamptz not null default timezone('utc', now())
);

alter table public.sync_wakeups enable row level security;
alter table public.sync_wakeups force row level security;

revoke all on table public.sync_wakeups from public, anon, authenticated;
grant select on table public.sync_wakeups to authenticated;

drop policy if exists sync_wakeups_select_active_member
    on public.sync_wakeups;
create policy sync_wakeups_select_active_member
on public.sync_wakeups
for select
to authenticated
using (
    private.is_org_member(organization_id)
);

create or replace function private.bump_sync_wakeup()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, private
as $$
begin
    insert into public.sync_wakeups(
        organization_id,
        latest_cursor,
        updated_at
    )
    values (
        new.organization_id,
        new.cursor,
        timezone('utc', now())
    )
    on conflict (organization_id) do update
    set latest_cursor = greatest(
            public.sync_wakeups.latest_cursor,
            excluded.latest_cursor
        ),
        updated_at = excluded.updated_at;
    return new;
end;
$$;

revoke all on function private.bump_sync_wakeup() from public;

drop trigger if exists sync_events_wakeup on public.sync_events;
create trigger sync_events_wakeup
after insert on public.sync_events
for each row execute function private.bump_sync_wakeup();

do $$
begin
    if not exists (
        select 1
        from pg_catalog.pg_publication_tables
        where pubname = 'supabase_realtime'
          and schemaname = 'public'
          and tablename = 'sync_wakeups'
    ) then
        alter publication supabase_realtime
            add table public.sync_wakeups;
    end if;
end;
$$;
