-- Keep JWT session validation compatible with PostgreSQL's regex repeat limit.
begin;

create or replace function private.current_session_id()
returns text
language sql
stable
security definer
set search_path = ''
as $$
    with claim as (
        select nullif((select auth.jwt()) ->> 'session_id','') as session_id
    )
    select case
        when length(session_id) between 16 and 256
         and session_id ~ '^[A-Za-z0-9._~-]+$'
        then session_id
        else null
    end
    from claim;
$$;

revoke all on function private.current_session_id()
    from public, anon, authenticated, service_role;

commit;
