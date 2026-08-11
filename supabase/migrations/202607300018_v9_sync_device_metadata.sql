-- Expose only the active device key material required for organization sync.
begin;

create or replace function public.list_sync_devices(
    p_organization_id uuid
)
returns table (
    org_id uuid,
    device_id uuid,
    key_algorithm text,
    public_key text
)
language plpgsql
stable
security definer
set search_path = ''
as $sync_devices$
begin
    if not private.is_org_member(p_organization_id) then
        raise exception 'active membership required'
            using errcode = '42501';
    end if;

    return query
    select
        d.organization_id as org_id,
        d.id as device_id,
        d.key_algorithm,
        private.encode_base64url(d.public_key) as public_key
    from public.devices d
    where d.organization_id = p_organization_id
      and d.status = 'active'
    order by d.id;
end;
$sync_devices$;

revoke all on function public.list_sync_devices(uuid)
    from public, anon, authenticated;
grant execute on function public.list_sync_devices(uuid)
    to authenticated;

commit;
