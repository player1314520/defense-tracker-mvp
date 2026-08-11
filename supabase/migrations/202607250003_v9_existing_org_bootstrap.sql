-- Preserve the local organization UUID during first ciphertext migration.
begin;

create function private.bootstrap_organization(
    name_ciphertext text,
    name_nonce text,
    device_id uuid,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    key_algorithm text,
    requested_organization_id uuid
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    new_org uuid := requested_organization_id;
begin
    if actor is null then raise exception 'authentication required'; end if;
    if new_org is null then raise exception 'organization id required'; end if;
    if key_algorithm not in ('x25519','p256') then
        raise exception 'unsupported key algorithm';
    end if;
    insert into public.organizations(
        id,name_ciphertext,name_nonce,created_by
    ) values (
        new_org,
        private.decode_base64url(name_ciphertext),
        private.decode_base64url(name_nonce),
        actor
    );
    insert into public.memberships(organization_id,user_id,role,status)
    values (new_org,actor,'owner','active');
    insert into public.devices(
        id,organization_id,user_id,key_algorithm,public_key,
        name_ciphertext,name_nonce,status
    ) values (
        device_id,new_org,actor,key_algorithm,
        private.decode_base64url(device_public_key),
        private.decode_base64url(device_name_ciphertext),
        private.decode_base64url(device_name_nonce),
        'active'
    );
    return new_org;
end;
$$;

create function public.bootstrap_organization(
    name_ciphertext text,
    name_nonce text,
    device_id uuid,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    key_algorithm text,
    requested_organization_id uuid
)
returns uuid
language sql
security invoker
set search_path = ''
as $$
    select private.bootstrap_organization(
        name_ciphertext,name_nonce,device_id,device_public_key,
        device_name_ciphertext,device_name_nonce,key_algorithm,
        requested_organization_id
    );
$$;

revoke all on function private.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) from public, anon;
grant execute on function private.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) to authenticated;
revoke all on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) from public, anon;
grant execute on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) to authenticated;

commit;
