-- Make response-loss retries safe without turning device registration into an
-- upsert: only an exact P-256 desktop replay may return an existing row.
begin;

create or replace function private.register_mvp_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    device_kind text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    membership_status text;
    invitation_expiry timestamptz;
    membership_invitation_id uuid;
    pending_device_count bigint;
    existing public.devices%rowtype;
    decoded_public_key bytea;
    decoded_name_ciphertext bytea;
    decoded_name_nonce bytea;
begin
    if actor is null then
        raise exception 'authentication required'
            using errcode = '42501';
    end if;
    if organization_id is null or device_id is null then
        raise exception 'invalid device registration';
    end if;
    if key_algorithm is null
       or key_algorithm not in ('x25519','p256')
       or device_kind is null
       or device_kind not in ('desktop','browser') then
        raise exception 'unsupported device type';
    end if;
    if device_public_key is null
       or length(device_public_key) > 128
       or length(device_public_key) % 4 = 1
       or device_public_key !~ '^[A-Za-z0-9_-]+$'
       or device_name_ciphertext is null
       or length(device_name_ciphertext) > 1368
       or length(device_name_ciphertext) % 4 = 1
       or device_name_ciphertext !~ '^[A-Za-z0-9_-]+$'
       or device_name_nonce is null
       or length(device_name_nonce) > 32
       or length(device_name_nonce) % 4 = 1
       or device_name_nonce !~ '^[A-Za-z0-9_-]+$' then
        raise exception 'device field size limit exceeded';
    end if;

    begin
        decoded_public_key := private.decode_base64url(device_public_key);
        decoded_name_ciphertext := private.decode_base64url(
            device_name_ciphertext
        );
        decoded_name_nonce := private.decode_base64url(device_name_nonce);
    exception when others then
        raise exception 'invalid device registration';
    end;
    if (
        key_algorithm = 'x25519'
        and octet_length(decoded_public_key) <> 32
    ) or (
        key_algorithm = 'p256'
        and (
            octet_length(decoded_public_key) <> 65
            or pg_catalog.get_byte(decoded_public_key,0) <> 4
        )
    ) or octet_length(decoded_name_ciphertext) not between 16 and 1024
       or octet_length(decoded_name_nonce) <> 12
       or private.encode_base64url(decoded_public_key) <> device_public_key
       or private.encode_base64url(decoded_name_ciphertext)
          <> device_name_ciphertext
       or private.encode_base64url(decoded_name_nonce) <> device_name_nonce then
        raise exception 'device field size limit exceeded';
    end if;

    -- The membership row is the serialization point for both first attempts
    -- and retries by the same caller.
    select m.status,m.invite_expires_at,m.invitation_request_id
      into membership_status,invitation_expiry,membership_invitation_id
    from public.memberships m
    where m.organization_id = register_mvp_device.organization_id
      and m.user_id = actor
      and (
          m.status = 'active'
          or (
              m.status = 'invited'
              and m.invite_expires_at > statement_timestamp()
          )
      )
    for update;
    if not found then
        raise exception 'active or unexpired invited membership required'
            using errcode = '42501';
    end if;

    select d.* into existing
    from public.devices d
    where d.organization_id = register_mvp_device.organization_id
      and d.id = register_mvp_device.device_id
    for update;
    if found then
        if existing.user_id is distinct from actor
           or key_algorithm <> 'p256'
           or device_kind <> 'desktop'
           or existing.key_algorithm <> 'p256'
           or existing.device_kind <> 'desktop'
           or existing.public_key <> decoded_public_key
           or existing.name_ciphertext <> decoded_name_ciphertext
           or existing.name_nonce <> decoded_name_nonce
           or existing.status not in ('pending','active')
           or (
               existing.status = 'active'
               and membership_status <> 'active'
           )
           or (
               membership_status = 'invited'
               and existing.invitation_request_id
                   is distinct from membership_invitation_id
           )
           or (
               membership_status = 'active'
               and existing.invitation_request_id is not null
               and existing.invitation_request_id
                   is distinct from membership_invitation_id
           ) then
            raise exception 'device registration conflict'
                using errcode = '23505';
        end if;
        return existing.id;
    end if;

    select count(*) into pending_device_count
    from public.devices d
    where d.organization_id = register_mvp_device.organization_id
      and d.user_id = actor
      and d.status = 'pending';
    if membership_status = 'invited'
       and pending_device_count >= 1 then
        raise exception 'invited member already has pending device';
    end if;
    if membership_status = 'active'
       and pending_device_count >= 5 then
        raise exception 'active member pending device limit reached';
    end if;

    insert into public.devices(
        id,organization_id,user_id,key_algorithm,public_key,
        name_ciphertext,name_nonce,status,invitation_request_id,device_kind
    ) values (
        device_id,organization_id,actor,key_algorithm,
        decoded_public_key,decoded_name_ciphertext,decoded_name_nonce,
        'pending',
        case
            when membership_status = 'invited' then membership_invitation_id
            else null
        end,
        device_kind
    );
    return device_id;
end;
$$;

create or replace function public.register_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    device_kind text default 'desktop'
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.can_register_device_session(organization_id) then
        raise exception 'device registration session denied'
            using errcode = '42501';
    end if;
    return private.register_mvp_device(
        organization_id,device_id,key_algorithm,device_public_key,
        device_name_ciphertext,device_name_nonce,device_kind
    );
end;
$$;

revoke all on function private.register_mvp_device(uuid,uuid,text,text,text,text,text)
    from public, anon, authenticated, service_role;
revoke all on function public.register_device(uuid,uuid,text,text,text,text,text)
    from public, anon, authenticated;
grant execute on function public.register_device(uuid,uuid,text,text,text,text,text)
    to authenticated;

comment on function public.register_device(uuid,uuid,text,text,text,text,text) is
    'Registers a pending device; an exact same-user P-256 desktop retry is idempotent and never mutates the stored row.';

commit;
