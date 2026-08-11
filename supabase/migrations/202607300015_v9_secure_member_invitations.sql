-- Secure, JWT-bound member invitation lifecycle.
-- The database stores only a SHA-256 email digest; the Auth service owns email.
begin;

create table private.member_invitation_requests (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    email_sha256 text not null
        check (email_sha256 ~ '^[0-9a-f]{64}$'),
    role text not null check (
        role in ('owner','admin','collector','analyst','editor','approver')
    ),
    status text not null default 'requested' check (
        status in ('requested','finalized','cancelled')
    ),
    requested_by uuid references auth.users(id) on delete set null,
    requested_by_audit_id uuid not null,
    invited_user_id uuid references auth.users(id) on delete set null,
    invited_user_audit_id uuid,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    finalized_at timestamptz,
    cancelled_at timestamptz,
    unique (organization_id,id),
    check (expires_at > created_at),
    check (
        (
            status = 'requested'
            and invited_user_audit_id is null
            and finalized_at is null
            and cancelled_at is null
        )
        or (
            status = 'finalized'
            and invited_user_audit_id is not null
            and finalized_at is not null
            and cancelled_at is null
        )
        or (
            status = 'cancelled'
            and cancelled_at is not null
            and (
                (
                    invited_user_audit_id is null
                    and finalized_at is null
                )
                or (
                    invited_user_audit_id is not null
                    and finalized_at is not null
                )
            )
        )
    )
);

create unique index member_invitation_requests_one_pending_email
    on private.member_invitation_requests(
        organization_id,email_sha256
    )
    where status = 'requested';
create index member_invitation_requests_requested_by_idx
    on private.member_invitation_requests(requested_by_audit_id);
create index member_invitation_requests_invited_user_idx
    on private.member_invitation_requests(invited_user_audit_id)
    where invited_user_audit_id is not null;

revoke all on table private.member_invitation_requests
    from public, anon, authenticated;

alter table public.memberships
    drop constraint if exists memberships_status_check;
alter table public.memberships
    add constraint memberships_status_check
    check (status in ('active','invited','revoked'));

alter table public.memberships
    add column if not exists invited_by uuid,
    add column if not exists invited_by_audit_id uuid,
    add column if not exists invited_at timestamptz,
    add column if not exists invite_expires_at timestamptz,
    add column if not exists invitation_request_id uuid,
    add column if not exists accepted_at timestamptz;

alter table public.memberships
    add constraint memberships_invited_by_fk
        foreign key (invited_by)
        references auth.users(id) on delete set null,
    add constraint memberships_invitation_request_fk
        foreign key (
            organization_id,invitation_request_id
        )
        references private.member_invitation_requests(
            organization_id,id
        )
        deferrable initially deferred,
    add constraint memberships_invitation_metadata_check check (
        status <> 'invited'
        or (
            invited_by_audit_id is not null
            and invited_at is not null
            and invite_expires_at is not null
            and invite_expires_at > invited_at
            and invitation_request_id is not null
            and accepted_at is null
            and revoked_at is null
        )
    );

create unique index memberships_invitation_request_unique
    on public.memberships(invitation_request_id)
    where invitation_request_id is not null;

alter table public.devices
    add column if not exists invitation_request_id uuid;

alter table public.devices
    add constraint devices_invitation_request_fk
        foreign key (
            organization_id,invitation_request_id
        )
        references private.member_invitation_requests(
            organization_id,id
        )
        deferrable initially deferred;

create index devices_invitation_request_idx
    on public.devices(organization_id,invitation_request_id)
    where invitation_request_id is not null;

create or replace function private.can_read_device(
    target_org uuid,
    target_user uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.memberships actor_membership
        where actor_membership.organization_id = target_org
          and actor_membership.user_id = (select auth.uid())
          and actor_membership.status = 'active'
          and actor_membership.role in ('owner','admin')
    ) or (
        target_user = (select auth.uid())
        and exists (
            select 1
            from public.memberships m
            where m.organization_id = target_org
              and m.user_id = target_user
              and (
                  m.status = 'active'
                  or (
                      m.status = 'invited'
                      and m.invite_expires_at > now()
                  )
              )
        )
    );
$$;

create or replace function private.begin_member_invitation(
    p_organization_id uuid,
    p_email_sha256 text,
    p_role text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    locked_organization uuid;
    new_request_id uuid;
    existing_request private.member_invitation_requests%rowtype;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if p_email_sha256 is null
       or p_email_sha256 <> lower(p_email_sha256)
       or p_email_sha256 !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid email hash';
    end if;
    if p_role not in (
        'owner','admin','collector','analyst','editor','approver'
    ) then
        raise exception 'invalid role';
    end if;

    select o.id into locked_organization
    from public.organizations o
    where o.id = p_organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = p_organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role not in ('owner','admin') then
        raise exception 'owner or admin required';
    end if;
    if p_role = 'owner' and actor_role <> 'owner' then
        raise exception 'only owner can invite owner';
    end if;

    update private.member_invitation_requests r
       set status = 'cancelled',
           cancelled_at = now()
     where r.organization_id = p_organization_id
       and r.email_sha256 = p_email_sha256
       and r.status = 'requested'
       and r.expires_at <= now();

    select r.* into existing_request
        from private.member_invitation_requests r
        where r.organization_id = p_organization_id
          and r.email_sha256 = p_email_sha256
          and r.status = 'requested'
        for update;
    if found then
        -- Authorized callers receive the same success shape whether this is
        -- their retry or another administrator already created the request.
        -- The existing role/requester remain immutable.
        return existing_request.id;
    end if;

    if exists (
        select 1
        from public.memberships m
        join auth.users u on u.id = m.user_id
        where m.organization_id = p_organization_id
          and (
              m.status = 'active'
              or (
                  m.status = 'invited'
                  and m.invite_expires_at > now()
              )
          )
          and encode(
              extensions.digest(
                  convert_to(lower(trim(u.email)), 'UTF8'),
                  'sha256'
              ),
              'hex'
          ) = p_email_sha256
    ) then
        -- Do not disclose email-to-membership correlation through the Edge
        -- response. This opaque reference is deliberately not persisted.
        return gen_random_uuid();
    end if;

    insert into private.member_invitation_requests(
        organization_id,email_sha256,role,requested_by,
        requested_by_audit_id,expires_at
    ) values (
        p_organization_id,p_email_sha256,p_role,actor,actor,
        now() + interval '24 hours'
    )
    returning id into new_request_id;

    return new_request_id;
end;
$$;

create or replace function private.accept_member_invitation()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_email_hash text;
    candidate record;
    locked_organization uuid;
    target_request private.member_invitation_requests%rowtype;
    current_membership public.memberships%rowtype;
    inviter_role text;
    accepted_count integer := 0;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select encode(
        extensions.digest(
            convert_to(lower(trim(u.email)), 'UTF8'),
            'sha256'
        ),
        'hex'
    ) into actor_email_hash
    from auth.users u
    where u.id = actor
      and u.email is not null;
    if actor_email_hash is null then
        raise exception 'authenticated email required';
    end if;

    -- Pre-read only identifiers in a stable order. Every mutable row is
    -- re-read after the organization lock before it is trusted.
    for candidate in
        select r.organization_id,r.id
        from private.member_invitation_requests r
        where (
            r.status = 'requested'
            and r.email_sha256 = actor_email_hash
            and r.expires_at > now()
        ) or (
            r.status = 'finalized'
            and r.invited_user_audit_id = actor
            and exists (
                select 1
                from public.memberships m
                where m.organization_id = r.organization_id
                  and m.user_id = actor
                  and m.invitation_request_id = r.id
                  and m.status in ('invited','active')
            )
        )
        order by r.organization_id,r.id
    loop
        select o.id into locked_organization
        from public.organizations o
        where o.id = candidate.organization_id
        for update;
        if not found then
            continue;
        end if;

        select r.* into target_request
        from private.member_invitation_requests r
        where r.organization_id = candidate.organization_id
          and r.id = candidate.id
        for update;
        if not found then
            continue;
        end if;

        if target_request.status = 'finalized' then
            if target_request.invited_user_audit_id
               is distinct from actor then
                continue;
            end if;
            -- A retry is successful but does not count the same invitation
            -- twice, including after its device has activated membership.
            continue;
        end if;
        if target_request.status <> 'requested'
           or target_request.email_sha256 <> actor_email_hash
           or target_request.expires_at <= now() then
            continue;
        end if;

        inviter_role := null;
        select m.role into inviter_role
        from public.memberships m
        where m.organization_id = candidate.organization_id
          and m.user_id = target_request.requested_by
          and m.status = 'active';
        if inviter_role is null
           or inviter_role not in ('owner','admin')
           or (
               target_request.role = 'owner'
               and inviter_role <> 'owner'
           ) then
            update private.member_invitation_requests
               set status = 'cancelled',
                   cancelled_at = now()
             where id = target_request.id;
            continue;
        end if;

        select m.* into current_membership
        from public.memberships m
        where m.organization_id = candidate.organization_id
          and m.user_id = actor
        for update;

        if found then
            if current_membership.status = 'active'
               or (
                   current_membership.status = 'invited'
                   and current_membership.invite_expires_at > now()
               ) then
                update private.member_invitation_requests
                   set status = 'cancelled',
                       cancelled_at = now()
                 where id = target_request.id;
                continue;
            end if;

            update public.devices
               set status = 'revoked',
                   revoked_at = now()
             where devices.organization_id =
                       candidate.organization_id
               and devices.user_id = actor
               and devices.status = 'pending';

            update public.memberships
               set role = target_request.role,
                   status = 'invited',
                   invited_by = target_request.requested_by,
                   invited_by_audit_id =
                       target_request.requested_by_audit_id,
                   invited_at = now(),
                   invite_expires_at = target_request.expires_at,
                   invitation_request_id = target_request.id,
                   accepted_at = null,
                   revoked_at = null
             where memberships.organization_id =
                       candidate.organization_id
               and memberships.user_id = actor;
        else
            insert into public.memberships(
                organization_id,user_id,role,status,invited_by,
                invited_by_audit_id,invited_at,invite_expires_at,
                invitation_request_id
            ) values (
                candidate.organization_id,actor,target_request.role,
                'invited',target_request.requested_by,
                target_request.requested_by_audit_id,now(),
                target_request.expires_at,target_request.id
            );
        end if;

        update private.member_invitation_requests
           set status = 'finalized',
               invited_user_id = actor,
               invited_user_audit_id = actor,
               finalized_at = now()
         where id = target_request.id;
        accepted_count := accepted_count + 1;
    end loop;

    return jsonb_build_object('accepted_count',accepted_count);
end;
$$;

create or replace function private.cancel_member_invitation(
    p_invitation_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    target_organization uuid;
    locked_organization uuid;
    target_request private.member_invitation_requests%rowtype;
    membership_status text;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select r.organization_id into target_organization
    from private.member_invitation_requests r
    where r.id = p_invitation_id;
    if not found then
        return false;
    end if;

    select o.id into locked_organization
    from public.organizations o
    where o.id = target_organization
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = target_organization
      and m.user_id = actor
      and m.status = 'active';
    if actor_role not in ('owner','admin') then
        raise exception 'owner or admin required';
    end if;

    select r.* into target_request
    from private.member_invitation_requests r
    where r.id = p_invitation_id
      and r.organization_id = target_organization
    for update;
    if not found then
        return false;
    end if;
    if target_request.role = 'owner' and actor_role <> 'owner' then
        raise exception 'only owner can invite owner';
    end if;
    if target_request.status = 'cancelled' then
        return true;
    end if;
    if target_request.status = 'finalized' then
        membership_status := null;
        select m.status into membership_status
        from public.memberships m
        where m.organization_id = target_organization
          and m.invitation_request_id = target_request.id
        for update;
        if membership_status = 'active' then
            raise exception 'active membership requires revoke_member';
        end if;
        if membership_status = 'invited' then
            update public.memberships
               set status = 'revoked',
                   revoked_at = now()
             where memberships.organization_id =
                       target_organization
               and memberships.invitation_request_id =
                       target_request.id
               and memberships.status = 'invited';

            update public.devices
               set status = 'revoked',
                   revoked_at = now()
             where devices.organization_id = target_organization
               and devices.invitation_request_id =
                       target_request.id
               and devices.status = 'pending';
        end if;

        update private.member_invitation_requests
           set status = 'cancelled',
               cancelled_at = now()
         where id = target_request.id;
        return true;
    end if;
    if target_request.status <> 'requested' then
        return false;
    end if;

    update private.member_invitation_requests
       set status = 'cancelled',
           cancelled_at = now()
     where id = target_request.id;
    return true;
end;
$$;

create or replace function private.list_member_invitations(
    p_organization_id uuid
)
returns table (
    invitation_id uuid,
    invitation_role text,
    invitation_status text,
    expires_at timestamptz,
    created_at timestamptz,
    finalized_at timestamptz,
    cancelled_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = p_organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role not in ('owner','admin') then
        raise exception 'owner or admin required';
    end if;

    return query
    select
        r.id,
        r.role,
        r.status,
        r.expires_at,
        r.created_at,
        r.finalized_at,
        r.cancelled_at
    from private.member_invitation_requests r
    where r.organization_id = p_organization_id
    order by
        (r.status = 'requested') desc,
        r.created_at desc,
        r.id
    limit 200;
end;
$$;

create or replace function private.register_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text
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
    decoded_public_key bytea;
    decoded_name_ciphertext bytea;
    decoded_name_nonce bytea;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if key_algorithm is null
       or key_algorithm not in ('x25519','p256') then
        raise exception 'unsupported key algorithm';
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

    decoded_public_key :=
        private.decode_base64url(device_public_key);
    decoded_name_ciphertext :=
        private.decode_base64url(device_name_ciphertext);
    decoded_name_nonce :=
        private.decode_base64url(device_name_nonce);
    if (
        key_algorithm = 'x25519'
        and octet_length(decoded_public_key) <> 32
    ) or (
        key_algorithm = 'p256'
        and octet_length(decoded_public_key) <> 65
    ) or octet_length(decoded_name_ciphertext) < 16
       or octet_length(decoded_name_ciphertext) > 1024
       or octet_length(decoded_name_nonce) <> 12 then
        raise exception 'device field size limit exceeded';
    end if;

    select m.status,m.invite_expires_at,m.invitation_request_id
      into membership_status,invitation_expiry,
           membership_invitation_id
    from public.memberships m
    where m.organization_id = register_device.organization_id
      and m.user_id = actor
      and (
          m.status = 'active'
          or (
              m.status = 'invited'
              and m.invite_expires_at > now()
          )
      )
    for update;
    if not found then
        raise exception 'active or unexpired invited membership required';
    end if;

    select count(*) into pending_device_count
    from public.devices d
    where d.organization_id = register_device.organization_id
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
        name_ciphertext,name_nonce,status,invitation_request_id
    ) values (
        device_id,organization_id,actor,key_algorithm,
        decoded_public_key,decoded_name_ciphertext,decoded_name_nonce,
        'pending',
        case
            when membership_status = 'invited'
            then membership_invitation_id
            else null
        end
    );
    return device_id;
end;
$$;

create or replace function private.pair_device(
    organization_id uuid,
    device_id uuid,
    target_user_id uuid,
    envelope_key_version integer,
    envelope_algorithm text,
    ephemeral_public_key text,
    envelope_nonce text,
    envelope_ciphertext text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    organization_key_version integer;
    target_membership public.memberships%rowtype;
    target_key_algorithm text;
    target_device_invitation_id uuid;
    decoded_ephemeral_public_key bytea;
    decoded_envelope_nonce bytea;
    decoded_envelope_ciphertext bytea;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if ephemeral_public_key is null
       or length(ephemeral_public_key) > 128
       or length(ephemeral_public_key) % 4 = 1
       or ephemeral_public_key !~ '^[A-Za-z0-9_-]+$'
       or envelope_nonce is null
       or length(envelope_nonce) > 32
       or length(envelope_nonce) % 4 = 1
       or envelope_nonce !~ '^[A-Za-z0-9_-]+$'
       or envelope_ciphertext is null
       or length(envelope_ciphertext) > 128
       or length(envelope_ciphertext) % 4 = 1
       or envelope_ciphertext !~ '^[A-Za-z0-9_-]+$' then
        raise exception 'envelope field size limit exceeded';
    end if;

    decoded_ephemeral_public_key :=
        private.decode_base64url(ephemeral_public_key);
    decoded_envelope_nonce :=
        private.decode_base64url(envelope_nonce);
    decoded_envelope_ciphertext :=
        private.decode_base64url(envelope_ciphertext);
    if (
        envelope_algorithm = 'x25519'
        and octet_length(decoded_ephemeral_public_key) <> 32
    ) or (
        envelope_algorithm = 'p256'
        and octet_length(decoded_ephemeral_public_key) <> 65
    ) or envelope_algorithm is null
       or envelope_algorithm not in ('x25519','p256')
       or octet_length(decoded_envelope_nonce) <> 12
       or octet_length(decoded_envelope_ciphertext) <> 48 then
        raise exception 'envelope field size limit exceeded';
    end if;

    select o.key_version into organization_key_version
    from public.organizations o
    where o.id = pair_device.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = pair_device.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role not in ('owner','admin') then
        raise exception 'owner or admin required';
    end if;

    select m.* into target_membership
    from public.memberships m
    where m.organization_id = pair_device.organization_id
      and m.user_id = target_user_id
    for update;
    if not found or target_membership.status not in ('active','invited') then
        raise exception 'target membership is not pairable';
    end if;
    if target_membership.status = 'invited'
       and target_membership.invite_expires_at <= now() then
        raise exception 'target invitation expired';
    end if;
    if target_membership.role = 'owner' and actor_role <> 'owner' then
        raise exception 'only owner can pair owner device';
    end if;

    select d.key_algorithm,d.invitation_request_id
      into target_key_algorithm,target_device_invitation_id
    from public.devices d
    where d.organization_id = pair_device.organization_id
      and d.id = pair_device.device_id
      and d.user_id = target_user_id
      and d.status = 'pending'
    for update;
    if not found then
        raise exception 'pending target device not found';
    end if;
    if envelope_key_version <> organization_key_version then
        raise exception 'envelope key version mismatch';
    end if;
    if envelope_algorithm <> target_key_algorithm then
        raise exception 'envelope algorithm mismatch';
    end if;
    if target_membership.status = 'invited'
       and target_device_invitation_id is distinct from
           target_membership.invitation_request_id then
        raise exception 'pending device invitation mismatch';
    end if;

    insert into public.key_envelopes(
        organization_id,device_id,key_version,key_algorithm,
        ephemeral_public_key,nonce,ciphertext
    ) values (
        organization_id,device_id,envelope_key_version,envelope_algorithm,
        decoded_ephemeral_public_key,decoded_envelope_nonce,
        decoded_envelope_ciphertext
    );

    update public.devices
       set status = 'active'
     where devices.organization_id = pair_device.organization_id
       and devices.id = pair_device.device_id
       and devices.user_id = target_user_id
       and devices.status = 'pending';

    if target_membership.status = 'invited' then
        update public.memberships
           set status = 'active',
               accepted_at = now()
         where memberships.organization_id =
                   pair_device.organization_id
           and memberships.user_id = target_user_id
           and memberships.status = 'invited';
    end if;
end;
$$;

create or replace function private.revoke_member(
    organization_id uuid,
    target_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    target_role text;
    target_status text;
    target_invitation_id uuid;
    locked_organization uuid;
    owner_count bigint;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select o.id into locked_organization
    from public.organizations o
    where o.id = revoke_member.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = revoke_member.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role not in ('owner','admin') then
        raise exception 'owner or admin required';
    end if;

    select m.role,m.status,m.invitation_request_id
      into target_role,target_status,target_invitation_id
    from public.memberships m
    where m.organization_id = revoke_member.organization_id
      and m.user_id = target_user_id
    for update;
    if not found
       or target_status not in ('active','invited') then
        return false;
    end if;

    if target_role = 'owner' and actor_role <> 'owner' then
        raise exception 'admin cannot revoke owner';
    end if;
    if target_role = 'owner' and target_status = 'active' then
        select count(*) into owner_count
        from public.memberships m
        where m.organization_id = revoke_member.organization_id
          and m.role = 'owner'
          and m.status = 'active';
        if owner_count <= 1 then
            raise exception 'cannot revoke the last owner';
        end if;
    end if;

    update public.memberships
       set status = 'revoked',
           revoked_at = now()
     where memberships.organization_id =
               revoke_member.organization_id
       and memberships.user_id = target_user_id
       and memberships.status in ('active','invited');

    update public.devices
       set status = 'revoked',
           revoked_at = now()
     where devices.organization_id =
               revoke_member.organization_id
       and devices.user_id = target_user_id
       and devices.status <> 'revoked';

    update private.member_invitation_requests r
       set status = 'cancelled',
           cancelled_at = now()
     where r.organization_id = revoke_member.organization_id
       and r.requested_by_audit_id = target_user_id
       and r.status = 'requested';

    if target_status = 'invited'
       and target_invitation_id is not null then
        update private.member_invitation_requests r
           set status = 'cancelled',
               cancelled_at = now()
         where r.organization_id = revoke_member.organization_id
           and r.id = target_invitation_id
           and r.status = 'finalized';
    end if;

    return true;
end;
$$;

create or replace function public.begin_member_invitation(
    p_organization_id uuid,
    p_email_sha256 text,
    p_role text
)
returns uuid
language sql
security invoker
set search_path = ''
as $$
    select private.begin_member_invitation(
        p_organization_id,p_email_sha256,p_role
    );
$$;

create or replace function public.accept_member_invitation()
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.accept_member_invitation();
$$;

create or replace function public.cancel_member_invitation(
    p_invitation_id uuid
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.cancel_member_invitation(p_invitation_id);
$$;

create or replace function public.list_member_invitations(
    p_organization_id uuid
)
returns table (
    invitation_id uuid,
    invitation_role text,
    invitation_status text,
    expires_at timestamptz,
    created_at timestamptz,
    finalized_at timestamptz,
    cancelled_at timestamptz
)
language sql
stable
security invoker
set search_path = ''
as $$
    select * from private.list_member_invitations(p_organization_id);
$$;

create or replace function public.revoke_member(
    organization_id uuid,
    target_user_id uuid
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.revoke_member(organization_id,target_user_id);
$$;

drop policy if exists organizations_select on public.organizations;
create policy organizations_select on public.organizations
for select to authenticated using (
    private.is_org_member(organizations.id)
    or exists (
        select 1
        from public.memberships own_membership
        where own_membership.organization_id = organizations.id
          and own_membership.user_id = (select auth.uid())
          and own_membership.status = 'invited'
          and own_membership.invite_expires_at > now()
    )
);

drop policy if exists memberships_select on public.memberships;
create policy memberships_select on public.memberships
for select to authenticated using (
    private.is_org_admin(memberships.organization_id)
    or (
        memberships.user_id = (select auth.uid())
        and (
            memberships.status = 'active'
            or (
                memberships.status = 'invited'
                and memberships.invite_expires_at > now()
            )
        )
    )
);

drop policy if exists devices_select on public.devices;
create policy devices_select on public.devices
for select to authenticated using (
    private.can_read_device(devices.organization_id,devices.user_id)
);

revoke all on function private.can_read_device(uuid,uuid)
    from public, anon, authenticated;
revoke all on function private.begin_member_invitation(uuid,text,text)
    from public, anon, authenticated;
revoke all on function private.accept_member_invitation()
    from public, anon, authenticated;
revoke all on function private.cancel_member_invitation(uuid)
    from public, anon, authenticated;
revoke all on function private.list_member_invitations(uuid)
    from public, anon, authenticated;
revoke all on function private.register_device(
    uuid,uuid,text,text,text,text
) from public, anon, authenticated;
revoke all on function private.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) from public, anon, authenticated;
revoke all on function private.revoke_member(uuid,uuid)
    from public, anon, authenticated;

grant usage on schema private to authenticated;
grant execute on function private.can_read_device(uuid,uuid)
    to authenticated;
grant execute on function private.begin_member_invitation(uuid,text,text)
    to authenticated;
grant execute on function private.accept_member_invitation()
    to authenticated;
grant execute on function private.cancel_member_invitation(uuid)
    to authenticated;
grant execute on function private.list_member_invitations(uuid)
    to authenticated;
grant execute on function private.register_device(
    uuid,uuid,text,text,text,text
) to authenticated;
grant execute on function private.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) to authenticated;
grant execute on function private.revoke_member(uuid,uuid)
    to authenticated;

revoke all on function public.begin_member_invitation(uuid,text,text)
    from public, anon, authenticated;
revoke all on function public.accept_member_invitation()
    from public, anon, authenticated;
revoke all on function public.cancel_member_invitation(uuid)
    from public, anon, authenticated;
revoke all on function public.list_member_invitations(uuid)
    from public, anon, authenticated;
revoke all on function public.revoke_member(uuid,uuid)
    from public, anon, authenticated;

grant execute on function public.begin_member_invitation(uuid,text,text)
    to authenticated;
grant execute on function public.accept_member_invitation()
    to authenticated;
grant execute on function public.cancel_member_invitation(uuid)
    to authenticated;
grant execute on function public.list_member_invitations(uuid)
    to authenticated;
grant execute on function public.revoke_member(uuid,uuid)
    to authenticated;

commit;
