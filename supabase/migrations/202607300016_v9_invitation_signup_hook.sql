-- Invite-only Auth user creation gate.
--
-- Applying this migration does not activate the hook. Staging must select
-- public.hook_v9_before_user_created in
-- Dashboard -> Authentication -> Hooks before opening create-user PKCE flows.
begin;

create index if not exists member_invitation_requests_auth_hook_idx
    on private.member_invitation_requests(email_sha256,expires_at,id)
    where status = 'requested';

create or replace function public.hook_v9_before_user_created(event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $hook$
declare
    denied constant jsonb := pg_catalog.jsonb_build_object(
        'error',
        pg_catalog.jsonb_build_object(
            'http_code', 403,
            'message', 'Registration is not permitted.'
        )
    );
    raw_email text;
    normalized_email text;
    normalized_email_sha256 text;
    provider text;
    providers jsonb;
    candidate record;
    locked_organization uuid;
    matched_invitation_id uuid;
begin
    if pg_catalog.jsonb_typeof(event) is distinct from 'object'
       or pg_catalog.jsonb_typeof(event #> '{user}') is distinct from 'object'
       or pg_catalog.jsonb_typeof(event #> '{user,email}')
            is distinct from 'string' then
        return denied;
    end if;

    provider := event #>> '{user,app_metadata,provider}';
    providers := event #> '{user,app_metadata,providers}';
    if provider is distinct from 'email'
       or providers is distinct from '["email"]'::jsonb then
        return denied;
    end if;

    raw_email := event #>> '{user,email}';
    normalized_email := pg_catalog.lower(pg_catalog.btrim(raw_email));
    if normalized_email is null
       or pg_catalog.length(normalized_email) < 3
       or pg_catalog.length(normalized_email) > 254
       or pg_catalog.length(
            pg_catalog.split_part(normalized_email, '@', 1)
       ) > 64
       or normalized_email !~ '^[a-z0-9!#$%&''*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&''*+/=?^_`{|}~-]+)*@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' then
        return denied;
    end if;

    normalized_email_sha256 := pg_catalog.encode(
        extensions.digest(
            pg_catalog.convert_to(normalized_email, 'UTF8'),
            'sha256'
        ),
        'hex'
    );

    -- Match the mutation lock order used by invitation/member RPCs:
    -- organization first, then invitation and inviter membership. This closes
    -- cancellation/revocation races without creating an inverted lock order.
    for candidate in
        select r.organization_id, r.id
        from private.member_invitation_requests r
        where r.email_sha256 = normalized_email_sha256
          and r.status = 'requested'
          and r.expires_at > pg_catalog.statement_timestamp()
        order by r.organization_id, r.id
    loop
        locked_organization := null;
        select o.id
          into locked_organization
          from public.organizations o
         where o.id = candidate.organization_id
         for share;
        if locked_organization is null then
            continue;
        end if;

        matched_invitation_id := null;
        select r.id
          into matched_invitation_id
          from private.member_invitation_requests r
          join public.memberships inviter
            on inviter.organization_id = r.organization_id
           and inviter.user_id = r.requested_by
           and inviter.status = 'active'
           and inviter.role in ('owner','admin')
         where r.organization_id = candidate.organization_id
           and r.id = candidate.id
           and r.email_sha256 = normalized_email_sha256
           and r.status = 'requested'
           and r.expires_at > pg_catalog.statement_timestamp()
           and (r.role <> 'owner' or inviter.role = 'owner')
         for share of r, inviter;
        if matched_invitation_id is not null then
            exit;
        end if;
    end loop;

    if matched_invitation_id is null then
        return denied;
    end if;

    return '{}'::jsonb;
end;
$hook$;

revoke all on function public.hook_v9_before_user_created(jsonb)
    from public, anon, authenticated, service_role;
grant execute on function public.hook_v9_before_user_created(jsonb)
    to supabase_auth_admin;

comment on function public.hook_v9_before_user_created(jsonb) is
    'Before User Created Auth Hook: permits only unexpired invite-only email signups.';

commit;
