-- Add an attempt-fenced lease around the non-transactional Auth Admin invite
-- call.  No email address is returned by any database function or audit row.
begin;

alter table private.member_invitation_requests
    add column if not exists provisioning_state text not null
        default 'pending',
    add column if not exists provisioning_attempt_id uuid,
    add column if not exists provisioning_lease_until timestamptz,
    add column if not exists provisioning_attempt_count integer not null
        default 0,
    add column if not exists provisioning_last_attempt_at timestamptz,
    add column if not exists provisioning_last_result_code text,
    add column if not exists provisioned_at timestamptz;

do $constraints$
begin
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'member_invitation_provisioning_state_check'
          and conrelid = 'private.member_invitation_requests'::regclass
    ) then
        alter table private.member_invitation_requests
            add constraint member_invitation_provisioning_state_check
            check (provisioning_state in (
                'pending','leased','retryable','provisioned',
                'compensating','terminal_failed'
            ));
    end if;
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'member_invitation_provisioning_attempt_count_check'
          and conrelid = 'private.member_invitation_requests'::regclass
    ) then
        alter table private.member_invitation_requests
            add constraint member_invitation_provisioning_attempt_count_check
            check (provisioning_attempt_count between 0 and 5);
    end if;
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'member_invitation_provisioning_result_code_check'
          and conrelid = 'private.member_invitation_requests'::regclass
    ) then
        alter table private.member_invitation_requests
            add constraint member_invitation_provisioning_result_code_check
            check (
                provisioning_last_result_code is null
                or provisioning_last_result_code in (
                    'created','already_exists','timeout','rate_limited',
                    'provider_unavailable','invalid_identity','unexpected',
                    'compensated','compensation_failed','attempts_exhausted'
                )
            );
    end if;
end;
$constraints$;

create index if not exists member_invitation_provisioning_lease_idx
    on private.member_invitation_requests(
        provisioning_state,provisioning_lease_until,id
    ) where status = 'requested';

create table if not exists private.invitation_provisioning_audit (
    id bigint generated always as identity primary key,
    invitation_id uuid not null
        references private.member_invitation_requests(id) on delete cascade,
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    attempt_id uuid,
    event_type text not null check (event_type in (
        'claimed','busy','provisioned','retryable_failure',
        'terminal_failure','compensation_required',
        'compensated','compensation_failed'
    )),
    result_code text,
    occurred_at timestamptz not null default statement_timestamp()
);

create index if not exists invitation_provisioning_audit_request_idx
    on private.invitation_provisioning_audit(invitation_id,id desc);
revoke all on table private.invitation_provisioning_audit
    from public, anon, authenticated, service_role;

create or replace function private.claim_member_invitation_provisioning(
    p_invitation_id uuid,
    p_email_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_org uuid;
    target private.member_invitation_requests%rowtype;
    inviter_role text;
    attempt uuid;
begin
    if p_invitation_id is null
       or p_email_sha256 is null
       or p_email_sha256 <> pg_catalog.lower(p_email_sha256)
       or p_email_sha256 !~ '^[0-9a-f]{64}$' then
        return jsonb_build_object('action','cancelled');
    end if;

    select r.organization_id into target_org
    from private.member_invitation_requests r
    where r.id = p_invitation_id;
    if target_org is null then
        return jsonb_build_object('action','cancelled');
    end if;

    perform o.id from public.organizations o
    where o.id = target_org
    for update;
    if not found then
        return jsonb_build_object('action','cancelled');
    end if;

    select r.* into target
    from private.member_invitation_requests r
    where r.organization_id = target_org
      and r.id = p_invitation_id
    for update;
    if not found or target.email_sha256 <> p_email_sha256 then
        return jsonb_build_object('action','cancelled');
    end if;
    if target.status = 'finalized'
       or target.provisioning_state = 'provisioned' then
        return jsonb_build_object('action','provisioned');
    end if;
    if target.status <> 'requested'
       or target.expires_at <= statement_timestamp() then
        return jsonb_build_object('action','cancelled');
    end if;

    select m.role into inviter_role
    from public.memberships m
    where m.organization_id = target_org
      and m.user_id = target.requested_by
      and m.status = 'active';
    if inviter_role is null
       or inviter_role not in ('owner','admin')
       or (target.role = 'owner' and inviter_role <> 'owner') then
        update private.member_invitation_requests
           set status = 'cancelled',
               cancelled_at = statement_timestamp(),
               provisioning_state = 'terminal_failed',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = 'invalid_identity'
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,event_type,result_code
        ) values (
            target.id,target_org,'terminal_failure','invalid_identity'
        );
        return jsonb_build_object('action','cancelled');
    end if;

    if target.provisioning_state in ('compensating','terminal_failed') then
        return jsonb_build_object('action','cancelled');
    end if;
    if target.provisioning_state = 'leased'
       and target.provisioning_lease_until > statement_timestamp() then
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,attempt_id,event_type
        ) values (target.id,target_org,target.provisioning_attempt_id,'busy');
        return jsonb_build_object('action','busy');
    end if;
    if target.provisioning_attempt_count >= 5 then
        update private.member_invitation_requests
           set status = 'cancelled',
               cancelled_at = statement_timestamp(),
               provisioning_state = 'terminal_failed',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = 'attempts_exhausted'
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,event_type,result_code
        ) values (
            target.id,target_org,'terminal_failure','attempts_exhausted'
        );
        return jsonb_build_object('action','cancelled');
    end if;

    attempt := gen_random_uuid();
    update private.member_invitation_requests
       set provisioning_state = 'leased',
           provisioning_attempt_id = attempt,
           provisioning_lease_until =
               statement_timestamp() + interval '120 seconds',
           provisioning_attempt_count = provisioning_attempt_count + 1,
           provisioning_last_attempt_at = statement_timestamp(),
           provisioning_last_result_code = null
     where id = target.id;
    insert into private.invitation_provisioning_audit(
        invitation_id,organization_id,attempt_id,event_type
    ) values (target.id,target_org,attempt,'claimed');

    return jsonb_build_object(
        'action','provision',
        'attempt_id',attempt
    );
end;
$$;

create or replace function private.finish_member_invitation_provisioning(
    p_invitation_id uuid,
    p_attempt_id uuid,
    p_outcome text,
    p_result_code text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_org uuid;
    target private.member_invitation_requests%rowtype;
    inviter_role text;
begin
    if p_outcome not in (
        'provisioned','retryable_failure','deterministic_failure'
    ) then
        raise exception 'invalid provisioning outcome';
    end if;
    if (
        p_outcome = 'provisioned'
        and p_result_code not in ('created','already_exists')
    ) or (
        p_outcome = 'retryable_failure'
        and p_result_code not in (
            'timeout','rate_limited','provider_unavailable','unexpected'
        )
    ) or (
        p_outcome = 'deterministic_failure'
        and p_result_code <> 'invalid_identity'
    ) then
        raise exception 'invalid provisioning result code';
    end if;

    select r.organization_id into target_org
    from private.member_invitation_requests r
    where r.id = p_invitation_id;
    if target_org is null then
        return jsonb_build_object(
            'applied',false,'reason','invitation_closed',
            'compensate',p_result_code = 'created'
        );
    end if;
    perform o.id from public.organizations o
    where o.id = target_org
    for update;

    select r.* into target
    from private.member_invitation_requests r
    where r.id = p_invitation_id
    for update;
    if not found then
        return jsonb_build_object(
            'applied',false,'reason','invitation_closed',
            'compensate',p_result_code = 'created'
        );
    end if;
    if target.provisioning_state <> 'leased'
       or target.provisioning_attempt_id is distinct from p_attempt_id then
        return jsonb_build_object(
            'applied',false,'reason','stale_attempt','compensate',false
        );
    end if;

    -- Authentication may complete in the narrow interval between the Auth
    -- Admin call and this fenced completion. Never delete a user whose
    -- membership has already been finalized and activated.
    if target.status = 'finalized' then
        update private.member_invitation_requests
           set provisioning_state = 'provisioned',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = 'already_exists',
               provisioned_at = coalesce(
                   provisioned_at,statement_timestamp()
               )
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,attempt_id,event_type,result_code
        ) values (
            target.id,target_org,p_attempt_id,'provisioned','already_exists'
        );
        return jsonb_build_object(
            'applied',true,'compensate',false
        );
    end if;

    select m.role into inviter_role
    from public.memberships m
    where m.organization_id = target_org
      and m.user_id = target.requested_by
      and m.status = 'active';
    if target.status <> 'requested'
       or target.expires_at <= statement_timestamp()
       or inviter_role is null
       or inviter_role not in ('owner','admin')
       or (target.role = 'owner' and inviter_role <> 'owner') then
        if p_result_code = 'created' then
            update private.member_invitation_requests
               set status = case
                       when status = 'requested' then 'cancelled'
                       else status
                   end,
                   cancelled_at = case
                       when status = 'requested'
                       then statement_timestamp()
                       else cancelled_at
                   end,
                   provisioning_state = 'compensating',
                   provisioning_lease_until = null,
                   provisioning_last_result_code = 'created'
             where id = target.id;
            insert into private.invitation_provisioning_audit(
                invitation_id,organization_id,attempt_id,event_type,
                result_code
            ) values (
                target.id,target_org,p_attempt_id,
                'compensation_required','created'
            );
            return jsonb_build_object(
                'applied',false,'reason','invitation_closed',
                'compensate',true
            );
        end if;
        update private.member_invitation_requests
           set status = case
                   when status = 'requested' then 'cancelled'
                   else status
               end,
               cancelled_at = case
                   when status = 'requested'
                   then statement_timestamp()
                   else cancelled_at
               end,
               provisioning_state = 'terminal_failed',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = p_result_code
         where id = target.id;
        return jsonb_build_object(
            'applied',false,'reason','invitation_closed',
            'compensate',false
        );
    end if;

    if p_outcome = 'provisioned' then
        update private.member_invitation_requests
           set provisioning_state = 'provisioned',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = p_result_code,
               provisioned_at = statement_timestamp()
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,attempt_id,event_type,result_code
        ) values (
            target.id,target_org,p_attempt_id,'provisioned',p_result_code
        );
    elsif p_outcome = 'retryable_failure' then
        update private.member_invitation_requests
           set provisioning_state = 'retryable',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = p_result_code
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,attempt_id,event_type,result_code
        ) values (
            target.id,target_org,p_attempt_id,
            'retryable_failure',p_result_code
        );
    else
        update private.member_invitation_requests
           set status = 'cancelled',
               cancelled_at = statement_timestamp(),
               provisioning_state = 'terminal_failed',
               provisioning_attempt_id = null,
               provisioning_lease_until = null,
               provisioning_last_result_code = p_result_code
         where id = target.id;
        insert into private.invitation_provisioning_audit(
            invitation_id,organization_id,attempt_id,event_type,result_code
        ) values (
            target.id,target_org,p_attempt_id,
            'terminal_failure',p_result_code
        );
    end if;

    return jsonb_build_object(
        'applied',true,
        'compensate',false
    );
end;
$$;

create or replace function private.record_member_invitation_compensation(
    p_invitation_id uuid,
    p_attempt_id uuid,
    p_succeeded boolean
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    target private.member_invitation_requests%rowtype;
begin
    select r.* into target
    from private.member_invitation_requests r
    where r.id = p_invitation_id
    for update;
    if not found
       or target.provisioning_state <> 'compensating'
       or target.provisioning_attempt_id is distinct from p_attempt_id then
        return false;
    end if;

    update private.member_invitation_requests
       set provisioning_state = 'terminal_failed',
           provisioning_attempt_id = null,
           provisioning_lease_until = null,
           provisioning_last_result_code = case
               when p_succeeded then 'compensated'
               else 'compensation_failed'
           end
     where id = target.id;
    insert into private.invitation_provisioning_audit(
        invitation_id,organization_id,attempt_id,event_type,result_code
    ) values (
        target.id,target.organization_id,p_attempt_id,
        case when p_succeeded
            then 'compensated'
            else 'compensation_failed'
        end,
        case when p_succeeded
            then 'compensated'
            else 'compensation_failed'
        end
    );
    return true;
end;
$$;

create or replace function public.claim_member_invitation_provisioning(
    p_invitation_id uuid,
    p_email_sha256 text
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.claim_member_invitation_provisioning(
        p_invitation_id,p_email_sha256
    );
$$;

create or replace function public.finish_member_invitation_provisioning(
    p_invitation_id uuid,
    p_attempt_id uuid,
    p_outcome text,
    p_result_code text
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.finish_member_invitation_provisioning(
        p_invitation_id,p_attempt_id,p_outcome,p_result_code
    );
$$;

create or replace function public.record_member_invitation_compensation(
    p_invitation_id uuid,
    p_attempt_id uuid,
    p_succeeded boolean
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.record_member_invitation_compensation(
        p_invitation_id,p_attempt_id,p_succeeded
    );
$$;

revoke all on function private.claim_member_invitation_provisioning(uuid,text)
    from public, anon, authenticated, service_role;
revoke all on function private.finish_member_invitation_provisioning(
    uuid,uuid,text,text
) from public, anon, authenticated, service_role;
revoke all on function private.record_member_invitation_compensation(
    uuid,uuid,boolean
) from public, anon, authenticated, service_role;
revoke all on function public.claim_member_invitation_provisioning(uuid,text)
    from public, anon, authenticated;
revoke all on function public.finish_member_invitation_provisioning(
    uuid,uuid,text,text
) from public, anon, authenticated;
revoke all on function public.record_member_invitation_compensation(
    uuid,uuid,boolean
) from public, anon, authenticated;

grant usage on schema private to service_role;
grant execute on function private.claim_member_invitation_provisioning(
    uuid,text
) to service_role;
grant execute on function private.finish_member_invitation_provisioning(
    uuid,uuid,text,text
) to service_role;
grant execute on function private.record_member_invitation_compensation(
    uuid,uuid,boolean
) to service_role;
grant execute on function public.claim_member_invitation_provisioning(
    uuid,text
) to service_role;
grant execute on function public.finish_member_invitation_provisioning(
    uuid,uuid,text,text
) to service_role;
grant execute on function public.record_member_invitation_compensation(
    uuid,uuid,boolean
) to service_role;

comment on function public.claim_member_invitation_provisioning(uuid,text) is
    'Service-only fencing lease; result never contains an email digest.';
comment on function public.finish_member_invitation_provisioning(
    uuid,uuid,text,text
) is 'Attempt-bound completion with cancellation compensation signal.';

commit;
