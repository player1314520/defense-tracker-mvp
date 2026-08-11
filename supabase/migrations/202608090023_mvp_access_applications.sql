-- Store public-beta applications as keyed digests plus AES-GCM ciphertext.
-- Review is restricted to one active-device Owner/Admin organization.
begin;

create table if not exists private.access_applications (
    id uuid primary key default gen_random_uuid(),
    email_hmac text not null
        check (email_hmac ~ '^[0-9a-f]{64}$'),
    email_ciphertext bytea not null check (
        octet_length(email_ciphertext) between 17 and 512
    ),
    email_nonce bytea not null check (octet_length(email_nonce) = 12),
    email_key_version integer not null check (
        email_key_version between 1 and 100
    ),
    terms_version text not null check (
        length(terms_version) between 1 and 64
        and terms_version ~ '^[A-Za-z0-9._-]+$'
    ),
    status text not null default 'pending' check (
        status in ('pending','approved','rejected','invited','cancelled')
    ),
    organization_id uuid references public.organizations(id)
        on delete set null,
    requested_role text check (
        requested_role is null
        or requested_role in (
            'owner','admin','collector','analyst','editor','approver'
        )
    ),
    invitation_request_id uuid unique
        references private.member_invitation_requests(id)
        on delete set null,
    reviewed_by uuid references auth.users(id) on delete set null,
    reviewed_by_audit_id uuid,
    decision_reason_code text check (
        decision_reason_code is null
        or decision_reason_code ~ '^[a-z0-9_]{1,64}$'
    ),
    last_ip_hmac text not null check (
        last_ip_hmac ~ '^[0-9a-f]{64}$'
    ),
    last_user_agent_hmac text not null check (
        last_user_agent_hmac ~ '^[0-9a-f]{64}$'
    ),
    submission_count integer not null default 1 check (
        submission_count between 1 and 100
    ),
    created_at timestamptz not null default statement_timestamp(),
    last_submitted_at timestamptz not null default statement_timestamp(),
    updated_at timestamptz not null default statement_timestamp(),
    reviewed_at timestamptz,
    invited_at timestamptz,
    unique (email_hmac),
    check (
        (status = 'pending' and reviewed_at is null)
        or (
            status in ('approved','rejected','invited','cancelled')
            and reviewed_at is not null
        )
    )
);

create index if not exists access_applications_review_queue_idx
    on private.access_applications(status,created_at,id);
create index if not exists access_applications_org_idx
    on private.access_applications(organization_id,status,created_at,id);

create table if not exists private.access_application_audit (
    id bigint generated always as identity primary key,
    application_id uuid not null
        references private.access_applications(id) on delete cascade,
    organization_id uuid references public.organizations(id)
        on delete set null,
    actor_user_id uuid references auth.users(id) on delete set null,
    actor_audit_id uuid,
    event_type text not null check (event_type in (
        'submitted','resubmitted','approved','rejected',
        'invitation_dispatched','invitation_retryable',
        'invitation_cancelled'
    )),
    previous_status text,
    next_status text not null,
    reason_code text,
    occurred_at timestamptz not null default statement_timestamp()
);

create index if not exists access_application_audit_app_idx
    on private.access_application_audit(application_id,id);

create table if not exists private.access_application_rate_buckets (
    scope text not null check (
        scope in ('global_hour','ip_hour','email_day')
    ),
    subject_hmac text not null check (
        subject_hmac ~ '^[0-9a-f]{64}$'
    ),
    window_start timestamptz not null,
    request_count integer not null check (request_count between 1 and 1000),
    updated_at timestamptz not null default statement_timestamp(),
    primary key (scope,subject_hmac,window_start)
);
create index if not exists access_application_rate_updated_idx
    on private.access_application_rate_buckets(updated_at);

revoke all on table private.access_applications
    from public, anon, authenticated, service_role;
revoke all on table private.access_application_audit
    from public, anon, authenticated, service_role;
revoke all on table private.access_application_rate_buckets
    from public, anon, authenticated, service_role;

drop function if exists private.consume_access_application_rate(text,text);

create or replace function private.consume_access_application_rates(
    p_ip_hmac text,
    p_email_hmac text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    observed_at timestamptz := statement_timestamp();
    hour_start timestamptz := date_trunc('hour',statement_timestamp());
    day_start timestamptz := date_trunc('day',statement_timestamp());
    global_count integer := 0;
    ip_count integer := 0;
    email_count integer := 0;
begin
    if p_ip_hmac !~ '^[0-9a-f]{64}$'
       or p_email_hmac !~ '^[0-9a-f]{64}$' then
        return false;
    end if;

    -- One transaction-scoped lock serializes the three-bucket decision. This
    -- prevents a rejected IP/email attempt from consuming the global bucket,
    -- while the single INSERT below makes the accepted increments atomic.
    perform pg_catalog.pg_advisory_xact_lock(90608,23001);

    select coalesce(max(b.request_count),0)
      into global_count
    from private.access_application_rate_buckets b
    where b.scope = 'global_hour'
      and b.subject_hmac = repeat('0',64)
      and b.window_start = hour_start;
    select coalesce(max(b.request_count),0)
      into ip_count
    from private.access_application_rate_buckets b
    where b.scope = 'ip_hour'
      and b.subject_hmac = p_ip_hmac
      and b.window_start = hour_start;
    select coalesce(max(b.request_count),0)
      into email_count
    from private.access_application_rate_buckets b
    where b.scope = 'email_day'
      and b.subject_hmac = p_email_hmac
      and b.window_start = day_start;

    if global_count >= 200
       or ip_count >= 20
       or email_count >= 3 then
        return false;
    end if;

    insert into private.access_application_rate_buckets as bucket(
        scope,subject_hmac,window_start,request_count
    ) values
        ('global_hour',repeat('0',64),hour_start,1),
        ('ip_hour',p_ip_hmac,hour_start,1),
        ('email_day',p_email_hmac,day_start,1)
    on conflict (scope,subject_hmac,window_start)
    do update set
        request_count = bucket.request_count + 1,
        updated_at = excluded.updated_at;

    delete from private.access_application_rate_buckets
    where updated_at < observed_at - interval '7 days';
    return true;
end;
$$;

create or replace function private.submit_access_application(
    p_email_hmac text,
    p_email_ciphertext text,
    p_email_nonce text,
    p_email_key_version integer,
    p_terms_version text,
    p_ip_hmac text,
    p_user_agent_hmac text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    decoded_ciphertext bytea;
    decoded_nonce bytea;
    application_id uuid;
    previous_count integer;
    current_status text;
begin
    if p_email_hmac !~ '^[0-9a-f]{64}$'
       or p_ip_hmac !~ '^[0-9a-f]{64}$'
       or p_user_agent_hmac !~ '^[0-9a-f]{64}$'
       or p_email_key_version not between 1 and 100
       or p_terms_version !~ '^[A-Za-z0-9._-]{1,64}$' then
        return jsonb_build_object('accepted',false);
    end if;
    begin
        decoded_ciphertext := private.decode_base64url(p_email_ciphertext);
        decoded_nonce := private.decode_base64url(p_email_nonce);
    exception when others then
        return jsonb_build_object('accepted',false);
    end;
    if octet_length(decoded_ciphertext) not between 17 and 512
       or octet_length(decoded_nonce) <> 12 then
        return jsonb_build_object('accepted',false);
    end if;
    if not private.consume_access_application_rates(p_ip_hmac,p_email_hmac) then
        return jsonb_build_object('accepted',false);
    end if;

    select a.submission_count into previous_count
    from private.access_applications a
    where a.email_hmac = p_email_hmac;

    insert into private.access_applications(
        email_hmac,email_ciphertext,email_nonce,email_key_version,
        terms_version,last_ip_hmac,last_user_agent_hmac
    ) values (
        p_email_hmac,decoded_ciphertext,decoded_nonce,p_email_key_version,
        p_terms_version,p_ip_hmac,p_user_agent_hmac
    )
    on conflict (email_hmac)
    do update set
        email_ciphertext = case
            when private.access_applications.status = 'pending'
            then excluded.email_ciphertext
            else private.access_applications.email_ciphertext
        end,
        email_nonce = case
            when private.access_applications.status = 'pending'
            then excluded.email_nonce
            else private.access_applications.email_nonce
        end,
        email_key_version = case
            when private.access_applications.status = 'pending'
            then excluded.email_key_version
            else private.access_applications.email_key_version
        end,
        terms_version = case
            when private.access_applications.status = 'pending'
            then excluded.terms_version
            else private.access_applications.terms_version
        end,
        last_ip_hmac = excluded.last_ip_hmac,
        last_user_agent_hmac = excluded.last_user_agent_hmac,
        submission_count = least(
            private.access_applications.submission_count + 1,100
        ),
        last_submitted_at = statement_timestamp(),
        updated_at = statement_timestamp()
    returning id,status into application_id,current_status;

    insert into private.access_application_audit(
        application_id,event_type,previous_status,next_status
    ) values (
        application_id,
        case when previous_count is null then 'submitted' else 'resubmitted' end,
        case when previous_count is null then null else current_status end,
        current_status
    );
    return jsonb_build_object('accepted',true,'application_id',application_id);
end;
$$;

create or replace function private.current_review_organization()
returns uuid
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    organizations uuid[];
begin
    select array_agg(candidate.organization_id order by candidate.organization_id)
      into organizations
    from (
        select m.organization_id
        from public.memberships m
        where m.user_id = (select auth.uid())
          and m.status = 'active'
          and m.role in ('owner','admin')
          and private.has_active_device_session(m.organization_id,null)
        order by m.organization_id
        limit 2
    ) candidate;
    if coalesce(cardinality(organizations),0) = 0 then
        raise exception 'owner or admin active device required'
            using errcode = '42501';
    end if;
    if cardinality(organizations) > 1 then
        raise exception 'more than one review organization'
            using errcode = '42501';
    end if;
    return organizations[1];
end;
$$;

create or replace function public.submit_access_application(
    p_email_hmac text,
    p_email_ciphertext text,
    p_email_nonce text,
    p_email_key_version integer,
    p_terms_version text,
    p_ip_hmac text,
    p_user_agent_hmac text
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.submit_access_application(
        p_email_hmac,p_email_ciphertext,p_email_nonce,
        p_email_key_version,p_terms_version,p_ip_hmac,
        p_user_agent_hmac
    );
$$;

create or replace function public.list_access_applications(
    p_status text default 'pending',
    p_cursor uuid default null,
    p_limit integer default 50
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    review_org uuid := private.current_review_organization();
    bounded_limit integer := least(greatest(coalesce(p_limit,50),1),100);
    cursor_created timestamptz;
    item record;
    items jsonb := '[]'::jsonb;
    last_id uuid;
begin
    if p_status not in (
        'pending','approved','rejected','invited','cancelled','all'
    ) then
        raise exception 'invalid application status';
    end if;
    if p_cursor is not null then
        select a.created_at into cursor_created
        from private.access_applications a
        where a.id = p_cursor;
        if cursor_created is null then
            raise exception 'invalid cursor';
        end if;
    end if;

    for item in
        select a.*
        from private.access_applications a
        where (
              p_status = 'all'
              or (
                  p_status = 'pending'
                  and a.status in ('pending','approved')
              )
              or (p_status <> 'pending' and a.status = p_status)
          )
          and (
              a.organization_id is null
              or a.organization_id = review_org
          )
          and (
              p_cursor is null
              or (a.created_at,a.id) < (cursor_created,p_cursor)
          )
        order by a.created_at desc,a.id desc
        limit bounded_limit
    loop
        items := items || jsonb_build_array(jsonb_build_object(
            'application_id',item.id,
            'email_ciphertext',private.encode_base64url(item.email_ciphertext),
            'email_nonce',private.encode_base64url(item.email_nonce),
            'email_key_version',item.email_key_version,
            'terms_version',item.terms_version,
            'status',item.status,
            'provisioning_status',case
                when item.status = 'approved' then 'retryable'
                else null
            end,
            'requested_role',item.requested_role,
            'created_at',item.created_at,
            'last_submitted_at',item.last_submitted_at,
            'submission_count',item.submission_count
        ));
        last_id := item.id;
    end loop;
    return jsonb_build_object(
        'items',items,
        'next_cursor',case
            when jsonb_array_length(items) = bounded_limit then last_id
            else null
        end
    );
end;
$$;

create or replace function public.get_access_application_for_review(
    p_application_id uuid
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    review_org uuid := private.current_review_organization();
    target private.access_applications%rowtype;
begin
    select a.* into target
    from private.access_applications a
    where a.id = p_application_id
      and (a.organization_id is null or a.organization_id = review_org);
    if not found then
        raise exception 'application not found';
    end if;
    return jsonb_build_object(
        'application_id',target.id,
        'email_ciphertext',private.encode_base64url(target.email_ciphertext),
        'email_nonce',private.encode_base64url(target.email_nonce),
        'email_key_version',target.email_key_version,
        'status',target.status
    );
end;
$$;

create or replace function public.decide_access_application(
    p_application_id uuid,
    p_decision text,
    p_role text default null,
    p_email_sha256 text default null,
    p_reason_code text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    review_org uuid := private.current_review_organization();
    actor uuid := (select auth.uid());
    target private.access_applications%rowtype;
    invitation_status text;
    invitation_provisioning_state text;
    invitation_id uuid;
    next_status text := p_decision;
begin
    if p_decision not in ('approved','rejected') then
        raise exception 'invalid application decision';
    end if;
    if p_reason_code is not null
       and p_reason_code !~ '^[a-z0-9_]{1,64}$' then
        raise exception 'invalid decision reason';
    end if;

    select a.* into target
    from private.access_applications a
    where a.id = p_application_id
      and (a.organization_id is null or a.organization_id = review_org)
    for update;
    if not found then
        raise exception 'application not found';
    end if;
    if p_decision = 'approved'
       and (
           p_role is null
           or p_role not in (
               'collector','analyst','editor','approver'
           )
           or p_email_sha256 is null
           or p_email_sha256 !~ '^[0-9a-f]{64}$'
       ) then
        raise exception 'approval metadata invalid';
    end if;
    -- A caller may replay an approval to restart a lost/retryable attempt.
    -- The stored invitation fixes the original role, so a replay can never
    -- change authorization semantics even if its UI role selection changed.
    if target.status = 'approved'
       and p_decision = 'approved'
       and target.organization_id = review_org
       and target.invitation_request_id is not null then
        select r.status,r.provisioning_state
          into invitation_status,invitation_provisioning_state
        from private.member_invitation_requests r
        where r.id = target.invitation_request_id
          and r.organization_id = review_org
        for update;
        if not found then
            raise exception 'application invitation state invalid';
        end if;
        if invitation_status = 'finalized'
           or invitation_provisioning_state = 'provisioned' then
            perform private.finish_access_application_invitation(
                target.id,target.invitation_request_id,'invited'
            );
            return jsonb_build_object(
                'application_id',target.id,
                'status','invited',
                'invitation_id',target.invitation_request_id,
                'requested_role',target.requested_role
            );
        end if;
        if invitation_status = 'cancelled'
           or invitation_provisioning_state = 'terminal_failed'
           or invitation_provisioning_state = 'compensating' then
            perform private.finish_access_application_invitation(
                target.id,target.invitation_request_id,'cancelled'
            );
            return jsonb_build_object(
                'application_id',target.id,
                'status','cancelled',
                'invitation_id',target.invitation_request_id,
                'requested_role',target.requested_role
            );
        end if;
        return jsonb_build_object(
            'application_id',target.id,
            'status','approved',
            'invitation_id',target.invitation_request_id,
            'requested_role',target.requested_role
        );
    end if;
    if target.status <> 'pending' then
        raise exception 'application already decided';
    end if;

    if p_decision = 'approved' then
        invitation_id := private.begin_member_invitation(
            review_org,p_email_sha256,p_role
        );
        if not exists (
            select 1
            from private.member_invitation_requests r
            where r.id = invitation_id
              and r.organization_id = review_org
        ) then
            -- The invitation implementation intentionally returns an opaque
            -- UUID when the identity already has active/invited membership.
            -- Do not persist that opaque UUID through the invitation FK.
            invitation_id := null;
            next_status := 'invited';
        end if;
    end if;

    update private.access_applications
       set status = next_status,
           organization_id = review_org,
           requested_role = case
               when p_decision = 'approved' then p_role
               else null
           end,
           invitation_request_id = invitation_id,
           reviewed_by = actor,
           reviewed_by_audit_id = actor,
           decision_reason_code = p_reason_code,
           reviewed_at = statement_timestamp(),
           invited_at = case
               when next_status = 'invited'
               then statement_timestamp()
               else invited_at
           end,
           updated_at = statement_timestamp()
     where id = target.id;
    insert into private.access_application_audit(
        application_id,organization_id,actor_user_id,actor_audit_id,
        event_type,previous_status,next_status,reason_code
    ) values (
        target.id,review_org,actor,actor,p_decision,
        target.status,next_status,p_reason_code
    );
    return jsonb_build_object(
        'application_id',target.id,
        'status',next_status,
        'invitation_id',invitation_id
    );
end;
$$;

create or replace function private.finish_access_application_invitation(
    p_application_id uuid,
    p_invitation_id uuid,
    p_outcome text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    target private.access_applications%rowtype;
begin
    if p_outcome not in ('invited','retryable','cancelled') then
        raise exception 'invalid access invitation outcome';
    end if;
    select a.* into target
    from private.access_applications a
    where a.id = p_application_id
    for update;
    if not found
       or target.status <> 'approved'
       or target.invitation_request_id is distinct from p_invitation_id then
        return false;
    end if;
    update private.access_applications
       set status = case
               when p_outcome = 'invited' then 'invited'
               when p_outcome = 'cancelled' then 'cancelled'
               else status
           end,
           invited_at = case
               when p_outcome = 'invited' then statement_timestamp()
               else invited_at
           end,
           updated_at = statement_timestamp()
     where id = target.id;
    insert into private.access_application_audit(
        application_id,organization_id,actor_audit_id,event_type,
        previous_status,next_status
    ) values (
        target.id,target.organization_id,target.reviewed_by_audit_id,
        case p_outcome
            when 'invited' then 'invitation_dispatched'
            when 'cancelled' then 'invitation_cancelled'
            else 'invitation_retryable'
        end,
        target.status,
        case
            when p_outcome = 'invited' then 'invited'
            when p_outcome = 'cancelled' then 'cancelled'
            else target.status
        end
    );
    return true;
end;
$$;

create or replace function public.finish_access_application_invitation(
    p_application_id uuid,
    p_invitation_id uuid,
    p_outcome text
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.finish_access_application_invitation(
        p_application_id,p_invitation_id,p_outcome
    );
$$;

revoke all on function private.consume_access_application_rates(text,text)
    from public, anon, authenticated, service_role;
revoke all on function private.submit_access_application(
    text,text,text,integer,text,text,text
) from public, anon, authenticated, service_role;
revoke all on function private.current_review_organization()
    from public, anon, authenticated, service_role;
revoke all on function private.finish_access_application_invitation(
    uuid,uuid,text
) from public, anon, authenticated, service_role;

revoke all on function public.submit_access_application(
    text,text,text,integer,text,text,text
) from public, anon, authenticated;
revoke all on function public.list_access_applications(text,uuid,integer)
    from public, anon, authenticated;
revoke all on function public.get_access_application_for_review(uuid)
    from public, anon, authenticated;
revoke all on function public.decide_access_application(
    uuid,text,text,text,text
) from public, anon, authenticated;
revoke all on function public.finish_access_application_invitation(
    uuid,uuid,text
) from public, anon, authenticated;

grant usage on schema private to service_role;
grant execute on function private.submit_access_application(
    text,text,text,integer,text,text,text
) to service_role;
grant execute on function private.finish_access_application_invitation(
    uuid,uuid,text
) to service_role;
grant execute on function public.submit_access_application(
    text,text,text,integer,text,text,text
) to service_role;
grant execute on function public.finish_access_application_invitation(
    uuid,uuid,text
) to service_role;

grant execute on function public.list_access_applications(text,uuid,integer)
    to authenticated;
grant execute on function public.get_access_application_for_review(uuid)
    to authenticated;
grant execute on function public.decide_access_application(
    uuid,text,text,text,text
) to authenticated;

comment on table private.access_applications is
    'MVP beta applications: keyed digest plus AES-GCM ciphertext only.';
comment on function public.list_access_applications(text,uuid,integer) is
    'Active-device Owner/Admin review queue; ciphertext is decrypted only in Edge.';

commit;
