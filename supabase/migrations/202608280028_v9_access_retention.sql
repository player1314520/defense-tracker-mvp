-- Bound public-access application data and expose one service-role-only purge
-- RPC.  Contact material is nullable only after an explicit purge marker.
begin;

alter table private.access_applications
    alter column email_hmac drop not null,
    alter column email_ciphertext drop not null,
    alter column email_nonce drop not null,
    alter column email_key_version drop not null,
    alter column last_ip_hmac drop not null,
    alter column last_user_agent_hmac drop not null,
    add column if not exists contact_purged_at timestamptz;

alter table private.access_applications
    add constraint access_applications_contact_lifecycle_check check (
        (
            contact_purged_at is null
            and email_hmac is not null
            and email_ciphertext is not null
            and email_nonce is not null
            and email_key_version is not null
            and last_ip_hmac is not null
            and last_user_agent_hmac is not null
        )
        or (
            contact_purged_at is not null
            and status <> 'pending'
            and email_hmac is null
            and email_ciphertext is null
            and email_nonce is null
            and email_key_version is null
            and last_ip_hmac is null
            and last_user_agent_hmac is null
            and invitation_request_id is null
        )
    );

alter table private.member_invitation_requests
    alter column email_sha256 drop not null,
    add column if not exists contact_purged_at timestamptz;

alter table private.member_invitation_requests
    add constraint member_invitation_contact_lifecycle_check check (
        (
            status = 'requested'
            and email_sha256 is not null
            and contact_purged_at is null
        )
        or (
            status in ('finalized','cancelled')
            and (
                (email_sha256 is not null and contact_purged_at is null)
                or (email_sha256 is null and contact_purged_at is not null)
            )
        )
    );

-- Retained decision/audit metadata is not a contact directory.  Exclude rows
-- whose contact material has been purged before applying the page limit so a
-- page can never fail because one historical row has NULL crypto fields.  The
-- cursor lookup intentionally accepts a row purged between page requests: its
-- immutable ordering tuple remains a valid boundary for the following page.
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
        where a.contact_purged_at is null
          and (
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

-- A direct decision request for a purged row also stops in SQL, before Edge
-- can attempt decryption.  Pending and retryable review behavior is unchanged.
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
      and a.contact_purged_at is null
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

comment on function public.list_access_applications(text,uuid,integer) is
    'Active-device Owner/Admin review queue; purged contacts are excluded before pagination.';
comment on function public.get_access_application_for_review(uuid) is
    'Active-device Owner/Admin review lookup; purged contacts are unavailable.';

create or replace function private.purge_access_application_data(
    p_now timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    expired_invitations integer := 0;
    expired_memberships integer := 0;
    stale_approvals integer := 0;
    pending_deleted integer := 0;
    contacts_purged integer := 0;
    invitation_contacts_purged integer := 0;
    audit_deleted integer := 0;
    applications_deleted integer := 0;
    rate_buckets_deleted integer := 0;
    invitation_audit_deleted integer := 0;
    event_usage_deleted integer := 0;
    provisioning_grace interval := interval '5 minutes';
    contact_retention_limit interval := interval '24 hours';
begin
    if p_now is null then
        raise exception 'purge timestamp is required';
    end if;

    -- Expired invitation records are terminal before their digest is removed.
    update private.member_invitation_requests r
       set status = 'cancelled',
           cancelled_at = coalesce(r.cancelled_at,p_now),
           -- Keep an in-flight fenced attempt identifiable so its completion
           -- path can compensate a just-created Auth user after this close.
           provisioning_state = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_state
               else 'terminal_failed'
           end,
           provisioning_attempt_id = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_attempt_id
               else null
           end,
           provisioning_lease_until = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_lease_until
               else null
           end
     where r.status = 'requested'
       and r.expires_at <= p_now;
    get diagnostics expired_invitations = row_count;

    update public.memberships m
       set status = 'revoked',
           revoked_at = coalesce(m.revoked_at,p_now)
     where m.status = 'invited'
       and m.invite_expires_at <= p_now;
    get diagnostics expired_memberships = row_count;

    -- Approval is a bounded hand-off, not an indefinite contact store.  Give
    -- the synchronous Edge -> Auth hand-off a small claim grace and respect a
    -- live, attempt-fenced provisioning lease.  Neither can cross the hard
    -- contact-retention deadline: at 24 hours the application is closed even
    -- if an invalid/stuck lease claims a later expiry.
    with stale as (
        update private.access_applications a
           set status = 'cancelled',
               decision_reason_code = coalesce(
                   a.decision_reason_code,'retention_window_elapsed'
               ),
               updated_at = p_now
         where a.status = 'approved'
           and a.reviewed_at <= p_now
           and (
               a.reviewed_at + contact_retention_limit <= p_now
               or (
                   a.reviewed_at + provisioning_grace <= p_now
                   and not exists (
                       select 1
                       from private.member_invitation_requests r
                       where r.id = a.invitation_request_id
                         and r.status = 'requested'
                         and r.provisioning_state = 'leased'
                         and r.provisioning_attempt_id is not null
                         and r.provisioning_lease_until > p_now
                   )
               )
           )
        returning
            a.id,a.organization_id,a.reviewed_by_audit_id,
            a.invitation_request_id
    ), closed_requests as (
        update private.member_invitation_requests r
           set status = 'cancelled',
               cancelled_at = coalesce(r.cancelled_at,p_now),
               -- Only the hard 24-hour branch can select an application with
               -- a live lease.  Preserve that attempt fence for compensation;
               -- every non-live request is terminal and cannot be reclaimed.
               provisioning_state = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_state
                   else 'terminal_failed'
               end,
               provisioning_attempt_id = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_attempt_id
                   else null
               end,
               provisioning_lease_until = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_lease_until
                   else null
               end
          from stale s
         where r.id = s.invitation_request_id
           and r.status = 'requested'
        returning r.id
    ), logged as (
        insert into private.access_application_audit(
            application_id,organization_id,actor_audit_id,event_type,
            previous_status,next_status,reason_code,occurred_at
        )
        select
            s.id,s.organization_id,s.reviewed_by_audit_id,
            'invitation_cancelled','approved','cancelled',
            'retention_window_elapsed',p_now
        from stale s
        returning 1
    )
    select count(*)::integer into stale_approvals
    from logged
    cross join lateral (
        select count(*) from closed_requests
    ) closed_request_count;

    delete from private.access_applications a
    where a.status = 'pending'
      and a.created_at <= p_now - interval '29 days';
    get diagnostics pending_deleted = row_count;

    update private.access_applications a
       set email_hmac = null,
           email_ciphertext = null,
           email_nonce = null,
           email_key_version = null,
           last_ip_hmac = null,
           last_user_agent_hmac = null,
           invitation_request_id = null,
           contact_purged_at = p_now,
           updated_at = p_now
     where a.status <> 'pending'
       -- A still-approved row is inside the bounded grace or has a live lease.
       -- The hard 24-hour branch above first closes it in this same transaction.
       and a.status <> 'approved'
       and a.reviewed_at <= p_now
       and a.contact_purged_at is null;
    get diagnostics contacts_purged = row_count;

    update private.member_invitation_requests r
       set email_sha256 = null,
           contact_purged_at = p_now
     where r.status in ('finalized','cancelled')
       and coalesce(r.finalized_at,r.cancelled_at,r.expires_at) <= p_now
       and r.contact_purged_at is null;
    get diagnostics invitation_contacts_purged = row_count;

    delete from private.access_application_audit a
    where a.occurred_at <= p_now - interval '179 days';
    get diagnostics audit_deleted = row_count;

    delete from private.invitation_provisioning_audit a
    where a.occurred_at <= p_now - interval '179 days';
    get diagnostics invitation_audit_deleted = row_count;

    delete from private.access_applications a
    where a.status <> 'pending'
      and coalesce(a.reviewed_at,a.updated_at,a.created_at)
          <= p_now - interval '179 days';
    get diagnostics applications_deleted = row_count;

    delete from private.access_application_rate_buckets b
    where (
        b.scope in ('global_hour','ip_hour')
        and b.window_start <= p_now - interval '2 hours'
    ) or (
        b.scope = 'email_day'
        and b.window_start <= p_now - interval '2 days'
    );
    get diagnostics rate_buckets_deleted = row_count;

    delete from private.sync_event_daily_usage u
    where u.usage_date < (p_now at time zone 'UTC')::date - 7;
    get diagnostics event_usage_deleted = row_count;

    return jsonb_build_object(
        'expired_invitations',expired_invitations,
        'expired_memberships',expired_memberships,
        'stale_approvals',stale_approvals,
        'pending_deleted',pending_deleted,
        'contacts_purged',contacts_purged,
        'invitation_contacts_purged',invitation_contacts_purged,
        'audit_deleted',audit_deleted,
        'invitation_audit_deleted',invitation_audit_deleted,
        'applications_deleted',applications_deleted,
        'rate_buckets_deleted',rate_buckets_deleted,
        'event_usage_deleted',event_usage_deleted
    );
end;
$$;

create or replace function public.purge_expired_access_application_data()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
    if (select auth.role()) is distinct from 'service_role' then
        raise exception 'service role required';
    end if;
    return private.purge_access_application_data(statement_timestamp());
end;
$$;

revoke all on function private.purge_access_application_data(timestamptz)
    from public, anon, authenticated, service_role;
revoke all on function public.purge_expired_access_application_data()
    from public, anon, authenticated;
grant execute on function public.purge_expired_access_application_data()
    to service_role;

comment on function public.purge_expired_access_application_data() is
    'Service-role-only bounded retention purge; returns aggregate counts only.';

commit;
