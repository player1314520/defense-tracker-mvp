begin;

create extension if not exists pgtap with schema extensions;
set local search_path = public, extensions;
select plan(15);

insert into auth.users(id,email)
values (
    '00000000-0000-0000-0002-000000000001'::uuid,
    'retention-owner@example.invalid'
);

insert into public.organizations(
    id,name_ciphertext,name_nonce,created_by
) values (
    '60000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('aa',17),'hex'),decode(repeat('bb',12),'hex'),
    '00000000-0000-0000-0002-000000000001'::uuid
);

insert into public.memberships(organization_id,user_id,role,status)
values (
    '60000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    'owner','active'
);

insert into private.member_invitation_requests(
    id,organization_id,email_sha256,role,status,requested_by,
    requested_by_audit_id,expires_at,provisioning_state,
    provisioning_attempt_id,provisioning_lease_until,
    provisioning_attempt_count,provisioning_last_attempt_at
) values (
    '70000000-0000-0000-0000-000000000001'::uuid,
    '60000000-0000-0000-0000-000000000001'::uuid,
    repeat('a',64),'analyst','requested',
    '00000000-0000-0000-0002-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    statement_timestamp() + interval '1 hour','leased',
    '71000000-0000-0000-0000-000000000001'::uuid,
    statement_timestamp() + interval '2 minutes',1,
    statement_timestamp()
);

insert into private.access_applications(
    id,email_hmac,email_ciphertext,email_nonce,email_key_version,
    terms_version,status,organization_id,requested_role,
    invitation_request_id,reviewed_by,reviewed_by_audit_id,
    decision_reason_code,last_ip_hmac,last_user_agent_hmac,
    reviewed_at
) values (
    '80000000-0000-0000-0000-000000000001'::uuid,
    repeat('b',64),decode(repeat('cc',17),'hex'),
    decode(repeat('dd',12),'hex'),1,'v9.0.0','approved',
    '60000000-0000-0000-0000-000000000001'::uuid,'analyst',
    '70000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    'approved',repeat('c',64),repeat('d',64),
    statement_timestamp() - interval '10 minutes'
);

select is(
    (
        private.claim_member_invitation_provisioning(
            '70000000-0000-0000-0000-000000000001'::uuid,
            repeat('a',64)
        )->>'action'
    ),
    'busy',
    'a live provisioning lease cannot be claimed twice'
);

update private.member_invitation_requests
set provisioning_lease_until = statement_timestamp() - interval '1 second'
where id = '70000000-0000-0000-0000-000000000001'::uuid;

select is(
    (
        private.claim_member_invitation_provisioning(
            '70000000-0000-0000-0000-000000000001'::uuid,
            repeat('a',64)
        )->>'action'
    ),
    'provision',
    'an expired lease can be reclaimed by a new fenced attempt'
);

select isnt(
    (
        select provisioning_attempt_id
        from private.member_invitation_requests
        where id = '70000000-0000-0000-0000-000000000001'::uuid
    ),
    '71000000-0000-0000-0000-000000000001'::uuid,
    'lease reclaim rotates the attempt identifier'
);

select ok(
    (
        select provisioning_lease_until > statement_timestamp()
        from private.member_invitation_requests
        where id = '70000000-0000-0000-0000-000000000001'::uuid
    ),
    'the reclaimed attempt receives a future lease deadline'
);

select is(
    (
        private.purge_access_application_data(statement_timestamp())
            ->>'stale_approvals'
    )::integer,
    0,
    'a live lease protects an approved application after the five-minute grace'
);

select is(
    (
        select status
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000001'::uuid
    ),
    'approved',
    'the lease-protected application remains approved'
);

select ok(
    (
        select contact_purged_at is null and email_ciphertext is not null
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000001'::uuid
    ),
    'contact ciphertext remains available only during the live hand-off lease'
);

update private.access_applications
set reviewed_at = statement_timestamp() - interval '24 hours'
where id = '80000000-0000-0000-0000-000000000001'::uuid;

select is(
    (
        private.purge_access_application_data(statement_timestamp())
            ->>'stale_approvals'
    )::integer,
    1,
    'the hard 24-hour boundary closes an application despite a live lease'
);

select is(
    (
        select status
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000001'::uuid
    ),
    'cancelled',
    'hard-retained approval is made terminal'
);

select ok(
    (
        select contact_purged_at is not null
           and email_hmac is null
           and email_ciphertext is null
           and invitation_request_id is null
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000001'::uuid
    ),
    'application contact material is purged at the hard deadline'
);

select ok(
    (
        select status = 'cancelled'
           and provisioning_state = 'leased'
           and provisioning_attempt_id is not null
        from private.member_invitation_requests
        where id = '70000000-0000-0000-0000-000000000001'::uuid
    ),
    'hard closure preserves the live attempt fence for compensation'
);

select ok(
    (
        select email_sha256 is null and contact_purged_at is not null
        from private.member_invitation_requests
        where id = '70000000-0000-0000-0000-000000000001'::uuid
    ),
    'terminal invitation contact digest is purged'
);

insert into private.access_applications(
    id,email_hmac,email_ciphertext,email_nonce,email_key_version,
    terms_version,status,last_ip_hmac,last_user_agent_hmac,created_at,
    last_submitted_at,updated_at
) values
(
    '80000000-0000-0000-0000-000000000002'::uuid,
    repeat('e',64),decode(repeat('11',17),'hex'),
    decode(repeat('22',12),'hex'),1,'v9.0.0','pending',
    repeat('f',64),repeat('1',64),
    statement_timestamp() - interval '29 days',
    statement_timestamp() - interval '29 days',
    statement_timestamp() - interval '29 days'
),
(
    '80000000-0000-0000-0000-000000000003'::uuid,
    repeat('2',64),decode(repeat('33',17),'hex'),
    decode(repeat('44',12),'hex'),1,'v9.0.0','pending',
    repeat('3',64),repeat('4',64),
    statement_timestamp() - interval '28 days 23 hours',
    statement_timestamp() - interval '28 days 23 hours',
    statement_timestamp() - interval '28 days 23 hours'
);

select is(
    (
        private.purge_access_application_data(statement_timestamp())
            ->>'pending_deleted'
    )::integer,
    1,
    'pending retention purge removes the row at the bounded cutoff'
);

select is(
    (
        select count(*)
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000002'::uuid
    ),
    0::bigint,
    'the expired pending application is deleted'
);

select is(
    (
        select count(*)
        from private.access_applications
        where id = '80000000-0000-0000-0000-000000000003'::uuid
    ),
    1::bigint,
    'a pending application just inside the cutoff is retained'
);

select * from finish();
rollback;
