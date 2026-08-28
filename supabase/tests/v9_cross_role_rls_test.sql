begin;

create extension if not exists pgtap with schema extensions;
set local search_path = public, extensions;
select plan(3);

insert into auth.users(id,email) values
(
    '00000000-0000-0000-0003-000000000001'::uuid,
    'rls-owner@example.invalid'
),
(
    '00000000-0000-0000-0003-000000000002'::uuid,
    'rls-analyst@example.invalid'
);

insert into public.organizations(
    id,name_ciphertext,name_nonce,created_by
) values (
    '90000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('aa',17),'hex'),decode(repeat('bb',12),'hex'),
    '00000000-0000-0000-0003-000000000001'::uuid
);

insert into public.memberships(organization_id,user_id,role,status) values
(
    '90000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0003-000000000001'::uuid,
    'owner','active'
),
(
    '90000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0003-000000000002'::uuid,
    'analyst','active'
);

insert into public.devices(
    id,organization_id,user_id,key_algorithm,public_key,
    name_ciphertext,name_nonce,status,device_kind
) values
(
    '91000000-0000-0000-0000-000000000001'::uuid,
    '90000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0003-000000000001'::uuid,
    'p256',decode('04' || repeat('00',64),'hex'),
    decode(repeat('cc',17),'hex'),decode(repeat('dd',12),'hex'),
    'active','desktop'
),
(
    '91000000-0000-0000-0000-000000000002'::uuid,
    '90000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0003-000000000002'::uuid,
    'p256',decode('04' || repeat('11',64),'hex'),
    decode(repeat('ee',17),'hex'),decode(repeat('ff',12),'hex'),
    'active','desktop'
);

insert into private.device_sessions(
    session_id,organization_id,device_id,user_id,status
) values
(
    'owner-session-00000001',
    '90000000-0000-0000-0000-000000000001'::uuid,
    '91000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0003-000000000001'::uuid,
    'active'
),
(
    'analyst-session-00001',
    '90000000-0000-0000-0000-000000000001'::uuid,
    '91000000-0000-0000-0000-000000000002'::uuid,
    '00000000-0000-0000-0003-000000000002'::uuid,
    'active'
);

set local role authenticated;
set local request.jwt.claim.sub =
    '00000000-0000-0000-0003-000000000001';
set local request.jwt.claims =
    '{"sub":"00000000-0000-0000-0003-000000000001","role":"authenticated","session_id":"owner-session-00000001"}';
select is(
    (
        select count(*)
        from public.devices
        where organization_id = '90000000-0000-0000-0000-000000000001'::uuid
    ),
    2::bigint,
    'an active-device owner can read organization device metadata'
);
reset role;

set local role authenticated;
set local request.jwt.claim.sub =
    '00000000-0000-0000-0003-000000000002';
set local request.jwt.claims =
    '{"sub":"00000000-0000-0000-0003-000000000002","role":"authenticated","session_id":"analyst-session-00001"}';
select is(
    (
        select count(*)
        from public.devices
        where organization_id = '90000000-0000-0000-0000-000000000001'::uuid
    ),
    1::bigint,
    'an analyst can read only their own device metadata'
);
reset role;

update private.device_sessions
set status = 'revoked',revoked_at = statement_timestamp()
where session_id = 'analyst-session-00001';

set local role authenticated;
set local request.jwt.claim.sub =
    '00000000-0000-0000-0003-000000000002';
set local request.jwt.claims =
    '{"sub":"00000000-0000-0000-0003-000000000002","role":"authenticated","session_id":"analyst-session-00001"}';
select is(
    (
        select count(*)
        from public.devices
        where organization_id = '90000000-0000-0000-0000-000000000001'::uuid
    ),
    0::bigint,
    'revoking the analyst session removes access to active device rows'
);
reset role;

select * from finish();
rollback;
