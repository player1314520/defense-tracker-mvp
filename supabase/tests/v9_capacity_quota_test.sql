begin;

create extension if not exists pgtap with schema extensions;
set local search_path = public, extensions;
select plan(11);

insert into auth.users(id,email)
values (
    '00000000-0000-0000-0001-000000000001'::uuid,
    'capacity-owner@example.invalid'
);

insert into public.organizations(
    id,name_ciphertext,name_nonce,created_by
) values (
    '10000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('aa',17),'hex'),
    decode(repeat('bb',12),'hex'),
    '00000000-0000-0000-0001-000000000001'::uuid
);

insert into auth.users(id,email)
select
    format(
        '00000000-0000-0000-0001-%s',
        lpad(i::text,12,'0')
    )::uuid,
    format('capacity-%s@example.invalid',i)
from generate_series(2,101) as series(i);

insert into public.memberships(organization_id,user_id,role,status)
select
    '10000000-0000-0000-0000-000000000001'::uuid,
    format(
        '00000000-0000-0000-0001-%s',
        lpad(i::text,12,'0')
    )::uuid,
    case when i = 1 then 'owner' else 'analyst' end,
    'active'
from generate_series(1,100) as series(i);

select is(
    (
        select count(*)
        from public.memberships
        where organization_id = '10000000-0000-0000-0000-000000000001'::uuid
          and status = 'active'
    ),
    100::bigint,
    'exactly 100 active members are accepted'
);

select is(
    (
        select used_seats
        from private.organization_seat_usage
        where organization_id = '10000000-0000-0000-0000-000000000001'::uuid
    ),
    100,
    'the seat ledger records all 100 active members'
);

select throws_ok(
    $$
        insert into public.memberships(
            organization_id,user_id,role,status
        ) values (
            '10000000-0000-0000-0000-000000000001'::uuid,
            '00000000-0000-0000-0001-000000000101'::uuid,
            'analyst','active'
        )
    $$,
    'P0001',
    'organization active and reserved seat limit exceeded',
    'the 101st active member is rejected atomically'
);

select is(
    (
        select count(*)
        from public.memberships
        where organization_id = '10000000-0000-0000-0000-000000000001'::uuid
          and status = 'active'
    ),
    100::bigint,
    'the rejected member is not persisted'
);

-- Reuse the same single-organization fixture for event quota checks.
delete from public.memberships
where organization_id = '10000000-0000-0000-0000-000000000001'::uuid;

insert into public.memberships(organization_id,user_id,role,status)
values (
    '10000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0001-000000000001'::uuid,
    'owner','active'
);

select is(
    (
        select used_seats
        from private.organization_seat_usage
        where organization_id = '10000000-0000-0000-0000-000000000001'::uuid
    ),
    1,
    'seat ledger releases deleted memberships before quota fixture reuse'
);

insert into public.devices(
    id,organization_id,user_id,key_algorithm,public_key,
    name_ciphertext,name_nonce,status,device_kind
) values (
    '20000000-0000-0000-0000-000000000001'::uuid,
    '10000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0001-000000000001'::uuid,
    'p256',decode('04' || repeat('00',64),'hex'),
    decode(repeat('cc',17),'hex'),decode(repeat('dd',12),'hex'),
    'active','desktop'
);

insert into public.record_heads(
    organization_id,record_id,record_type
) values (
    '10000000-0000-0000-0000-000000000001'::uuid,
    '30000000-0000-0000-0000-000000000001'::uuid,
    'source'
);

insert into public.record_versions(
    organization_id,record_id,version_id,logical_version,record_type,
    device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,key_version,
    content_hash
) values (
    '10000000-0000-0000-0000-000000000001'::uuid,
    '30000000-0000-0000-0000-000000000001'::uuid,
    '40000000-0000-0000-0000-000000000001'::uuid,
    1,'source','20000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('ee',17),'hex'),decode(repeat('11',12),'hex'),
    decode(repeat('22',48),'hex'),decode(repeat('33',12),'hex'),1,
    repeat('a',64)
);

set local request.jwt.claim.sub =
    '00000000-0000-0000-0001-000000000001';

insert into public.sync_events(
    event_id,organization_id,device_id,record_id,version_id,operation,applied
)
select
    format(
        '50000000-0000-0000-0000-%s',
        lpad(i::text,12,'0')
    )::uuid,
    '10000000-0000-0000-0000-000000000001'::uuid,
    '20000000-0000-0000-0000-000000000001'::uuid,
    '30000000-0000-0000-0000-000000000001'::uuid,
    '40000000-0000-0000-0000-000000000001'::uuid,
    'upsert',true
from generate_series(1,1000) as series(i);

select is(
    (
        select event_count
        from private.sync_event_daily_usage
        where user_id = '00000000-0000-0000-0001-000000000001'::uuid
          and usage_date = (statement_timestamp() at time zone 'UTC')::date
    ),
    1000,
    'the daily counter reaches exactly 1000'
);

select throws_ok(
    $$
        insert into public.sync_events(
            event_id,organization_id,device_id,record_id,version_id,
            operation,applied
        ) values (
            '50000000-0000-0000-0000-000000001001'::uuid,
            '10000000-0000-0000-0000-000000000001'::uuid,
            '20000000-0000-0000-0000-000000000001'::uuid,
            '30000000-0000-0000-0000-000000000001'::uuid,
            '40000000-0000-0000-0000-000000000001'::uuid,
            'upsert',true
        )
    $$,
    'P0001',
    'daily sync event limit exceeded',
    'the 1001st new event is rejected atomically'
);

select lives_ok(
    $$
        insert into public.sync_events(
            event_id,organization_id,device_id,record_id,version_id,
            operation,applied
        ) values (
            '50000000-0000-0000-0000-000000000001'::uuid,
            '10000000-0000-0000-0000-000000000001'::uuid,
            '20000000-0000-0000-0000-000000000001'::uuid,
            '30000000-0000-0000-0000-000000000001'::uuid,
            '40000000-0000-0000-0000-000000000001'::uuid,
            'upsert',true
        ) on conflict (event_id) do nothing
    $$,
    'a duplicate event ID remains idempotent at the hard limit'
);

select is(
    (
        select event_count
        from private.sync_event_daily_usage
        where user_id = '00000000-0000-0000-0001-000000000001'::uuid
          and usage_date = (statement_timestamp() at time zone 'UTC')::date
    ),
    1000,
    'the duplicate event does not increment daily usage'
);

select is(
    (
        select count(*)
        from public.sync_events
        where organization_id = '10000000-0000-0000-0000-000000000001'::uuid
    ),
    1000::bigint,
    'only 1000 distinct sync events are stored'
);

select is(
    (
        select count(*)
        from public.sync_events
        where event_id = '50000000-0000-0000-0000-000000001001'::uuid
    ),
    0::bigint,
    'the rejected 1001st event is not persisted'
);

select * from finish();
rollback;
