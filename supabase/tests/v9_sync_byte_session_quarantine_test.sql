begin;

create extension if not exists pgtap with schema extensions;
set local search_path = public, extensions;
select plan(28);

insert into auth.users(id,email)
values (
    '00000000-0000-0000-0002-000000000001'::uuid,
    'sync-budget-owner@example.invalid'
);

insert into public.organizations(
    id,name_ciphertext,name_nonce,created_by
) values (
    '11000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('aa',17),'hex'),decode(repeat('bb',12),'hex'),
    '00000000-0000-0000-0002-000000000001'::uuid
);

insert into public.memberships(organization_id,user_id,role,status)
values (
    '11000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    'owner','active'
);

insert into public.devices(
    id,organization_id,user_id,key_algorithm,public_key,
    name_ciphertext,name_nonce,status,device_kind
) values (
    '21000000-0000-0000-0000-000000000001'::uuid,
    '11000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    'p256',decode('04' || repeat('00',64),'hex'),
    decode(repeat('cc',17),'hex'),decode(repeat('dd',12),'hex'),
    'active','browser'
);

insert into private.device_sessions(
    session_id,organization_id,device_id,user_id
) values (
    'portal-session-0000000000000001',
    '11000000-0000-0000-0000-000000000001'::uuid,
    '21000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid
);

insert into public.record_heads(
    organization_id,record_id,record_type
) values (
    '11000000-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000001'::uuid,
    'alert'
);

insert into public.record_versions(
    organization_id,record_id,version_id,base_version_id,logical_version,
    record_type,device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,
    key_version,content_hash,deleted
) values
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000001'::uuid,
    '41000000-0000-0000-0000-000000000001'::uuid,null,1,'alert',
    '21000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('ee',17),'hex'),decode(repeat('11',12),'hex'),
    decode(repeat('22',48),'hex'),decode(repeat('33',12),'hex'),1,
    repeat('a',64),false
),
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000001'::uuid,
    '41000000-0000-0000-0000-000000000002'::uuid,
    '41000000-0000-0000-0000-000000000001'::uuid,2,'alert',
    '21000000-0000-0000-0000-000000000001'::uuid,
    decode(repeat('ef',17),'hex'),decode(repeat('12',12),'hex'),
    decode(repeat('23',48),'hex'),decode(repeat('34',12),'hex'),1,
    repeat('b',64),false
);

update public.record_heads
set head_version_id = '41000000-0000-0000-0000-000000000001'::uuid,
    logical_version = 1
where organization_id = '11000000-0000-0000-0000-000000000001'::uuid
  and record_id = '31000000-0000-0000-0000-000000000001'::uuid;

set local request.jwt.claims =
    '{"sub":"00000000-0000-0000-0002-000000000001","role":"authenticated","session_id":"portal-session-0000000000000001"}';
set local request.jwt.claim.sub =
    '00000000-0000-0000-0002-000000000001';

insert into private.sync_event_daily_usage(
    user_id,usage_date,event_count,ciphertext_bytes
) values (
    '00000000-0000-0000-0002-000000000001'::uuid,
    (statement_timestamp() at time zone 'UTC')::date,
    1,67108864 - 89
);
insert into private.organization_sync_daily_usage(
    organization_id,usage_date,event_count,ciphertext_bytes
) values (
    '11000000-0000-0000-0000-000000000001'::uuid,
    (statement_timestamp() at time zone 'UTC')::date,
    1,1
);

select lives_ok(
    $$
        insert into public.sync_events(
            event_id,organization_id,device_id,record_id,version_id,
            operation,applied,request_hash
        ) values (
            '51000000-0000-0000-0000-000000000001'::uuid,
            '11000000-0000-0000-0000-000000000001'::uuid,
            '21000000-0000-0000-0000-000000000001'::uuid,
            '31000000-0000-0000-0000-000000000001'::uuid,
            '41000000-0000-0000-0000-000000000001'::uuid,
            'upsert',true,repeat('c',64)
        )
    $$,
    'user byte boundary accepts the last byte'
);

select is(
    (
        select ciphertext_bytes
        from private.sync_event_daily_usage
        where user_id = '00000000-0000-0000-0002-000000000001'::uuid
          and usage_date =
              (statement_timestamp() at time zone 'UTC')::date
    ),
    67108864::bigint,
    'decoded envelope bytes reach the exact user boundary'
);

select is(
    (
        select event_count
        from private.organization_sync_daily_usage
        where organization_id =
            '11000000-0000-0000-0000-000000000001'::uuid
    ),
    2,
    'one organization ledger row is updated atomically'
);

update private.sync_event_daily_usage
set ciphertext_bytes = 0
where user_id = '00000000-0000-0000-0002-000000000001'::uuid;
update private.organization_sync_daily_usage
set ciphertext_bytes = 536870912
where organization_id = '11000000-0000-0000-0000-000000000001'::uuid;

select throws_ok(
    $$
        insert into public.sync_events(
            event_id,organization_id,device_id,record_id,version_id,
            operation,applied,request_hash
        ) values (
            '51000000-0000-0000-0000-000000000002'::uuid,
            '11000000-0000-0000-0000-000000000001'::uuid,
            '21000000-0000-0000-0000-000000000001'::uuid,
            '31000000-0000-0000-0000-000000000001'::uuid,
            '41000000-0000-0000-0000-000000000002'::uuid,
            'upsert',true,repeat('d',64)
        )
    $$,
    'P0001',
    'daily organization sync byte limit exceeded',
    'organization byte rejection rolls back the user reservation'
);

select is(
    (
        select ciphertext_bytes
        from private.sync_event_daily_usage
        where user_id = '00000000-0000-0000-0002-000000000001'::uuid
    ),
    0::bigint,
    'failed organization reservation leaves user bytes unchanged'
);

select is(
    (
        select count(*)
        from private.sync_event_daily_usage
        where user_id = '00000000-0000-0000-0002-000000000001'::uuid
    ),
    1::bigint,
    'primary-key upserts serialize concurrent quota reservations'
);

update private.organization_sync_daily_usage
set ciphertext_bytes = 1
where organization_id = '11000000-0000-0000-0000-000000000001'::uuid;

select lives_ok(
    $$
        select public.report_sync_event_quarantine(
            '11000000-0000-0000-0000-000000000001'::uuid,
            (
                select cursor from public.sync_events
                where event_id =
                    '51000000-0000-0000-0000-000000000001'::uuid
            ),
            '51000000-0000-0000-0000-000000000001'::uuid,
            '31000000-0000-0000-0000-000000000001'::uuid,
            '41000000-0000-0000-0000-000000000001'::uuid,
            'invalid_json'
        )
    $$,
    'an active paired browser can report a metadata-only quarantine'
);

select is(
    (
        select count(*) from private.sync_event_quarantine_reports
        where organization_id =
            '11000000-0000-0000-0000-000000000001'::uuid
    ),
    1::bigint,
    'one quarantine report is auditable'
);

select is(
    (
        select count(*)
        from information_schema.columns
        where table_schema = 'private'
          and table_name = 'sync_event_quarantine_reports'
          and column_name = 'ciphertext'
    ),
    0::bigint,
    'quarantine report contains no ciphertext'
);

select is(
    (
        select logical_version
        from public.list_sync_quarantine_reports(
            '11000000-0000-0000-0000-000000000001'::uuid,
            50
        )
        limit 1
    ),
    1::bigint,
    'admin repair data includes the quarantined logical version'
);

select throws_ok(
    $$
        select public.admin_tombstone_quarantined_record(
            (select id from private.sync_event_quarantine_reports limit 1),
            jsonb_build_object(
                'event_id','51000000-0000-0000-0000-000000000003',
                'organization_id','11000000-0000-0000-0000-000000000001',
                'record_id','31000000-0000-0000-0000-000000000099',
                'operation','delete',
                'payload',jsonb_build_object(
                    'organization_id','11000000-0000-0000-0000-000000000001',
                    'record_id','31000000-0000-0000-0000-000000000099',
                    'record_type','alert',
                    'version',2,
                    'version_id','41000000-0000-0000-0000-000000000003',
                    'base_version_id','41000000-0000-0000-0000-000000000001',
                    'key_version',1,
                    'ciphertext',private.encode_base64url(
                        decode(repeat('44',17),'hex')
                    ),
                    'nonce',private.encode_base64url(
                        decode(repeat('55',12),'hex')
                    ),
                    'wrapped_data_key',private.encode_base64url(
                        decode(repeat('66',48),'hex')
                    ),
                    'wrap_nonce',private.encode_base64url(
                        decode(repeat('77',12),'hex')
                    ),
                    'content_hash',repeat('e',64),
                    'device_id','21000000-0000-0000-0000-000000000001',
                    'deleted',true
                )
            )
        )
    $$,
    'P0001',
    'quarantine tombstone event does not match report',
    'a tombstone cannot target a different record'
);

select is(
    (
        select head_version_id
        from public.record_heads
        where organization_id =
            '11000000-0000-0000-0000-000000000001'::uuid
          and record_id =
            '31000000-0000-0000-0000-000000000001'::uuid
    ),
    '41000000-0000-0000-0000-000000000001'::uuid,
    'rejected cross-record tombstone leaves the head unchanged'
);

select lives_ok(
    $$
        select public.admin_tombstone_quarantined_record(
            (select id from private.sync_event_quarantine_reports limit 1),
            jsonb_build_object(
                'event_id','51000000-0000-0000-0000-000000000004',
                'organization_id','11000000-0000-0000-0000-000000000001',
                'record_id','31000000-0000-0000-0000-000000000001',
                'operation','delete',
                'payload',jsonb_build_object(
                    'organization_id','11000000-0000-0000-0000-000000000001',
                    'record_id','31000000-0000-0000-0000-000000000001',
                    'record_type','alert',
                    'version',2,
                    'version_id','41000000-0000-0000-0000-000000000004',
                    'base_version_id','41000000-0000-0000-0000-000000000001',
                    'key_version',1,
                    'ciphertext',private.encode_base64url(
                        decode(repeat('44',17),'hex')
                    ),
                    'nonce',private.encode_base64url(
                        decode(repeat('55',12),'hex')
                    ),
                    'wrapped_data_key',private.encode_base64url(
                        decode(repeat('66',48),'hex')
                    ),
                    'wrap_nonce',private.encode_base64url(
                        decode(repeat('77',12),'hex')
                    ),
                    'content_hash',repeat('e',64),
                    'device_id','21000000-0000-0000-0000-000000000001',
                    'deleted',true
                )
            )
        )
    $$,
    'an administrator can commit a structurally valid client ciphertext tombstone'
);

select ok(
    (
        select deleted from public.record_heads
        where organization_id =
            '11000000-0000-0000-0000-000000000001'::uuid
          and record_id =
            '31000000-0000-0000-0000-000000000001'::uuid
    ),
    'the quarantine tombstone advances and deletes the record head'
);

select is(
    (public.revoke_current_device_session() ->> 'revoked')::boolean,
    true,
    'current device session is revoked without accepting an id argument'
);

select is(
    (
        select status from private.device_sessions
        where session_id = 'portal-session-0000000000000001'
    ),
    'revoked',
    'the bound current session is inactive immediately'
);

select is(
    (
        select count(*) from private.device_session_revocation_audit
        where user_id = '00000000-0000-0000-0002-000000000001'::uuid
    ),
    1::bigint,
    'session revocation audit stores one hashed session receipt'
);

create temp table retention_clock(p_now timestamptz not null);
insert into retention_clock values ('2026-08-30 12:00:00+00'::timestamptz);

insert into private.organization_sync_daily_usage(
    organization_id,usage_date,event_count,ciphertext_bytes
) values
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    '2026-08-22'::date,1,1
),
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    '2026-08-23'::date,1,1
);

insert into private.device_session_revocation_audit(
    session_sha256,organization_id,device_id,user_id,revoked_at
) values
(
    repeat('1',64),
    '11000000-0000-0000-0000-000000000001'::uuid,
    '21000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    '2026-03-03 12:00:00+00'::timestamptz
),
(
    repeat('2',64),
    '11000000-0000-0000-0000-000000000001'::uuid,
    '21000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0002-000000000001'::uuid,
    '2026-03-03 12:00:00.000001+00'::timestamptz
);

update private.sync_event_quarantine_reports
set resolved_at = '2026-03-03 12:00:00+00'::timestamptz
where failure_code = 'invalid_json';

insert into private.sync_event_quarantine_reports(
    organization_id,event_cursor,event_id,record_id,version_id,
    logical_version,record_type,reporter_user_id,reporter_device_id,
    failure_code,status,first_reported_at,last_reported_at,resolved_at,
    resolved_by
) values
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    (
        select cursor from public.sync_events
        where event_id = '51000000-0000-0000-0000-000000000001'::uuid
    ),
    '51000000-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000001'::uuid,
    '41000000-0000-0000-0000-000000000001'::uuid,
    1,'alert','00000000-0000-0000-0002-000000000001'::uuid,
    '21000000-0000-0000-0000-000000000001'::uuid,
    'integrity_failure','open',
    '2025-01-01 00:00:00+00'::timestamptz,
    '2025-01-01 00:00:00+00'::timestamptz,null,null
),
(
    '11000000-0000-0000-0000-000000000001'::uuid,
    (
        select cursor from public.sync_events
        where event_id = '51000000-0000-0000-0000-000000000001'::uuid
    ),
    '51000000-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000001'::uuid,
    '41000000-0000-0000-0000-000000000001'::uuid,
    1,'alert','00000000-0000-0000-0002-000000000001'::uuid,
    '21000000-0000-0000-0000-000000000001'::uuid,
    'decrypt_failure','repaired',
    '2026-03-03 12:00:00.000001+00'::timestamptz,
    '2026-03-03 12:00:00.000001+00'::timestamptz,
    '2026-03-03 12:00:00.000001+00'::timestamptz,
    '00000000-0000-0000-0002-000000000001'::uuid
);

create temp table retention_result as
select private.purge_access_application_data(p_now) as result
from retention_clock;

select ok(
    (
        select result ?& array[
            'expired_invitations','expired_memberships','stale_approvals',
            'pending_deleted','contacts_purged',
            'invitation_contacts_purged','audit_deleted',
            'invitation_audit_deleted','applications_deleted',
            'rate_buckets_deleted','event_usage_deleted'
        ] from retention_result
    ),
    'extended purge result preserves every existing aggregate field'
);

select is(
    (select (result ->> 'organization_sync_daily_usage_deleted')::integer
     from retention_result),
    1,
    'organization usage purge reports rows older than seven UTC days'
);
select is(
    (select count(*) from private.organization_sync_daily_usage
     where usage_date = '2026-08-22'::date),
    0::bigint,
    'organization usage older than seven UTC days is deleted'
);
select is(
    (select count(*) from private.organization_sync_daily_usage
     where usage_date = '2026-08-23'::date),
    1::bigint,
    'organization usage at the seven-day UTC boundary is retained'
);

select is(
    (select (result ->> 'device_session_revocation_audit_deleted')::integer
     from retention_result),
    1,
    'session audit purge reports the exact 180-day boundary deletion'
);
select is(
    (select count(*) from private.device_session_revocation_audit
     where session_sha256 = repeat('1',64)),
    0::bigint,
    'session audit at exactly 180 days is deleted'
);
select is(
    (select count(*) from private.device_session_revocation_audit
     where session_sha256 = repeat('2',64)),
    1::bigint,
    'session audit newer than 180 days is retained'
);

select is(
    (select (result ->> 'sync_event_quarantine_reports_deleted')::integer
     from retention_result),
    1,
    'quarantine purge reports only resolved rows at the 180-day boundary'
);
select is(
    (select count(*) from private.sync_event_quarantine_reports
     where failure_code = 'integrity_failure'),
    1::bigint,
    'an old open quarantine remains in the repair queue'
);
select is(
    (select count(*) from private.sync_event_quarantine_reports
     where failure_code = 'invalid_json'),
    0::bigint,
    'a resolved quarantine at exactly 180 days is deleted'
);
select is(
    (select count(*) from private.sync_event_quarantine_reports
     where failure_code = 'decrypt_failure'),
    1::bigint,
    'a resolved quarantine newer than 180 days is retained'
);

select * from finish();
rollback;
