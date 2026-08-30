# PostgreSQL isolationtester specification.  With the organization ledger at
# LIMIT - 89 bytes, two concurrent 89-byte reservations serialize on the
# primary-key upsert: one commits and one fails closed.
setup
{
  insert into auth.users(id,email) values
    ('00000000-0000-0000-0003-000000000001','quota-one@example.invalid'),
    ('00000000-0000-0000-0003-000000000002','quota-two@example.invalid');
  insert into public.organizations(
    id,name_ciphertext,name_nonce,created_by
  ) values (
    '12000000-0000-0000-0000-000000000001',
    decode(repeat('aa',17),'hex'),decode(repeat('bb',12),'hex'),
    '00000000-0000-0000-0003-000000000001'
  );
  insert into public.memberships(organization_id,user_id,role,status) values
    ('12000000-0000-0000-0000-000000000001','00000000-0000-0000-0003-000000000001','owner','active'),
    ('12000000-0000-0000-0000-000000000001','00000000-0000-0000-0003-000000000002','analyst','active');
  insert into public.devices(
    id,organization_id,user_id,key_algorithm,public_key,
    name_ciphertext,name_nonce,status,device_kind
  ) values
    ('22000000-0000-0000-0000-000000000001','12000000-0000-0000-0000-000000000001','00000000-0000-0000-0003-000000000001','p256',decode('04' || repeat('00',64),'hex'),decode(repeat('cc',17),'hex'),decode(repeat('dd',12),'hex'),'active','desktop'),
    ('22000000-0000-0000-0000-000000000002','12000000-0000-0000-0000-000000000001','00000000-0000-0000-0003-000000000002','p256',decode('04' || repeat('01',64),'hex'),decode(repeat('ce',17),'hex'),decode(repeat('de',12),'hex'),'active','desktop');
  insert into public.record_heads(
    organization_id,record_id,record_type
  ) values
    ('12000000-0000-0000-0000-000000000001','32000000-0000-0000-0000-000000000001','alert'),
    ('12000000-0000-0000-0000-000000000001','32000000-0000-0000-0000-000000000002','alert');
  insert into public.record_versions(
    organization_id,record_id,version_id,logical_version,record_type,
    device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,key_version,
    content_hash,deleted
  ) values
    ('12000000-0000-0000-0000-000000000001','32000000-0000-0000-0000-000000000001','42000000-0000-0000-0000-000000000001',1,'alert','22000000-0000-0000-0000-000000000001',decode(repeat('ee',17),'hex'),decode(repeat('11',12),'hex'),decode(repeat('22',48),'hex'),decode(repeat('33',12),'hex'),1,repeat('a',64),false),
    ('12000000-0000-0000-0000-000000000001','32000000-0000-0000-0000-000000000002','42000000-0000-0000-0000-000000000002',1,'alert','22000000-0000-0000-0000-000000000002',decode(repeat('ef',17),'hex'),decode(repeat('12',12),'hex'),decode(repeat('23',48),'hex'),decode(repeat('34',12),'hex'),1,repeat('b',64),false);
  insert into private.organization_sync_daily_usage(
    organization_id,usage_date,event_count,ciphertext_bytes
  ) select
    '12000000-0000-0000-0000-000000000001',
    candidate_day,
    1,536870912 - 89
  from generate_series(
    (statement_timestamp() at time zone 'UTC')::date - 1,
    (statement_timestamp() at time zone 'UTC')::date + 1,
    interval '1 day'
  ) as days(candidate_day);
}

teardown
{
  do $quota_isolation_assert$
  declare
    committed_events integer;
    saturated_days integer;
  begin
    select count(*) into committed_events
    from public.sync_events
    where organization_id = '12000000-0000-0000-0000-000000000001'
      and event_id in (
        '52000000-0000-0000-0000-000000000001',
        '52000000-0000-0000-0000-000000000002'
      );
    select count(*) into saturated_days
    from private.organization_sync_daily_usage
    where organization_id = '12000000-0000-0000-0000-000000000001'
      and ciphertext_bytes = 536870912
      and event_count = 2;
    if committed_events <> 1
       or saturated_days <> 1 then
      raise exception 'organization quota isolation invariant failed';
    end if;
  end;
  $quota_isolation_assert$;
  -- Immutable provenance FKs intentionally reject deleting a device or
  -- record version out from under history.  Test cleanup therefore follows
  -- an explicit leaf-to-root order without changing production delete rules.
  delete from public.sync_events
  where organization_id = '12000000-0000-0000-0000-000000000001';
  delete from public.record_heads
  where organization_id = '12000000-0000-0000-0000-000000000001';
  delete from public.memberships
  where organization_id = '12000000-0000-0000-0000-000000000001';
  delete from public.organizations
  where id = '12000000-0000-0000-0000-000000000001';
  delete from auth.users
  where id in (
    '00000000-0000-0000-0003-000000000001',
    '00000000-0000-0000-0003-000000000002'
  );
}

session s1
step s1_begin { begin; }
step s1_claim { set local request.jwt.claim.sub = '00000000-0000-0000-0003-000000000001'; }
step s1_reserve {
  insert into public.sync_events(
    event_id,organization_id,device_id,record_id,version_id,
    operation,applied,request_hash
  ) values (
    '52000000-0000-0000-0000-000000000001',
    '12000000-0000-0000-0000-000000000001',
    '22000000-0000-0000-0000-000000000001',
    '32000000-0000-0000-0000-000000000001',
    '42000000-0000-0000-0000-000000000001',
    'upsert',true,repeat('c',64)
  );
}
step s1_commit { commit; }

session s2
step s2_begin { begin; }
step s2_claim { set local request.jwt.claim.sub = '00000000-0000-0000-0003-000000000002'; }
step s2_reserve {
  insert into public.sync_events(
    event_id,organization_id,device_id,record_id,version_id,
    operation,applied,request_hash
  ) values (
    '52000000-0000-0000-0000-000000000002',
    '12000000-0000-0000-0000-000000000001',
    '22000000-0000-0000-0000-000000000002',
    '32000000-0000-0000-0000-000000000002',
    '42000000-0000-0000-0000-000000000002',
    'upsert',true,repeat('d',64)
  );
}
step s2_commit { commit; }

permutation s1_begin s1_claim s2_begin s2_claim s1_reserve s2_reserve s1_commit s2_commit
permutation s1_begin s1_claim s2_begin s2_claim s2_reserve s1_reserve s2_commit s1_commit
