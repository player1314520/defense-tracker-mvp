-- Enforce the V9 community limits in Postgres, not in the Portal UI.
-- Capacity reservations and event counters participate in the caller's
-- transaction, so a rejected operation cannot leave a consumed slot behind.
begin;

create table private.organization_seat_usage (
    organization_id uuid primary key
        references public.organizations(id) on delete cascade,
    used_seats integer not null default 0
        check (used_seats between 0 and 100),
    updated_at timestamptz not null default statement_timestamp()
);

create table private.organization_seat_reservations (
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    reservation_key text not null check (
        reservation_key ~ '^(member|invitation):[0-9a-f-]{36}$'
    ),
    reserved_until timestamptz,
    created_at timestamptz not null default statement_timestamp(),
    updated_at timestamptz not null default statement_timestamp(),
    primary key (organization_id,reservation_key)
);

create index organization_seat_reservations_expiry_idx
    on private.organization_seat_reservations(reserved_until)
    where reserved_until is not null;

revoke all on table private.organization_seat_usage
    from public, anon, authenticated, service_role;
revoke all on table private.organization_seat_reservations
    from public, anon, authenticated, service_role;

insert into private.organization_seat_usage(organization_id)
select o.id from public.organizations o
on conflict (organization_id) do nothing;

-- A membership created from an invitation retains that invitation's one seat;
-- it does not consume a second seat while the request is finalized.
insert into private.organization_seat_reservations(
    organization_id,reservation_key,reserved_until
)
select
    m.organization_id,
    case
        when m.invitation_request_id is not null
        then 'invitation:' || m.invitation_request_id::text
        else 'member:' || m.user_id::text
    end,
    case when m.status = 'invited' then m.invite_expires_at else null end
from public.memberships m
where m.status = 'active'
   or (m.status = 'invited' and m.invite_expires_at > statement_timestamp())
on conflict (organization_id,reservation_key) do nothing;

insert into private.organization_seat_reservations(
    organization_id,reservation_key,reserved_until
)
select
    r.organization_id,
    'invitation:' || r.id::text,
    r.expires_at
from private.member_invitation_requests r
where r.status = 'requested'
  and r.expires_at > statement_timestamp()
on conflict (organization_id,reservation_key) do nothing;

do $$
declare
    over_capacity uuid;
begin
    select r.organization_id into over_capacity
    from private.organization_seat_reservations r
    group by r.organization_id
    having count(*) > 100
    limit 1;
    if over_capacity is not null then
        raise exception 'existing organization exceeds the 100 seat limit';
    end if;
end;
$$;

update private.organization_seat_usage u
set used_seats = counted.used_seats,
    updated_at = statement_timestamp()
from (
    select r.organization_id,count(*)::integer as used_seats
    from private.organization_seat_reservations r
    group by r.organization_id
) counted
where u.organization_id = counted.organization_id;

create or replace function private.reserve_organization_seat(
    p_organization_id uuid,
    p_reservation_key text,
    p_reserved_until timestamptz
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    inserted_key text;
    expired_count integer := 0;
    resulting_count integer;
begin
    if p_organization_id is null
       or p_reservation_key is null
       or p_reservation_key !~ '^(member|invitation):[0-9a-f-]{36}$'
       or (
           p_reserved_until is not null
           and p_reserved_until <= statement_timestamp()
       ) then
        raise exception 'invalid organization seat reservation';
    end if;

    insert into private.organization_seat_usage(organization_id)
    values (p_organization_id)
    on conflict (organization_id) do nothing;

    -- This row is the per-organization serialization point.  Every trigger
    -- below acquires it before changing the reservation ledger.
    perform u.organization_id
    from private.organization_seat_usage u
    where u.organization_id = p_organization_id
    for update;
    if not found then
        raise exception 'organization capacity state is unavailable';
    end if;

    with expired as (
        delete from private.organization_seat_reservations r
        where r.organization_id = p_organization_id
          and r.reserved_until is not null
          and r.reserved_until <= statement_timestamp()
        returning 1
    )
    select count(*)::integer into expired_count from expired;
    if expired_count > 0 then
        update private.organization_seat_usage u
        set used_seats = greatest(0,u.used_seats - expired_count),
            updated_at = statement_timestamp()
        where u.organization_id = p_organization_id;
    end if;

    insert into private.organization_seat_reservations(
        organization_id,reservation_key,reserved_until
    ) values (
        p_organization_id,p_reservation_key,p_reserved_until
    )
    on conflict (organization_id,reservation_key) do nothing
    returning reservation_key into inserted_key;

    if inserted_key is not null then
        update private.organization_seat_usage u
        set used_seats = u.used_seats + 1,
            updated_at = statement_timestamp()
        where u.organization_id = p_organization_id
          and u.used_seats < 100
        returning u.used_seats into resulting_count;
        if resulting_count is null then
            raise exception 'organization active and reserved seat limit exceeded';
        end if;
    else
        -- A membership makes its invitation reservation indefinite.  A
        -- request may refresh only an already-expiring reservation.
        update private.organization_seat_reservations r
        set reserved_until = case
                when p_reserved_until is null then null
                when r.reserved_until is null then null
                else p_reserved_until
            end,
            updated_at = statement_timestamp()
        where r.organization_id = p_organization_id
          and r.reservation_key = p_reservation_key;
    end if;
end;
$$;

create or replace function private.release_organization_seat(
    p_organization_id uuid,
    p_reservation_key text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    removed_count integer := 0;
begin
    perform u.organization_id
    from private.organization_seat_usage u
    where u.organization_id = p_organization_id
    for update;
    if not found then
        raise exception 'organization capacity state is unavailable';
    end if;
    delete from private.organization_seat_reservations r
    where r.organization_id = p_organization_id
      and r.reservation_key = p_reservation_key;
    get diagnostics removed_count = row_count;
    if removed_count = 1 then
        update private.organization_seat_usage u
        set used_seats = greatest(0,u.used_seats - 1),
            updated_at = statement_timestamp()
        where u.organization_id = p_organization_id;
    end if;
end;
$$;

create or replace function private.initialize_organization_capacity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into private.organization_seat_usage(organization_id)
    values (new.id)
    on conflict (organization_id) do nothing;
    return new;
end;
$$;

create trigger organizations_initialize_capacity
after insert on public.organizations
for each row execute function private.initialize_organization_capacity();

create or replace function private.sync_invitation_capacity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    seat_key text;
    membership_expiry timestamptz;
    membership_status text;
begin
    seat_key := 'invitation:' || new.id::text;
    if tg_op = 'INSERT' and new.status = 'requested' then
        perform private.reserve_organization_seat(
            new.organization_id,seat_key,new.expires_at
        );
        return new;
    end if;

    if tg_op = 'UPDATE'
       and new.status = 'requested'
       and (
           old.status is distinct from new.status
           or old.expires_at is distinct from new.expires_at
       ) then
        perform private.reserve_organization_seat(
            new.organization_id,seat_key,new.expires_at
        );
        return new;
    end if;

    if tg_op = 'UPDATE'
       and old.status = 'requested'
       and new.status <> 'requested' then
        select m.status,m.invite_expires_at
          into membership_status,membership_expiry
        from public.memberships m
        where m.organization_id = old.organization_id
          and m.invitation_request_id = old.id
          and (
              m.status = 'active'
              or (
                  m.status = 'invited'
                  and m.invite_expires_at > statement_timestamp()
              )
          )
        limit 1;
        if membership_status = 'active' then
            perform private.reserve_organization_seat(
                old.organization_id,seat_key,null
            );
        elsif membership_status = 'invited' then
            perform private.reserve_organization_seat(
                old.organization_id,seat_key,membership_expiry
            );
        else
            perform private.release_organization_seat(
                old.organization_id,seat_key
            );
        end if;
    end if;
    return new;
end;
$$;

create trigger member_invitation_capacity_guard
after insert or update of status,expires_at
on private.member_invitation_requests
for each row execute function private.sync_invitation_capacity();

create or replace function private.sync_membership_capacity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    old_key text;
    new_key text;
    pending_expiry timestamptz;
    old_counted boolean := false;
    new_counted boolean := false;
begin
    if tg_op <> 'INSERT' then
        old_counted := old.status = 'active'
            or (
                old.status = 'invited'
                and old.invite_expires_at > statement_timestamp()
            );
        old_key := case
            when old.invitation_request_id is not null
            then 'invitation:' || old.invitation_request_id::text
            else 'member:' || old.user_id::text
        end;
    end if;
    if tg_op <> 'DELETE' then
        new_counted := new.status = 'active'
            or (
                new.status = 'invited'
                and new.invite_expires_at > statement_timestamp()
            );
        new_key := case
            when new.invitation_request_id is not null
            then 'invitation:' || new.invitation_request_id::text
            else 'member:' || new.user_id::text
        end;
    end if;

    if old_counted
       and (
           not new_counted
           or old.organization_id is distinct from new.organization_id
           or old_key is distinct from new_key
       ) then
        select r.expires_at into pending_expiry
        from private.member_invitation_requests r
        where old.invitation_request_id is not null
          and r.id = old.invitation_request_id
          and r.organization_id = old.organization_id
          and r.status = 'requested'
          and r.expires_at > statement_timestamp();
        if pending_expiry is null then
            perform private.release_organization_seat(
                old.organization_id,old_key
            );
        else
            perform private.reserve_organization_seat(
                old.organization_id,old_key,pending_expiry
            );
        end if;
    end if;

    if new_counted then
        perform private.reserve_organization_seat(
            new.organization_id,
            new_key,
            case when new.status = 'invited' then new.invite_expires_at
                 else null end
        );
    end if;
    if tg_op = 'DELETE' then
        return old;
    end if;
    return new;
end;
$$;

create trigger memberships_capacity_guard
after insert or delete or update of
    organization_id,user_id,status,invite_expires_at,invitation_request_id
on public.memberships
for each row execute function private.sync_membership_capacity();

create table private.sync_event_daily_usage (
    user_id uuid not null references auth.users(id) on delete cascade,
    usage_date date not null,
    event_count integer not null check (event_count between 1 and 1000),
    updated_at timestamptz not null default statement_timestamp(),
    primary key (user_id,usage_date)
);

revoke all on table private.sync_event_daily_usage
    from public, anon, authenticated, service_role;

create or replace function private.enforce_sync_event_daily_quota()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    device_owner uuid;
    resulting_count integer;
    utc_day date := (statement_timestamp() at time zone 'UTC')::date;
begin
    -- The canonical push RPC returns duplicates before INSERT, so retries do
    -- not reach this trigger and do not consume another daily event.
    if exists (
        select 1 from public.sync_events e where e.event_id = new.event_id
    ) then
        return new;
    end if;
    if actor is null then
        raise exception 'authenticated event owner required';
    end if;
    select d.user_id into device_owner
    from public.devices d
    where d.organization_id = new.organization_id
      and d.id = new.device_id;
    if device_owner is distinct from actor then
        raise exception 'event device owner mismatch';
    end if;

    insert into private.sync_event_daily_usage(
        user_id,usage_date,event_count
    ) values (actor,utc_day,1)
    on conflict (user_id,usage_date) do update
       set event_count = private.sync_event_daily_usage.event_count + 1,
           updated_at = statement_timestamp()
       where private.sync_event_daily_usage.event_count < 1000
    returning event_count into resulting_count;
    if resulting_count is null then
        raise exception 'daily sync event limit exceeded';
    end if;
    return new;
end;
$$;

create trigger sync_events_daily_quota_guard
before insert on public.sync_events
for each row execute function private.enforce_sync_event_daily_quota();

revoke all on function private.reserve_organization_seat(uuid,text,timestamptz)
    from public, anon, authenticated, service_role;
revoke all on function private.release_organization_seat(uuid,text)
    from public, anon, authenticated, service_role;
revoke all on function private.initialize_organization_capacity()
    from public, anon, authenticated, service_role;
revoke all on function private.sync_invitation_capacity()
    from public, anon, authenticated, service_role;
revoke all on function private.sync_membership_capacity()
    from public, anon, authenticated, service_role;
revoke all on function private.enforce_sync_event_daily_quota()
    from public, anon, authenticated, service_role;

commit;
