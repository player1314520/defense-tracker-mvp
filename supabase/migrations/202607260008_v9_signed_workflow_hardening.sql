-- Defense Tracker V9 signed-record and workflow state hardening.
-- This migration is intentionally additive so already-deployed migration 007
-- remains immutable in Staging.

create or replace function private.guard_signed_record_version()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if exists (
        select 1
        from public.workflow_states w
        where w.organization_id = new.organization_id
          and w.record_id = new.record_id
          and w.state = 'signed'
    ) then
        raise exception 'signed record is immutable until recalled';
    end if;
    return new;
end;
$$;

drop trigger if exists guard_signed_record_version
    on public.record_versions;
create trigger guard_signed_record_version
before insert on public.record_versions
for each row execute function private.guard_signed_record_version();

create or replace function private.guard_workflow_transition()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.state not in (
        'draft','editing','pending_approval','signed','recalled'
    ) then
        raise exception 'invalid workflow state';
    end if;

    if tg_op = 'INSERT' then
        if new.version <> 1
           or new.state not in ('draft','editing') then
            raise exception 'invalid initial workflow transition';
        end if;
        return new;
    end if;

    if new.version <> old.version + 1
       or not (
            (
                old.state in ('draft','editing')
                and new.state in ('editing','pending_approval')
            )
            or (
                old.state = 'pending_approval'
                and new.state in ('editing','signed')
            )
            or (
                old.state = 'signed'
                and new.state = 'recalled'
            )
            or (
                old.state = 'recalled'
                and new.state = 'editing'
            )
       ) then
        raise exception 'invalid workflow transition';
    end if;

    if new.state = 'signed'
       and old.content_hash <> new.content_hash then
        raise exception 'pending approval content hash changed';
    end if;
    if new.state = 'signed'
       and exists (
            select 1
            from public.conflicts c
            where c.organization_id = new.organization_id
              and c.record_id = new.record_id
              and c.status = 'open'
       ) then
        raise exception 'open conflict blocks signing';
    end if;
    return new;
end;
$$;

drop trigger if exists guard_workflow_transition
    on public.workflow_states;
create trigger guard_workflow_transition
before insert or update on public.workflow_states
for each row execute function private.guard_workflow_transition();

revoke all on function private.guard_signed_record_version()
    from public, anon, authenticated;
revoke all on function private.guard_workflow_transition()
    from public, anon, authenticated;
