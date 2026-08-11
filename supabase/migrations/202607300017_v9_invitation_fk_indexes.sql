-- Cover invitation lifecycle foreign keys introduced by migration 015.
begin;

create index if not exists member_invitation_requests_requested_by_fk_idx
    on private.member_invitation_requests(requested_by)
    where requested_by is not null;

create index if not exists member_invitation_requests_invited_user_fk_idx
    on private.member_invitation_requests(invited_user_id)
    where invited_user_id is not null;

create index if not exists memberships_invited_by_fk_idx
    on public.memberships(invited_by)
    where invited_by is not null;

create index if not exists memberships_invitation_request_fk_idx
    on public.memberships(organization_id,invitation_request_id)
    where invitation_request_id is not null;

commit;
