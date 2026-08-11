-- Cover every foreign key reported by the Supabase Performance Advisor.
-- Keep the indexes minimal: each key list exactly matches its FK column order.
begin;

create index if not exists encrypted_object_delete_requests_record_version_idx
    on private.encrypted_object_delete_requests
        (organization_id, record_id, version_id);

create index if not exists encrypted_object_delete_requests_finalized_by_idx
    on private.encrypted_object_delete_requests (finalized_by);

create index if not exists encrypted_object_delete_requests_requested_by_idx
    on private.encrypted_object_delete_requests (requested_by);

create index if not exists signed_publication_objects_publication_version_idx
    on private.signed_publication_objects
        (organization_id, publication_id, record_id, record_version_id);

create index if not exists signed_publication_versions_record_version_idx
    on private.signed_publication_versions
        (organization_id, record_id, record_version_id);

create index if not exists signed_publication_versions_signed_by_idx
    on private.signed_publication_versions (signed_by);

create index if not exists snapshot_import_items_import_org_idx
    on private.snapshot_import_items (import_id, organization_id);

create index if not exists snapshot_import_items_record_version_idx
    on private.snapshot_import_items
        (organization_id, record_id, version_id);

create index if not exists snapshot_imports_created_by_idx
    on private.snapshot_imports (created_by);

create index if not exists workflow_states_bound_version_idx
    on public.workflow_states
        (organization_id, record_id, bound_version_id);

commit;
