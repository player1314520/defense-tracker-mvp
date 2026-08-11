-- RLS is the row boundary; table grants are an independent least-privilege layer.
revoke all on all tables in schema public from authenticated;
revoke all on all sequences in schema public from authenticated;

grant select on
    public.organizations,
    public.memberships,
    public.devices,
    public.key_envelopes,
    public.recovery_envelopes,
    public.record_heads,
    public.record_versions,
    public.sync_events,
    public.sync_wakeups,
    public.conflicts,
    public.encrypted_objects,
    public.workflow_states,
    public.audit_chain,
    public.key_rotations,
    public.key_rotation_entries,
    public.device_pairings
to authenticated;

-- Organization labels are ciphertext and remain Owner-protected by RLS.
grant update on public.organizations to authenticated;

-- Encrypted object metadata is the only direct DML surface. Objects are
-- immutable: updates are intentionally not granted.
grant insert, delete on public.encrypted_objects to authenticated;
