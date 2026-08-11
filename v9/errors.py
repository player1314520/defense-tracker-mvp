class V9Error(Exception):
    """Base error for the V9 domain."""


class PermissionDenied(V9Error):
    pass


class VersionConflict(V9Error):
    pass


class NotFound(V9Error):
    pass


class InvalidRecordType(V9Error):
    pass


class UntrustedSyncEvent(V9Error):
    """A deterministic remote ciphertext failure safe to quarantine."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
