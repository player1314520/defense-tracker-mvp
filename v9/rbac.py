"""Six-role authorization matrix for local checks and API decisions."""

ROLES = ("owner", "admin", "collector", "analyst", "editor", "approver")

_ROLE_PERMISSIONS = {
    "owner": {"*"},
    "admin": {
        "member.manage",
        "device.manage",
        "rules.manage",
        "system.configure",
        "record.read",
    },
    "collector": {
        "source.create",
        "evidence.create",
        "evidence.annotate",
        "record.read",
    },
    "analyst": {
        "case.analyze",
        "graph.edit",
        "geo.edit",
        "scenario.run",
        "record.read",
    },
    "editor": {
        "document.edit",
        "layout.edit",
        "audit.write",
        "record.read",
    },
    "approver": {
        "publication.approve",
        "publication.recall",
        "audit.write",
        "audit.read",
        "record.read",
    },
}


def role_allows(role: str, permission: str) -> bool:
    permissions = _ROLE_PERMISSIONS.get((role or "").lower(), set())
    return "*" in permissions or permission in permissions
