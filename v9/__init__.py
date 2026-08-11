"""V9 zero-knowledge domain layer."""

__all__ = ["V9Service"]


def __getattr__(name):
    """Keep the cloud-only package import free of desktop dependencies."""
    if name == "V9Service":
        from .service import V9Service

        return V9Service
    raise AttributeError(name)
