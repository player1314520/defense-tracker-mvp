"""Windows desktop single-instance guard with no application imports."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass


DEFAULT_MUTEX_NAME = r"Local\DefenseTracker.Desktop.SingleInstance"
_ERROR_ALREADY_EXISTS = 183


@dataclass
class DesktopInstanceMutex:
    """Own a Windows kernel mutex handle for the lifetime of the process."""

    handle: int
    _kernel32: object

    def close(self) -> None:
        handle, self.handle = self.handle, 0
        if handle:
            self._kernel32.CloseHandle(handle)

    def __enter__(self) -> "DesktopInstanceMutex":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


def try_acquire_desktop_mutex(
    name: str = DEFAULT_MUTEX_NAME,
) -> DesktopInstanceMutex | None:
    """Return an owned mutex, or ``None`` when another instance owns it."""

    if os.name != "nt":
        return DesktopInstanceMutex(handle=1, _kernel32=_NoopKernel32())

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool

    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return DesktopInstanceMutex(handle=int(handle), _kernel32=kernel32)


class _NoopKernel32:
    @staticmethod
    def CloseHandle(_handle: int) -> bool:
        return True
