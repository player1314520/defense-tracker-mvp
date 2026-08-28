"""Visible, current-user-only WeChat MP credential configuration window."""

from __future__ import annotations

import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from wechat_publisher import CredentialVaultError, WechatCredentialVault  # noqa: E402
from wechat_runtime import (  # noqa: E402
    RuntimeSecurityError,
    ensure_secure_directory,
    resolve_runtime_paths,
)


_FIELDS = (
    ("app_id", "AppID"),
    ("app_secret", "AppSecret"),
    ("thumb_media_id", "永久封面 media_id"),
)

_SAFE_MESSAGES = {
    "CONFIGURED": "配置已安全保存",
    "ARGUMENTS_NOT_ALLOWED": "不允许通过命令行传入配置值。",
    "INPUT_CANCELLED": "配置已取消。",
    "INPUT_MISSING": "三项内容均为必填项。",
    "RUNTIME_SECURITY_ERROR": "运行目录安全校验未通过。",
    "CREDENTIAL_VAULT_ERROR": "凭据安全保存失败。",
    "GUI_ERROR": "配置窗口无法打开。",
}


def prompt_credentials(*, tk_module: Any | None = None) -> dict[str, str] | None:
    """Show one window with three masked fields, returning values on submit."""

    if tk_module is None:
        import tkinter as tk_module

    root = tk_module.Tk()
    root.title("公众号安全配置")
    root.resizable(False, False)

    variables = {
        name: tk_module.StringVar(master=root)
        for name, _label in _FIELDS
    }
    result: dict[str, str] | None = None

    def close_with_result() -> None:
        nonlocal result
        result = {name: variables[name].get() for name, _label in _FIELDS}
        for variable in variables.values():
            variable.set("")
        root.destroy()

    def cancel() -> None:
        for variable in variables.values():
            variable.set("")
        root.destroy()

    entries = []
    for row, (name, label) in enumerate(_FIELDS):
        tk_module.Label(root, text=label).grid(
            row=row,
            column=0,
            padx=(16, 8),
            pady=(14 if row == 0 else 6, 6),
            sticky="e",
        )
        entry = tk_module.Entry(
            root,
            textvariable=variables[name],
            show="*",
            width=48,
        )
        entry.grid(
            row=row,
            column=1,
            columnspan=2,
            padx=(0, 16),
            pady=(14 if row == 0 else 6, 6),
            sticky="ew",
        )
        entries.append(entry)

    tk_module.Button(root, text="取消", command=cancel).grid(
        row=len(_FIELDS), column=1, padx=8, pady=(12, 16), sticky="e"
    )
    tk_module.Button(root, text="安全保存", command=close_with_result).grid(
        row=len(_FIELDS), column=2, padx=(0, 16), pady=(12, 16), sticky="e"
    )
    root.protocol("WM_DELETE_WINDOW", cancel)
    entries[0].focus_set()
    root.mainloop()
    return result


def show_message(status: str, code: str) -> None:
    """Display only fixed, non-sensitive completion text."""

    from tkinter import messagebox

    text = _SAFE_MESSAGES.get(code, _SAFE_MESSAGES["GUI_ERROR"])
    if status == "CONFIGURED":
        messagebox.showinfo("公众号安全配置", text)
    else:
        messagebox.showerror("公众号安全配置", text)


def _finish(
    status: str,
    code: str,
    *,
    message: Callable[[str, str], None],
    exit_code: int,
) -> int:
    print(code)
    try:
        message(status, code)
    except Exception:
        return exit_code
    return exit_code


def main(
    argv: list[str] | None = None,
    *,
    prompt: Callable[[], Mapping[str, object] | None] = prompt_credentials,
    message: Callable[[str, str], None] = show_message,
    vault_factory: Callable[[Path], Any] = WechatCredentialVault,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Secure the runtime, collect masked input, and save it to the DPAPI vault."""

    arguments = sys.argv[1:] if argv is None else list(argv)
    if arguments:
        return _finish(
            "BLOCKED",
            "ARGUMENTS_NOT_ALLOWED",
            message=message,
            exit_code=2,
        )

    try:
        paths = resolve_runtime_paths(environment)
        ensure_secure_directory(paths.runtime_dir)
    except (RuntimeSecurityError, OSError):
        return _finish(
            "BLOCKED",
            "RUNTIME_SECURITY_ERROR",
            message=message,
            exit_code=2,
        )

    try:
        supplied = prompt()
    except Exception:
        return _finish("BLOCKED", "GUI_ERROR", message=message, exit_code=2)
    if supplied is None:
        return _finish("BLOCKED", "INPUT_CANCELLED", message=message, exit_code=2)

    try:
        credentials = {
            name: str(supplied.get(name, "")).strip()
            for name, _label in _FIELDS
        }
    except (AttributeError, TypeError, ValueError):
        return _finish("BLOCKED", "INPUT_MISSING", message=message, exit_code=2)
    if any(not value for value in credentials.values()):
        return _finish("BLOCKED", "INPUT_MISSING", message=message, exit_code=2)

    try:
        vault = vault_factory(paths.vault_path)
        vault.save(credentials)
    except RuntimeSecurityError:
        return _finish(
            "BLOCKED",
            "RUNTIME_SECURITY_ERROR",
            message=message,
            exit_code=2,
        )
    except (CredentialVaultError, OSError, TypeError, ValueError):
        return _finish(
            "BLOCKED",
            "CREDENTIAL_VAULT_ERROR",
            message=message,
            exit_code=2,
        )
    finally:
        if "credentials" in locals():
            credentials.clear()

    return _finish("CONFIGURED", "CONFIGURED", message=message, exit_code=0)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    raise SystemExit(main())
