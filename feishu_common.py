"""Shared helpers for local and cloud Feishu bot modules."""
import re
import time


_FILENAME_BAD_CHARS = re.compile(r'[\x00-\x1f"\'\\/:*?<>|`\r\n\t]')
_CN_PUNCT_MAP = str.maketrans({
    "、": "_", "，": "_", "。": ".", "；": "_", "：": "_",
    "！": "", "？": "", "（": "(", "）": ")", "【": "[", "】": "]",
    "《": "", "》": "", "「": "", "」": "", "『": "", "』": "",
    "—": "-", "～": "~", "…": "_",
})
_FALLBACK_SKIP = {"docx", "doc", "xlsx", "xls", "pptx", "ppt", "pdf", "txt", "md", "brief"}


def sanitize_feishu_filename(name: str, max_bytes: int = 120) -> str:
    """Clean a filename before sending it to Feishu's file upload API."""
    cleaned = (name or "").translate(_CN_PUNCT_MAP)
    cleaned = _FILENAME_BAD_CHARS.sub("_", cleaned)
    cleaned = re.sub(r"_{2,}", "_", cleaned).strip(" _.")
    if not cleaned:
        cleaned = "file"
    root, _, ext = cleaned.rpartition(".")
    if not root:
        root, ext = cleaned, ""
    else:
        ext = "." + ext
    while len(root.encode("utf-8")) + len(ext.encode("utf-8")) > max_bytes and len(root) > 1:
        root = root[:-1]
    return root + ext


def ascii_fallback_name(ext: str, original: str = "") -> str:
    """Build an ASCII-only fallback name while preserving useful Latin tokens."""
    if original:
        stem_only = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", original)
        ascii_parts = re.findall(r"[A-Za-z][A-Za-z0-9\-]{1,}", stem_only)
        ascii_parts = [p for p in ascii_parts if p.lower() not in _FALLBACK_SKIP][:4]
        if ascii_parts:
            stem = "_".join(ascii_parts)[:60]
            return f"brief_{stem}_{time.strftime('%Y%m%d_%H%M')}{ext}"
    return f"brief_{time.strftime('%Y%m%d_%H%M%S')}{ext}"
