import hashlib
import subprocess

from scripts import verify_public_tree
from scripts.verify_public_tree import CONTENT_RULES


def test_public_maintainer_handle_is_allowed_but_bare_legacy_marker_is_blocked():
    pattern = CONTENT_RULES["unapproved legacy user marker"]
    legacy_marker = "131" + "4520"

    assert pattern.search(f"legacy account {legacy_marker}") is not None
    assert pattern.search("@player1314520") is None
    assert pattern.search("https://github.com/player1314520/project") is None
    assert pattern.search("168609221+player1314520@users.noreply.github.com") is None


def _tracked_tree(tmp_path, relative_path: str, payload: bytes):
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", relative_path], check=True)
    return tmp_path


def test_public_tree_rejects_plainly_named_raster_image(tmp_path):
    root = _tracked_tree(
        tmp_path,
        "static/img/banner.png",
        b"\x89PNG\r\n\x1a\n\x00possible-account-screenshot",
    )

    assert verify_public_tree.audit(root) == [
        "unapproved raster image: static/img/banner.png"
    ]


def test_public_tree_rejects_png_disguised_with_data_suffix(tmp_path):
    root = _tracked_tree(
        tmp_path,
        "static/img/banner.dat",
        b"\x89PNG\r\n\x1a\n\x00possible-account-screenshot",
    )

    assert verify_public_tree.audit(root) == [
        "unapproved binary file: static/img/banner.dat"
    ]


def test_public_tree_rejects_jpeg_disguised_without_suffix(tmp_path):
    root = _tracked_tree(
        tmp_path,
        "static/img/banner",
        b"\xff\xd8\xff\xe0possible-account-screenshot\xff\xd9",
    )

    assert verify_public_tree.audit(root) == [
        "non-UTF-8 tracked file: static/img/banner"
    ]


def test_public_tree_rejects_unapproved_svg(tmp_path):
    root = _tracked_tree(
        tmp_path,
        "static/img/banner.svg",
        b'<svg xmlns="http://www.w3.org/2000/svg"><text>public</text></svg>',
    )

    assert verify_public_tree.audit(root) == [
        "unapproved SVG image: static/img/banner.svg"
    ]


def test_public_tree_rejects_embedded_image_even_for_hash_allowed_svg(
    tmp_path, monkeypatch
):
    relative = "static/img/test-map.svg"
    payload = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<image href="data:image/png;base64,placeholder"/></svg>'
    )
    root = _tracked_tree(tmp_path, relative, payload)
    monkeypatch.setitem(
        verify_public_tree.ALLOWED_SVG_SHA256,
        relative,
        hashlib.sha256(payload).hexdigest(),
    )

    assert verify_public_tree.audit(root) == [
        "SVG embeds raster or external image data: static/img/test-map.svg"
    ]


def test_public_tree_svg_hash_is_stable_across_checkout_line_endings(
    tmp_path, monkeypatch
):
    relative = "static/img/test-map.svg"
    payload_lf = b'<svg xmlns="http://www.w3.org/2000/svg">\n<path d="M0 0"/>\n</svg>\n'
    payload_crlf = payload_lf.replace(b"\n", b"\r\n")
    root = _tracked_tree(tmp_path, relative, payload_crlf)
    monkeypatch.setitem(
        verify_public_tree.ALLOWED_SVG_SHA256,
        relative,
        hashlib.sha256(payload_lf).hexdigest(),
    )

    assert verify_public_tree.audit(root) == []
