from feishu_common import ascii_fallback_name, sanitize_feishu_filename


def test_sanitize_feishu_filename_removes_bad_chars_and_preserves_extension():
    name = sanitize_feishu_filename('报告、"F-35":测试?.docx')
    assert '"' not in name
    assert ":" not in name
    assert "?" not in name
    assert name.endswith(".docx")
    assert "F-35" in name


def test_sanitize_feishu_filename_limits_utf8_bytes():
    name = sanitize_feishu_filename("军" * 100 + ".pdf", max_bytes=40)
    assert len(name.encode("utf-8")) <= 40
    assert name.endswith(".pdf")


def test_ascii_fallback_name_uses_latin_tokens():
    name = ascii_fallback_name(".pdf", original="简报 Rheinmetall-Lynx Block2.pdf")
    assert name.startswith("brief_Rheinmetall-Lynx_Block2_")
    assert name.endswith(".pdf")
