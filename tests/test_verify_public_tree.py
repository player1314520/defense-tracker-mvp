from scripts.verify_public_tree import CONTENT_RULES


def test_public_maintainer_handle_is_allowed_but_bare_legacy_marker_is_blocked():
    pattern = CONTENT_RULES["unapproved legacy user marker"]
    legacy_marker = "131" + "4520"

    assert pattern.search(f"legacy account {legacy_marker}") is not None
    assert pattern.search("@player1314520") is None
    assert pattern.search("https://github.com/player1314520/project") is None
    assert pattern.search("168609221+player1314520@users.noreply.github.com") is None
