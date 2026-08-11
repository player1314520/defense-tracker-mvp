import ast
from datetime import datetime
from pathlib import Path

import app as tracker


class LocaleHostileDateTime(datetime):
    def strftime(self, _format):
        raise AssertionError("Chinese date formatting must not call strftime")


def test_chinese_datetime_helpers_are_locale_independent_and_zero_padded():
    value = LocaleHostileDateTime(2026, 1, 2, 3, 4)

    assert tracker._format_cn_date(value) == "2026年01月02日"
    assert tracker._format_cn_month_day(value) == "01月02日"
    assert tracker._format_cn_datetime_minutes(value) == "2026年01月02日 03:04"


def test_app_has_no_chinese_bearing_strftime_format_strings():
    source_path = Path(tracker.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    violations = []

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "strftime"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue
        format_string = node.args[0].value
        if any("\u4e00" <= char <= "\u9fff" for char in format_string):
            violations.append((node.lineno, format_string))

    assert violations == []
