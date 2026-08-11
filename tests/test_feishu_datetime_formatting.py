import ast
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEISHU_MODULES = ("feishu_cloud.py", "feishu_bot.py")


def _contains_chinese(text: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in text)


@pytest.mark.parametrize("module_name", FEISHU_MODULES)
def test_strftime_format_strings_are_locale_independent(module_name):
    module_path = PROJECT_ROOT / module_name
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_path))

    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "strftime":
            continue
        if not node.args:
            continue

        string_parts = (
            child.value
            for child in ast.walk(node.args[0])
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        )
        if any(_contains_chinese(part) for part in string_parts):
            violations.append(node.lineno)

    assert violations == [], (
        f"{module_name} passes Chinese text to strftime on lines {violations}; "
        "format numeric fields directly so Windows locale/code-page settings cannot alter it"
    )
