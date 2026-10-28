"""Source-level guards for the secret-safety rules."""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "ops_deploy"
SOURCES = sorted(PACKAGE.rglob("*.py"))


def unsafe_become_keywords(tree: ast.AST) -> list[ast.keyword]:
    """Permit disabling inherited privilege, never enabling or selecting a user.

    Ordinary existing-identity SFTP must turn off a private CLI's inherited
    sudo/doas/dzdo to avoid shared plaintext staging. A corresponding user
    clearing needs its SAME-call literal False; su has no flag and clearing
    requires all three actual escalation flags explicitly disabled.
    """
    calls = {id(keyword): node for node in ast.walk(tree) if isinstance(node, ast.Call) for keyword in node.keywords}

    def literal_false(value: ast.expr) -> bool:
        return isinstance(value, ast.Constant) and type(value.value) is bool and value.value is False

    flags = {"_sudo", "_doas", "_dzdo"}
    paired = {"_sudo_user": "_sudo", "_doas_user": "_doas", "_dzdo_user": "_dzdo"}
    offenders = []
    for keyword in ast.walk(tree):
        if not isinstance(keyword, ast.keyword) or keyword.arg not in flags | set(paired) | {"_su_user"}:
            continue
        call = calls.get(id(keyword))
        disabled = {k.arg for k in call.keywords if literal_false(k.value)} if call is not None else set()
        clearing = isinstance(keyword.value, ast.Constant) and keyword.value.value in {"", None}
        if call is not None and (
            (keyword.arg in flags and literal_false(keyword.value))
            or (keyword.arg in paired and paired[keyword.arg] in disabled and clearing)
            or (keyword.arg == "_su_user" and flags <= disabled and clearing)
        ):
            continue
        offenders.append(keyword)
    return offenders


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_no_sudo_global_argument(path: Path) -> None:
    tree = ast.parse(path.read_text(), filename=str(path))
    assert [f"{path.name}:{node.lineno}" for node in unsafe_become_keywords(tree)] == []


@pytest.mark.parametrize(
    ("source", "allowed"),
    [
        ("op(_sudo=False)", True),
        ("op(_sudo=False, _sudo_user='')", True),
        ("op(_sudo=False, _doas=False, _dzdo=False, _su_user='')", True),
        ("op(_sudo=True)", False),
        ("op(_sudo=0)", False),
        ("op(_sudo=None)", False),
        ("op(_sudo=flag)", False),
        ("op(_sudo=False, _sudo_user='root')", False),
        ("op(_sudo=False, _su_user='owner')", False),
        ("op(_sudo=False, _sudo_user=empty)", False),
        ("op(_sudo=False, _su_user=empty())", False),
        ("op(_sudo_user='')", False),
        ("op(_su_user='')", False),
        ("op(_sudo=False, nested=op(_sudo_user=''))", False),
        ("op(_doas=False)", True),
        ("op(_dzdo=False)", True),
        ("op(_doas=False, _doas_user='')", True),
        ("op(_dzdo=False, _dzdo_user=None)", True),
        ("op(_doas=True)", False),
        ("op(_dzdo=True)", False),
        ("op(_doas=0)", False),
        ("op(_dzdo=0)", False),
        ("op(_doas=flag)", False),
        ("op(_dzdo=flag)", False),
        ("op(_doas_user='')", False),
        ("op(_dzdo_user=None)", False),
        ("op(_sudo=False, _doas_user='')", False),
        ("op(_doas=False, _doas_user='root')", False),
        ("op(_dzdo=False, _dzdo_user='root')", False),
        ("op(_sudo=False, _su_user='')", False),
        ("op(_sudo=False, _doas=False, _dzdo=False, _su_user='root')", False),
        ("class C(Base, _sudo=False): pass", False),
    ],
)
def test_sudo_policy_only_accepts_literal_disabling_in_the_same_call(source: str, allowed: bool) -> None:
    assert (not unsafe_become_keywords(ast.parse(source))) is allowed


REVEAL_ALLOWED = {PACKAGE / "core" / "secrets.py", PACKAGE / "ops" / "secret_file.py"}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_secret_content_is_only_revealed_by_secret_file(path: Path) -> None:
    # Secret bytes reach a host only through secret_file (stdin, 0600 temp, rename),
    # never through files.put/files.template or a command line.
    if path in REVEAL_ALLOWED:
        return
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = [
        f"{path.name}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "reveal"
    ]
    assert offenders == []


def test_sources_were_found() -> None:
    assert len(SOURCES) > 5
