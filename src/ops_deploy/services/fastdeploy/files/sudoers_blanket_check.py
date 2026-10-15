"""Print the sudoers files (arguments) that a FastDeploy restore must not copy back.

Allowlist, not a search for bad rules: a file is restorable only when every
line is blank, a plain comment, or exactly the narrow shape the current
registration roles write,

    <user> ALL=(<runas>) NOPASSWD:[NOSETENV:] <script>[ *| --config *]

where <script> is a file (one or two plain path components, no directory, no
`..`) under /home/fastdeploy/site/services/, /home/deploy/runners/ or
/usr/local/libexec/ - where the registration roles put service scripts.

Comments are "#" alone or "# text". Anything else (a command list with
ALL, aliases, Defaults, includes, #<uid> rules,
continuations, several commands) is reported, and the file is not restored;
rerun the service's register playbook instead.
"""

import re
import sys

RULE = re.compile(
    r"^[a-z_][a-z0-9_-]*[ \t]+ALL[ \t]*=[ \t]*\([A-Za-z_][A-Za-z0-9_-]*\)[ \t]*"
    r"NOPASSWD:(?:NOSETENV:)?[ \t]*(?:/home/fastdeploy/site/services/|/home/deploy/runners/|/usr/local/libexec/)(?!\.\.?/)[A-Za-z0-9_][A-Za-z0-9._-]*(?:/(?!\.\.?(?:[ \t]|$))[A-Za-z0-9_][A-Za-z0-9._-]*)?(?:[ \t]+(?:\*|--config[ \t]+\*))?[ \t]*$"
)


def restorable(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Only "#" alone or "# text" is a comment: "#include", "#includedir" and
        # "#<uid> ..." (a rule for a numeric user ID) are directives or rules.
        if re.match(r"#(?:\s|$)", stripped):
            continue
        if not RULE.match(stripped):
            return False
    return True


def main(paths: list[str]) -> int:
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            if not restorable(handle.read()):
                print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
