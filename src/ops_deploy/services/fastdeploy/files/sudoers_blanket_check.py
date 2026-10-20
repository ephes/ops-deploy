"""Print the sudoers files (arguments) that a FastDeploy restore must not copy back.

Allowlist, not a search for bad rules: a file is restorable only when every
line is blank, a plain comment, or exactly the narrow shape the current
registration roles write,

    <user> ALL=(<runas>) NOPASSWD:[NOSETENV:] <script>[ *| --config *]

where <script> is a file where the registration roles put service scripts:
/usr/local/libexec/fastdeploy/<service>/<file> or /usr/local/libexec/<file>
(root-owned, fastdeploy_runner role), or, for a rule that runs as deploy,
/home/deploy/runners/<service>/<file>. Plain path components only (no
directory, no `..`). Rules naming FastDeploy's services root
(/home/fastdeploy/site/services/) are not restored: fastdeploy owns the site
and could replace any script there.

Comments are "#" alone or "# text". Anything else (a command list with
ALL, aliases, Defaults, includes, #<uid> rules,
continuations, several commands) is reported, and the file is not restored;
rerun the service's register playbook instead.
"""

import re
import sys

RULE = re.compile(
    r"^[a-z_][a-z0-9_-]*[ \t]+ALL[ \t]*=[ \t]*\("
    # run as deploy: a root-owned runner or one in the deploy user's own runner directory
    r"(?:deploy\)[ \t]*NOPASSWD:(?:NOSETENV:)?[ \t]*"
    r"(?:/usr/local/libexec/(?:fastdeploy/[A-Za-z0-9_][A-Za-z0-9._-]*/[A-Za-z0-9_][A-Za-z0-9._-]*|[A-Za-z0-9_][A-Za-z0-9._-]*)"
    r"|/home/deploy/runners/[A-Za-z0-9_][A-Za-z0-9._-]*/[A-Za-z0-9_][A-Za-z0-9._-]*)"
    # run as anyone else (root): only a root-owned runner
    r"|[A-Za-z_][A-Za-z0-9_-]*\)[ \t]*NOPASSWD:(?:NOSETENV:)?[ \t]*"
    r"/usr/local/libexec/(?:fastdeploy/[A-Za-z0-9_][A-Za-z0-9._-]*/[A-Za-z0-9_][A-Za-z0-9._-]*|[A-Za-z0-9_][A-Za-z0-9._-]*))"
    r"(?:[ \t]+(?:\*|--config[ \t]+\*))?[ \t]*$"
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
