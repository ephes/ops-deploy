"""The Next.js standalone part: middleware, build, purged public files, the legacy-code guard.

The build runs as the service user in the site (``npm ci``, ``npm run build``
with the build environment) when the source changed or the build stamp
(``<site>/.ops-deploy-next-build``, the build environment of the last
complete build) differs. The stamp is removed before the build and written
after it, so a build that fails runs again on the next deploy; the
frontend's restart marker is written before anything changes.
"""

from __future__ import annotations

import hashlib
import shlex
from collections.abc import Callable, Iterable

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha256File
from pyinfra.operations import files, server

from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.python import DEFAULT_UV
from ops_deploy.services.django_site.config import DjangoSiteConfig, LegacyGuard, NextStandalone
from ops_deploy.services.django_site.django import fact, site_shell

BUILD_STAMP = ".ops-deploy-next-build"


def code_lines(lines: Iterable[str]) -> list[str]:
    """``lines`` without comment and blank lines (the shebang counts as code)."""

    return [line for line in lines if line.strip() and (line.startswith("#!") or not line.lstrip().startswith("#"))]


def require_tools(front: NextStandalone) -> OperationMeta:
    """Node.js and uv are host-level; the host's own deploys install them (read-only)."""

    node = shlex.quote(str(front.node))
    return mark_read_only(
        server.shell(
            name="Require Node.js and uv",
            commands=[
                f"test -x {node} && test -x {DEFAULT_UV} || "
                f"{{ echo 'this deploy needs {front.node} and {DEFAULT_UV}' >&2; exit 1; }}"
            ],
        )
    )


def install_middleware(cfg: DjangoSiteConfig, front: NextStandalone) -> OperationMeta | None:
    """``<app_dir>/<middleware_from>`` installed as ``<app_dir>/middleware.ts``.

    Returns the operation when the content differs (a source change); an
    owner or mode repair alone is written without counting as one.
    """

    if not front.middleware_from:
        return None
    src = cfg.source.path / front.app_dir / front.middleware_from
    dest = cfg.site_path / front.app_dir / "middleware.ts"
    op = files.put(
        name=f"Install {front.app_dir}/{front.middleware_from} as {front.app_dir}/middleware.ts",
        src=str(src),
        dest=str(dest),
        user=cfg.user,
        group=cfg.group_name,
        mode="0644",
    )
    deployed = host.get_fact(Sha256File, path=str(dest))
    return op if deployed != hashlib.sha256(src.read_bytes()).hexdigest() else None


def build(cfg: DjangoSiteConfig, front: NextStandalone, *, before: str, when: Callable[[], bool]) -> OperationMeta:
    """``npm ci`` and ``next build`` when ``when()`` or the stamp is stale; ``before``: a root command run first."""

    site = shlex.quote(str(cfg.site_path))
    standalone = front.standalone_dir
    current = fact(f"cat {site}/{BUILD_STAMP} 2>/dev/null; test -f {site}/{standalone}/server.js && echo built || true")
    stale = current != f"{front.build_stamp}\nbuilt"
    script = "; ".join(
        [
            "set -e",
            f"rm -f {BUILD_STAMP}",
            "npm ci --no-audit --no-fund",
            f"{shlex.join(['env', *front.build_argv])} npm run build",
            # ``next build`` leaves these out of the standalone output.
            f"[ -e {standalone}/.next/static ] || cp -r {front.app_dir}/.next/static {standalone}/.next/static",
            # ``public/`` is optional in a Next.js app.
            f"[ -e {standalone}/public ] || [ ! -e {front.app_dir}/public ] || "
            f"cp -r {front.app_dir}/public {standalone}/public",
            f"echo {shlex.quote(front.build_stamp)} > {BUILD_STAMP}",
        ]
    )
    shell = _in_site(cfg, script)
    return server.shell(
        name="Build the Next.js app (npm ci, next build)",
        commands=[f"{before} && {shell}"],
        _if=lambda: stale or when(),
    )


def _in_site(cfg: DjangoSiteConfig, script: str) -> str:
    """``script`` run by ``sh`` in the site root as the service user."""

    return site_shell(cfg, script, cwd=cfg.site_path)


def purge_public_dirs(cfg: DjangoSiteConfig, front: NextStandalone, *, after: Callable[[], bool]) -> None:
    """Files in ``purged_public_dirs`` are never served: removed when present, then checked (read-only).

    The removal also runs when ``after()`` (the source or the build changed):
    those may bring such files that no fact saw while planning.
    """

    dirs = [
        f"{base}/public/{name}" for name in front.purged_public_dirs for base in (front.app_dir, front.standalone_dir)
    ]
    if not dirs:
        return
    find = purge_script(dirs, "-print -quit")
    site = shlex.quote(str(cfg.site_path))
    # Nothing synced yet on a new host: nothing to remove.
    found = bool(fact(f"if cd {site} 2>/dev/null; then {find}; fi"))
    server.shell(
        name="Remove purged public files",
        commands=[_in_site(cfg, purge_script(dirs, "-delete"))],
        _if=lambda: found or after(),
    )
    check = f'cd {site} && out=$( {find} ); [ -z "$out" ] || {{ echo "purged files still served: $out" >&2; exit 1; }}'
    mark_read_only(server.shell(name="Check purged public files are absent", commands=[check]))


def purge_script(dirs: Iterable[str], action: str) -> str:
    """``find <dir> <symlinks and files but a regular .gitkeep> <action>`` for each of ``dirs`` that exists.

    Symlinks count, a symlinked ``dir`` itself included: ``find`` does not
    follow it, so a link to private files is removed instead of served. A
    symlinked parent of ``dir`` (``public`` linked to private storage) would
    be followed: then nothing is removed, the ``-delete`` script fails and
    the listing script prints the link (so the check after the purge fails).
    """

    parts = []
    for d in dirs:
        segments = d.split("/")[:-1]
        parents = ["/".join(segments[: i + 1]) for i in range(len(segments))]
        linked = " || ".join(f"[ -L {p} ]" for p in parents)
        refuse = (
            f"echo '{d}: a parent directory is a symlink; nothing removed' >&2; exit 1"
            if "-delete" in action
            else f"echo {d}"
        )
        find = f"find {d} \\( -type l -o -type f ! -name .gitkeep \\) {action}"
        guard = f"if {linked}; then {refuse}; el" if parents else ""
        parts.append(f"{guard}if [ -e {d} ] || [ -L {d} ]; then {find}; fi")
    return "; ".join(parts)


def legacy_guard(cfg: DjangoSiteConfig, guard: LegacyGuard) -> None:
    if guard.tokens or guard.dirs:
        site = shlex.quote(str(cfg.site_path))
        mark_read_only(
            server.shell(name="Check no legacy code is served", commands=[f"cd {site} && {legacy_guard_script(guard)}"])
        )


def legacy_guard_script(guard: LegacyGuard) -> str:
    """Fails when a ``guard.tokens`` string or a ``guard.dirs`` directory is in the served code."""

    lines = []
    if guard.tokens:
        grep = " ".join(f"-e {t}" for t in guard.tokens)
        targets = " ".join(guard.search)
        include = " ".join(f"--include='*.{ext}'" for ext in ("js", "ts", "tsx", "mjs", "cjs"))
        lines.append(f"tokens=$(grep -rInF --exclude-dir=node_modules {grep} {targets} {include} 2>/dev/null || true)")
    else:
        lines.append("tokens=")
    if guard.dirs:
        paths = " -o ".join(f"-path '{d}'" for d in guard.dirs)
        roots = " ".join(guard.search)
        prune = "-name node_modules -prune -o"
        lines.append(f"dirs=$(find {roots} {prune} -type d \\( {paths} \\) -print 2>/dev/null || true)")
    else:
        lines.append("dirs=")
    lines.append(
        'if [ -n "$tokens" ] || [ -n "$dirs" ]; then echo "Legacy code found in the served tree" >&2; '
        '[ -z "$tokens" ] || echo "$tokens" >&2; [ -z "$dirs" ] || echo "Directories: $dirs" >&2; exit 1; fi'
    )
    return "\n".join(lines) + "\n"


def code_changed(text: str, deployed: list[str] | None) -> bool:
    """Whether writing ``text`` over the ``deployed`` lines changes what runs (not only comments)."""

    return deployed is None or code_lines(deployed) != code_lines(text.splitlines())
