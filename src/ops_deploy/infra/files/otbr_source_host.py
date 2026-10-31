"""Target Git plan/apply, using the original force/update/recursive contract.

Only source-plan is a fact. source-apply is always a scheduled operation and
never runs as a planning probe. No radio, service or network setup is hidden here.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


def normalized_source(cfg):
    repo = cfg["repo_url"]
    if repo.startswith("-") or cfg["repo_version"].startswith("-"):
        raise ValueError("OTBR source values must not be Git options")
    # Git normalizes a local clone origin; do that once before resolving,
    # comparing or setting origin, from the same original command cwd.
    if "://" not in repo and re.match(r"^[^/]+:", repo) is None:
        repo = os.path.abspath(os.path.expanduser(repo))
    return {**cfg, "repo_url": repo}


def remote_refs(cfg, *patterns, symref=False):
    options = ["--symref"] if symref else []
    result = subprocess.run(
        ["git", "--no-optional-locks", "ls-remote", *options, "--", cfg["repo_url"], *patterns],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        # A configured authenticated URL must not appear in an exception argv.
        raise RuntimeError("Cannot resolve the selected OTBR source")
    return result.stdout


def git(directory, *args, required=True):
    result = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(directory), *args], capture_output=True, text=True, check=False
    )
    if required and result.returncode:
        raise RuntimeError("OTBR Git command failed: " + args[0])
    return result.stdout.strip() if result.returncode == 0 else None


def resolve(cfg):
    ref = cfg["repo_version"]
    if re.fullmatch("[0-9a-fA-F]{40}", ref):
        return ref.lower(), "commit", None
    head_branch = None
    if ref == "HEAD" and (Path(cfg["install_dir"]) / ".git").exists():
        head_branch = git(cfg["install_dir"], "symbolic-ref", "--quiet", "--short", "HEAD", required=False)
        if not head_branch:
            cached = git(
                cfg["install_dir"], "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", required=False
            )
            head_branch = cached.removeprefix("origin/") if cached else None
        if not head_branch:
            raise RuntimeError("Cannot establish the original existing HEAD branch")
    requested = (
        (["refs/heads/" + head_branch] if head_branch else ["HEAD"])
        if ref == "HEAD"
        else ["refs/heads/" + ref, "refs/tags/" + ref, "refs/tags/" + ref + "^{}"]
    )
    remote = remote_refs(cfg, *requested, symref=True)
    refs = {}
    branch = None
    for line in remote.splitlines():
        value, name = line.split("\t", 1)
        if value.startswith("ref: "):
            branch = value.removeprefix("ref: refs/heads/")
        else:
            refs[name] = value
    if ref == "HEAD":
        if head_branch and "refs/heads/" + head_branch in refs:
            return refs["refs/heads/" + head_branch], "branch", head_branch
        if "HEAD" in refs:
            return refs["HEAD"], "branch" if branch else "commit", branch
        raise RuntimeError("Cannot determine the original HEAD revision")
    # Match the original git module's branch preference, then annotated tag peel.
    for name, kind in [
        ("refs/heads/" + ref, "branch"),
        ("refs/tags/" + ref + "^{}", "tag"),
        ("refs/tags/" + ref, "tag"),
    ]:
        if name in refs:
            return refs[name], kind, ref if kind == "branch" else None
    if re.fullmatch("[0-9a-fA-F]{4,39}", ref):
        directory = Path(cfg["install_dir"])
        local = (
            git(directory, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}", required=False)
            if directory.exists()
            else None
        )
        if local and re.fullmatch("[0-9a-f]{40}", local):
            return local, "short-commit", None
        advertised = remote_refs(cfg)
        candidates = {line.split()[0] for line in advertised.splitlines() if line.split()[0].startswith(ref.lower())}
        if len(candidates) == 1:
            return candidates.pop(), "short-commit", None
        # A historical abbreviated commit may not be advertised. The original
        # scheduled fetch resolves it before checkout; do not mutate the host in
        # a fact or substitute the installed commit to manufacture a quiet plan.
        return None, "short-commit", None
    raise RuntimeError("Configured OTBR source ref was not found")


def plan(cfg):
    cfg = normalized_source(cfg)
    resolved, kind, branch = resolve(cfg)
    directory = Path(cfg["install_dir"])
    before = git(directory, "rev-parse", "HEAD", required=False) if directory.exists() else None
    remote = git(directory, "remote", "get-url", "origin", required=False) if before else None
    dirty = bool(git(directory, "status", "--porcelain", "--untracked-files=no", required=False)) if before else False
    submodules = git(directory, "submodule", "status", "--recursive", required=False) if before else None
    submodule_changed = bool(submodules and any(line[:1] in {"-", "+", "U"} for line in submodules.splitlines()))
    # A tracked change inside a submodule must not disappear from force-update
    # admission just because the superproject commit remains the same.
    if before and not submodule_changed:
        check = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(directory),
                "submodule",
                "foreach",
                "--quiet",
                "--recursive",
                "git diff-index --quiet HEAD --",
            ],
            capture_output=True,
            check=False,
        )
        submodule_changed = check.returncode != 0
    return {
        "before": before,
        "resolved": resolved,
        "kind": kind,
        "branch": branch,
        "resolution_pending_git_fetch": resolved is None,
        "changed": bool(before != resolved or remote != cfg["repo_url"] or dirty or submodule_changed),
        "tracked_dirty": dirty,
        "submodule_changed": submodule_changed,
    }


def apply(cfg):
    cfg = normalized_source(cfg)
    directory = Path(cfg["install_dir"])
    desired = cfg["_source"]
    if desired is None:
        resolved, kind, branch = resolve(cfg)
        desired = {"resolved": resolved, "kind": kind, "branch": branch}
    if not (directory / ".git").exists():
        cloned = subprocess.run(
            ["git", "clone", "--no-checkout", "--", cfg["repo_url"], str(directory)],
            capture_output=True,
            text=True,
            check=False,
        )
        if cloned.returncode:
            raise RuntimeError("OTBR source clone failed")
    else:
        git(directory, "remote", "set-url", "origin", cfg["repo_url"])
    git(directory, "fetch", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*")
    # Resolve at planning; do not silently install a different moving-main tip
    # after the explicit source effect map was inspected.
    resolved = desired["resolved"]
    if resolved is None:
        resolved = git(directory, "rev-parse", "--verify", "--end-of-options", cfg["repo_version"] + "^{commit}")
    if git(directory, "cat-file", "-t", resolved, required=False) != "commit":
        git(directory, "fetch", "origin", resolved)
    if desired["kind"] == "branch":
        git(directory, "checkout", "--force", "-B", desired["branch"], resolved)
        git(directory, "branch", "--set-upstream-to", "origin/" + desired["branch"], desired["branch"])
    else:
        git(directory, "checkout", "--force", "--detach", resolved)
    git(directory, "submodule", "sync", "--recursive")
    git(directory, "submodule", "update", "--init", "--recursive", "--force")
    if git(directory, "rev-parse", "HEAD") != resolved:
        raise RuntimeError("OTBR checkout differs from resolved source")


def packages_plan(request):
    # This is selected metadata only. python-apt was the original Ansible apt
    # module's OS dependency; memory-only caches must not create cache files.
    import fnmatch

    import apt
    import apt.progress.base
    import apt_pkg

    apt_pkg.init_config()
    apt_pkg.config.set("Dir::Cache::pkgcache", "")
    apt_pkg.config.set("Dir::Cache::srcpkgcache", "")
    apt_pkg.init_system()
    cache = apt.Cache(progress=apt.progress.base.OpProgress(), memonly=True)
    low = apt_pkg.Cache(apt.progress.base.OpProgress())
    specs = []
    for spec in request["packages"]:
        if ">=" in spec:
            name, version = spec.split(">=", 1)
            comparison = ">="
        elif "=" in spec:
            name, version = spec.split("=", 1)
            comparison = "="
        else:
            name, comparison, version = spec, "", ""
        if any(char in name for char in "*?[]!"):
            matches = [
                key
                for key in cache.keys()  # noqa: SIM118 -- apt.Cache iteration yields packages, keys() yields names
                if (":" in name or ":" not in key) and fnmatch.fnmatchcase(key, name)
            ]
            if not matches:
                raise ValueError("No selected OTBR packages match the declared name")
            # Original name-glob expansion emits names, not the attached version.
            specs.extend((key, "", "", key) for key in matches)
        else:
            specs.append((name, comparison, version, spec))
    result = {"install": [], "purge": [], "noop": []}
    for name, comparison, version, original in specs:
        if name not in cache:
            if request["present"]:
                # Let apt resolve a virtual package as the original module does.
                providers = cache.get_providing_packages(name)
                if not providers:
                    raise ValueError("No selected OTBR package candidate")
                if len(providers) == 1 and providers[0].is_installed:
                    result["noop"].append(name)
                else:
                    result["install"].append(original)
            else:
                result["noop"].append(name)
            continue
        package = cache[name]
        installed = low[name].current_state == apt_pkg.CURSTATE_INSTALLED
        installed_version = package.installed.version if installed else None
        try:
            has_files = bool(package.installed_files)
        except UnicodeDecodeError:
            has_files = True
        matched = bool(
            installed
            and (
                not comparison
                or (
                    fnmatch.fnmatchcase(installed_version, version)
                    if comparison == "="
                    else apt_pkg.version_compare(installed_version, version) >= 0
                )
            )
        )
        if not request["present"]:
            result["purge" if matched or (has_files and request["purge"]) else "noop"].append(original)
            continue
        policy = apt_pkg.Policy(low)
        policy.read_pinfile(apt_pkg.config.find_file("Dir::Etc::preferences"))
        policy.read_pindir(apt_pkg.config.find_file("Dir::Etc::preferencesparts"))
        if comparison == "=":
            policy.create_pin("Version", name, version, 1001)
        candidate = policy.get_candidate_ver(low[name])
        best = candidate.ver_str if candidate else None
        if best and (
            (comparison == "=" and not fnmatch.fnmatchcase(best, version))
            or (comparison == ">=" and apt_pkg.version_compare(best, version) < 0)
        ):
            best = None
        # Preserve the original apt module's matching-candidate upgrade for =,
        # including its historical wildcard behavior; unversioned/>= stay put.
        needed = (not matched and bool(best)) or (matched and comparison == "=" and best and best != installed_version)
        if needed:
            result["install"].append(name + "=" + best)
        elif matched:
            result["noop"].append(name)
        else:
            raise ValueError("No selected OTBR package version is installable")
    return result


if __name__ == "__main__":
    config = json.load(sys.stdin)
    if sys.argv[1] == "source-plan":
        print(json.dumps(plan(config)))
    elif sys.argv[1] == "source-apply":
        apply(config)
    elif sys.argv[1] == "packages-plan":
        try:
            value = packages_plan(config)
        except ModuleNotFoundError as error:
            value = {"error": "python-apt" if error.name in {"apt", "apt_pkg"} else "metadata"}
        except ValueError:
            value = {"error": "candidate"}
        except Exception:  # noqa: BLE001 -- return only a failure code; never expose target metadata diagnostics
            value = {"error": "metadata"}
        print(json.dumps(value))
    elif sys.argv[1] == "path-state":
        try:
            details = os.lstat(config["path"])
        except FileNotFoundError:
            value = None
        else:
            value = {"mode": details.st_mode, "uid": details.st_uid, "gid": details.st_gid}
        print(json.dumps(value))
    else:
        raise ValueError("Unknown OTBR source action")
