"""Mastodon-local release inspection/actions. No application code runs as root."""

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys

STATE = Path("/var/lib/ops-deploy-mastodon")
PROTECTED = (".env.production", "public/system", "vendor/bundle", "node_modules", ".bundle", "log", "tmp", ".git")


def require(value, message):
    if not value:
        raise ValueError(message)


def command(argv, *, environment=None, cwd=None, optional=False):
    result = subprocess.run(argv, env=environment, cwd=cwd, capture_output=True, text=True)
    if result.returncode and not optional:
        # Application stderr can contain env/credentials. Never echo it or argv.
        raise RuntimeError("Mastodon command failed; deployment remains incomplete")
    return result


def user(cfg, argv, *, shell=False, load_env=False, optional=False):
    path = (
        cfg["nvm_dir"]
        + "/versions/node/v"
        + cfg["node_version"]
        + "/bin:"
        + cfg["rbenv_root"]
        + "/bin:"
        + cfg["rbenv_root"]
        + "/shims:/usr/local/bin:/usr/bin:/bin"
    )
    exports = {
        "USER": "mastodon",
        "LOGNAME": "mastodon",
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "HOME": cfg["home_path"],
        "RBENV_ROOT": cfg["rbenv_root"],
        "RBENV_VERSION": cfg["ruby_version"],
        "RUBY_CONFIGURE_OPTS": cfg["ruby_configure_opts"],
        "NVM_DIR": cfg["nvm_dir"],
        "PATH": path,
    }
    script = argv if shell else shlex.join(argv)
    if load_env:
        script = "set -a; . " + shlex.quote(cfg["site_path"] + "/.env.production") + "; set +a; " + script
    script = "set -euo pipefail; cd " + shlex.quote(cfg["site_path"]) + "; " + script
    return command(
        [
            "runuser",
            "-u",
            "mastodon",
            "--",
            "env",
            "-i",
            *[k + "=" + v for k, v in exports.items()],
            "/bin/bash",
            "-c",
            script,
        ],
        optional=optional,
    )


def git(cfg, path, *args, optional=False):
    return user(
        cfg, ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(path), *args], optional=optional
    )


def safe_paths(cfg):
    account = pwd.getpwnam("mastodon")
    require(account.pw_uid != 0 and account.pw_dir == cfg["home_path"], "existing service identity differs")
    for name in ["home_path", "site_path"]:
        path = Path(cfg[name])
        require(path.is_dir() and not path.is_symlink() and path.resolve() == path, "unsafe existing installation path")
    for name in ["rbenv_root", "nvm_dir", "bundle_path"]:
        path = Path(cfg[name])
        require(not path.is_symlink() and path.resolve() == path, "unsafe runtime/dependency path")
    site = Path(cfg["site_path"])
    for suffix in PROTECTED:
        path = site / suffix
        require(not path.is_symlink() and path.resolve() == path, "retained path traverses a symlink")
    for value in cfg["source_tracked_paths"]:
        require(
            value and not Path(value).is_absolute() and ".." not in Path(value).parts, "invalid candidate tracked path"
        )
        require(
            value in {"log/.keep", "tmp/.keep"}
            or not any(value == p or value.startswith(p + "/") or p.startswith(value + "/") for p in PROTECTED),
            "candidate collides with retained data",
        )
    if STATE.exists() or STATE.is_symlink():
        require(
            STATE.is_dir()
            and not STATE.is_symlink()
            and STATE.stat().st_uid == 0
            and stat.S_IMODE(STATE.stat().st_mode) == 0o700,
            "unsafe release completion directory",
        )
        require(
            all(not p.is_symlink() and p.is_file() and p.stat().st_uid == 0 for p in STATE.iterdir()),
            "unsafe release completion entry",
        )
    for directory in (
        Path("/etc/systemd/system"),
        Path("/etc/mastodon"),
        Path("/etc/traefik/dynamic"),
        Path("/var/lib/mastodon-nginx/body"),
        Path("/var/log/mastodon-nginx"),
    ):
        require(
            directory.is_dir() and not directory.is_symlink() and directory.resolve() == directory,
            "existing managed configuration directory is missing or unsafe",
        )
    destinations = [
        Path("/etc/systemd/system") / ("mastodon-" + name + ".service")
        for name in ("web", "sidekiq", "streaming", "nginx")
    ]
    destinations += [
        Path("/etc/mastodon/nginx.conf"),
        Path("/etc/traefik/dynamic/mastodon.yml"),
        Path(cfg["maintenance_script_path"]),
    ]
    for kind in ("service", "timer"):
        destinations.append(
            Path(
                cfg["maintenance_" + kind + "_unit"]
                or (cfg["maintenance_unit_dir"] + "/" + cfg["maintenance_" + kind + "_name"] + "." + kind)
            )
        )
    for path in destinations:
        require(
            not path.is_symlink() and path.resolve() == path and (not path.exists() or path.is_file()),
            "managed destination is not a regular contained file",
        )
    legacy = Path("/etc/traefik/dynamic/mastodon.traefik.yml")
    require(not legacy.exists() and not legacy.is_symlink(), "legacy Mastodon route would conflict")
    if cfg["nginx_federation_cache_enabled"]:
        cache = Path("/var/cache/mastodon/nginx-federation")
        require(
            cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache,
            "existing federation cache directory is unsafe or missing",
        )
        user(cfg, ["test", "-w", str(cache)])
        user(cfg, ["test", "-x", str(cache)])
    return account


def state_read(name):
    path = STATE / name
    return json.loads(path.read_text()) if path.exists() else None


def state_write(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    path = STATE / name
    temporary = STATE / (name + ".new")
    with open(temporary, "w", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    descriptor = os.open(STATE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def debt(cache):
    state_write("pending-rollout", True)
    if cache:
        state_write("pending-cache-clear", True)


def fingerprint(cfg, keys):
    return hashlib.sha256(json.dumps({k: cfg[k] for k in keys}, sort_keys=True).encode()).hexdigest()


def source_state(cfg):
    site = Path(cfg["site_path"])
    require((site / ".git").is_dir(), "existing Git checkout is missing")
    tracked = git(cfg, site, "ls-tree", "-r", "--name-only", "-z", "HEAD").stdout.split("\x00")[:-1]
    for value in tracked:
        require(
            value in {"log/.keep", "tmp/.keep"}
            or not any(value == p or value.startswith(p + "/") or p.startswith(value + "/") for p in PROTECTED),
            "old tracked source collides with retained data",
        )
    for scaffold in ("log/.keep", "tmp/.keep"):
        if scaffold in cfg["source_tracked_paths"] and (site / scaffold).exists():
            require(scaffold in tracked, "candidate scaffold collides with an untracked retained file")
    head = git(cfg, site, "rev-parse", "HEAD").stdout.strip()
    dirty = git(cfg, site, "diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--", optional=True)
    require(dirty.returncode in (0, 1), "cannot establish tracked source state")
    remote = git(cfg, site, "remote", "get-url", "origin").stdout.strip()
    return head != cfg["source_commit"] or dirty.returncode == 1 or remote != cfg["git_repo"]


def source(cfg):
    debt(True)
    site = Path(cfg["site_path"])
    git(cfg, site, "remote", "set-url", "origin", cfg["git_repo"])
    git(cfg, site, "fetch", "--no-tags", "origin", cfg["git_ref"])
    require(
        git(cfg, site, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() == cfg["source_commit"],
        "selected source ref moved after controller resolution",
    )
    require(
        git(cfg, site, "ls-tree", "-r", "--name-only", "-z", "FETCH_HEAD").stdout.split("\x00")[:-1]
        == cfg["source_tracked_paths"],
        "candidate tracked paths differ",
    )
    git(cfg, site, "checkout", "--force", "--detach", cfg["source_commit"])
    verify_source(cfg)


def verify_source(cfg):
    require(not source_state(cfg), "selected source checkout is incomplete")
    for name, digest in cfg["source_files"].items():
        path = Path(cfg["site_path"]) / name
        require(
            path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            "candidate lock/runtime declaration differs",
        )


def tool_head(cfg, path):
    if not path.exists():
        return None
    require(path.is_dir() and not path.is_symlink() and path.resolve() == path, "unsafe runtime tool checkout")
    return git(cfg, path, "rev-parse", "HEAD").stdout.strip()


def node_resolved(cfg):
    script = ". " + shlex.quote(cfg["nvm_dir"] + "/nvm.sh") + "; nvm version " + shlex.quote(cfg["node_version"])
    if not (Path(cfg["nvm_dir"]) / "nvm.sh").is_file():
        return None
    result = user(cfg, script, shell=True, optional=True)
    value = result.stdout.strip().splitlines()[-1:] if result.returncode == 0 else []
    return value[0].removeprefix("v") if value and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value[0]) else None


def runtime_state(cfg):
    ruby = Path(cfg["rbenv_root"]) / "versions" / cfg["ruby_version"] / "bin/ruby"
    rb = tool_head(cfg, Path(cfg["rbenv_root"]))
    build = tool_head(cfg, Path(cfg["rbenv_root"]) / "plugins/ruby-build")
    nvm = Path(cfg["nvm_dir"])
    nh = tool_head(cfg, nvm)
    target = git(cfg, nvm, "rev-parse", cfg["nvm_version"] + "^{commit}", optional=True) if nh else None
    node = node_resolved(cfg)
    version = Path(cfg["rbenv_root"]) / "version"
    result = {
        "ruby": not ruby.is_file()
        or not rb
        or not build
        or not version.is_file()
        or version.read_text().strip() != cfg["ruby_version"],
        "ruby_tool": cfg["ruby_build_update"] and build != cfg["runtime_tool_commits"]["ruby_build"],
        "node": not node or not nh or target.returncode != 0 or target.stdout.strip() != nh,
        "node_version": node,
        "ruby_build_commit": build,
    }
    if ruby.is_file():
        actual = user(cfg, [str(ruby), "--version"]).stdout
        require(actual.startswith("ruby " + cfg["ruby_version"] + " "), "installed Ruby executable version differs")
    return result


def clone_tool(cfg, path, repo):
    if path.exists():
        require(git(cfg, path, "remote", "get-url", "origin").stdout.strip() == repo, "runtime tool repository differs")
    else:
        user(cfg, ["mkdir", "-p", str(path.parent)])
        user(cfg, ["git", "clone", "--", repo, str(path)])


def ruby(cfg):
    root = Path(cfg["rbenv_root"])
    clone_tool(cfg, root, cfg["rbenv_repo"])
    build = root / "plugins/ruby-build"
    clone_tool(cfg, build, cfg["ruby_build_repo"])
    if cfg["ruby_build_update"]:
        wanted = cfg["runtime_tool_commits"]["ruby_build"]
        git(cfg, build, "fetch", "--no-tags", "origin", wanted)
        require(
            git(cfg, build, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() == wanted,
            "ruby-build execution input differs",
        )
        git(cfg, build, "checkout", "--detach", wanted)
    if not (root / "versions" / cfg["ruby_version"] / "bin/ruby").is_file():
        debt(True)
        user(cfg, [str(root / "bin/rbenv"), "install", "-s", cfg["ruby_version"]])
    version = root / "version"
    if not version.is_file() or version.read_text().strip() != cfg["ruby_version"]:
        debt(True)
        user(cfg, [str(root / "bin/rbenv"), "global", cfg["ruby_version"]])
    user(cfg, [str(root / "bin/rbenv"), "rehash"])
    require(not runtime_state(cfg)["ruby"] and not runtime_state(cfg)["ruby_tool"], "Ruby convergence is incomplete")


def node(cfg):
    root = Path(cfg["nvm_dir"])
    clone_tool(cfg, root, cfg["nvm_repo"])
    git(cfg, root, "fetch", "--tags", "origin", cfg["nvm_version"])
    git(cfg, root, "checkout", "--detach", cfg["nvm_version"])
    if not node_resolved(cfg):
        debt(True)
        script = (
            ". "
            + shlex.quote(str(root / "nvm.sh"))
            + "; nvm install "
            + shlex.quote(cfg["node_version"])
            + "; nvm alias default "
            + shlex.quote(cfg["node_version"])
        )
        user(cfg, script, shell=True)
    require(node_resolved(cfg) is not None, "Node convergence is incomplete")


def desired_env(payload):
    content = base64.b64decode("".join(payload["environment_b64"].splitlines()), validate=True).decode()
    result = {}
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values = shlex.split(value)
        result[key] = values[0] if len(values) == 1 else value
    return result


def database_versions(payload):
    values = desired_env(payload)
    environment = os.environ.copy()
    environment.update(
        PGHOST=values["DB_HOST"],
        PGPORT=values["DB_PORT"],
        PGUSER=values["DB_USER"],
        PGDATABASE=values["DB_NAME"],
        PGPASSWORD=values["DB_PASS"],
        PGOPTIONS="-c default_transaction_read_only=on",
    )
    result = command(
        [
            "runuser",
            "-u",
            "mastodon",
            "--",
            "psql",
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT version FROM schema_migrations ORDER BY version",
        ],
        environment=environment,
    )
    versions = result.stdout.splitlines()
    require(
        all(re.fullmatch(r"[0-9]+", value) for value in versions),
        "cannot establish existing database migration identities",
    )
    return versions


def redis_ready(payload):
    from urllib.parse import urlsplit, unquote

    values = desired_env(payload)
    url = urlsplit(values["REDIS_URL"])
    require(
        url.scheme == "redis" and url.hostname in ("localhost", "127.0.0.1", "::1"), "existing local Redis is required"
    )
    environment = os.environ.copy()
    if url.password:
        environment["REDISCLI_AUTH"] = unquote(url.password)
    result = command(
        [
            "runuser",
            "-u",
            "mastodon",
            "--",
            "redis-cli",
            "--no-auth-warning",
            "-h",
            url.hostname,
            "-p",
            str(url.port or 6379),
            "-n",
            url.path.lstrip("/") or "0",
            "PING",
        ],
        environment=environment,
    )
    require(result.stdout.strip() == "PONG", "existing Redis is not ready")


def bundle_key(cfg):
    return fingerprint(
        cfg,
        [
            "source_commit",
            "source_files",
            "ruby_version",
            "bundle_path",
            "bundle_without",
            "bundle_jobs",
            "bundle_retry",
            "bundle_deployment",
        ],
    )


def yarn_key(cfg):
    return fingerprint(
        cfg, ["source_commit", "source_files", "node_version", "yarn_use_corepack", "yarn_global_install", "yarn_flags"]
    )


def assets_key(cfg):
    return fingerprint(cfg, ["source_commit", "source_files", "ruby_version", "node_version"])


def yarn_output(cfg):
    site = Path(cfg["site_path"])
    return (site / "node_modules").is_dir() and any(
        p.is_file()
        for p in (
            site / "node_modules/.yarn-state.yml",
            site / "node_modules/.yarn-integrity",
            site / ".yarn/install-state.gz",
        )
    )


def assets_output(cfg):
    site = Path(cfg["site_path"])
    public = site / "public"
    lock = (site / "Gemfile.lock").read_text()
    try:
        if "    propshaft (" in lock:
            manifest = public / "assets/.manifest.json"
            if not manifest.is_file():
                return False
            data = json.loads(manifest.read_text())
            require(isinstance(data, dict), "Propshaft manifest is invalid")
            for entry in data.values():
                value = entry.get("digested_path") if isinstance(entry, dict) else entry
                require(isinstance(value, str), "Propshaft entry has no digested path")
                path = public / "assets" / value
                require(
                    path.is_file() and path.resolve().is_relative_to(public / "assets"),
                    "compiled Propshaft asset is absent",
                )
        else:
            manifests = list((public / "assets").glob(".sprockets-manifest*.json"))
            if not manifests:
                return False
            for manifest in manifests:
                data = json.loads(manifest.read_text())
                for value in data.get("assets", {}).values():
                    path = public / "assets" / value
                    require(
                        path.is_file() and path.resolve().is_relative_to(public / "assets"),
                        "compiled Sprockets asset is absent",
                    )
        vite_config = site / "config/vite.json"
        if vite_config.is_file():
            settings = json.loads(vite_config.read_text())
            merged = {**settings.get("all", {}), **settings.get("production", {})}
            output = merged.get("publicOutputDir", "vite")
            packs = public / output
            require(packs.resolve().is_relative_to(public), "Vite output path leaves public directory")
            manifest = packs / ".vite/manifest.json"
            if not manifest.is_file():
                return False
            entries = json.loads(manifest.read_text())
            require(isinstance(entries, dict) and bool(entries), "Vite manifest is empty")
            for entry in entries.values():
                require(isinstance(entry, dict) and isinstance(entry.get("file"), str), "Vite entry is invalid")
                for value in [entry["file"], *entry.get("css", []), *entry.get("assets", [])]:
                    path = packs / value
                    require(path.is_file() and path.resolve().is_relative_to(packs), "compiled Vite asset is absent")
        elif "    webpacker (" in lock:
            manifest = public / "packs/manifest.json"
            if not manifest.is_file():
                return False
            entries = json.loads(manifest.read_text())
            require(isinstance(entries, dict) and bool(entries), "Webpack manifest is empty")
            for value in entries.values():
                if isinstance(value, str) and value.startswith("/packs/"):
                    path = public / value.lstrip("/")
                    require(path.is_file() and path.resolve().is_relative_to(public), "compiled pack is absent")
        return True
    except (ValueError, OSError, TypeError, KeyError):
        return False


def dependencies_state(cfg, runtime):
    ruby_ready = not runtime["ruby"]
    node_ready = not runtime["node"]
    bundle_current = (
        state_read("bundle") == bundle_key(cfg)
        and ruby_ready
        and user(cfg, ["bundle", "check", "--dry-run"], optional=True).returncode == 0
    )
    yarn_current = state_read("yarn") == yarn_key(cfg) and node_ready and yarn_output(cfg)
    return {
        "bundle": cfg["bundle_install"] and not bundle_current,
        "yarn": cfg["yarn_install"] and not yarn_current,
        "assets": cfg["precompile_assets"] and (state_read("assets") != assets_key(cfg) or not assets_output(cfg)),
    }


def bundle(cfg):
    debt(True)
    user(cfg, ["bundle", "config", "set", "--local", "path", cfg["bundle_path"]])
    user(cfg, ["bundle", "config", "set", "--local", "without", cfg["bundle_without"]])
    if cfg["bundle_deployment"]:
        user(cfg, ["bundle", "config", "set", "--local", "deployment", "true"])
    user(cfg, ["bundle", "install", "--jobs", str(cfg["bundle_jobs"]), "--retry", str(cfg["bundle_retry"])])
    verify_source(cfg)
    user(cfg, ["bundle", "check", "--dry-run"])
    state_write("bundle", bundle_key(cfg))


def yarn(cfg):
    debt(True)
    if cfg["yarn_use_corepack"]:
        user(cfg, ["corepack", "enable"])
    elif cfg["yarn_global_install"]:
        user(cfg, ["npm", "install", "-g", "yarn"])
    user(cfg, ["yarn", "install", *shlex.split(cfg["yarn_flags"])])
    verify_source(cfg)
    require(yarn_output(cfg), "Yarn install did not produce its installed output")
    state_write("yarn", yarn_key(cfg))


def migrate(payload):
    cfg = payload["config"]
    before = database_versions(payload)
    pending = sorted(set(cfg["migration_versions"]) - set(before))
    if pending:
        debt(True)
        # Confirm status with the candidate runtime/gems only after install.
        user(cfg, ["bundle", "exec", "rails", "db:migrate:status"], load_env=True)
        user(cfg, ["bundle", "exec", "rails", "db:migrate"], load_env=True)
    after = database_versions(payload)
    require(
        set(cfg["migration_versions"]).issubset(after),
        "candidate migrations remain pending, including post-deployment identities",
    )
    require(set(before).issubset(after), "existing migration history was removed")


def assets(cfg):
    debt(True)
    user(cfg, ["bundle", "exec", "rails", "assets:precompile"], load_env=True)
    verify_source(cfg)
    require(assets_output(cfg), "asset precompile did not produce complete manifests/output")
    state_write("assets", assets_key(cfg))


def cache_clear(cfg):
    if state_read("pending-cache-clear"):
        if cfg["clear_rails_cache_on_deploy"]:
            user(cfg, ["bin/tootctl", "cache", "clear"], load_env=True)
        (STATE / "pending-cache-clear").unlink()


def inspect(payload):
    cfg = payload["config"]
    runtime = runtime_state(cfg)
    versions = database_versions(payload)
    redis_ready(payload)
    env = Path(cfg["site_path"]) / ".env.production"
    require(not env.is_symlink() and env.is_file(), "existing environment file is missing or unsafe")
    account = pwd.getpwnam("mastodon")
    desired = base64.b64decode("".join(payload["environment_b64"].splitlines()), validate=True)
    env_changed = (
        env.read_bytes() != desired or env.stat().st_uid != account.pw_uid or stat.S_IMODE(env.stat().st_mode) != 0o600
    )
    pending = sorted(set(cfg["migration_versions"]) - set(versions))
    return {
        "source": source_state(cfg),
        "runtime": runtime,
        "dependencies": dependencies_state(cfg, runtime),
        "env": env_changed,
        "pending_migrations": pending,
        "applied_migrations": versions,
        "rollout_debt": bool(state_read("pending-rollout")),
        "cache_clear_debt": bool(state_read("pending-cache-clear")),
        "prime": prime_needed(cfg),
    }


def prime_items(cfg):
    items = []
    default_hosts = cfg["nginx_federation_cache_prime_hosts"] or [cfg["web_domain"]]
    for entry in cfg["nginx_federation_cache_prime"] + cfg["nginx_federation_cache_prime_extra"]:
        hosts = [entry["host"]] if "host" in entry else list(default_hosts)
        if "host" not in entry and cfg["traefik_local_domain_wellknown"] and entry["path"].startswith("/.well-known/"):
            hosts.append(cfg["local_domain"])
        items.extend({"host": host, "path": entry["path"], "accept": entry["accept"]} for host in dict.fromkeys(hosts))
    return items


def prime_key(cfg):
    return fingerprint(
        cfg,
        [
            "source_commit",
            "web_domain",
            "local_domain",
            "traefik_local_domain_wellknown",
            "nginx_federation_cache_prime",
            "nginx_federation_cache_prime_extra",
            "nginx_federation_cache_prime_hosts",
        ],
    )


def cache_file(item):
    accept = item["accept"].lower()
    if re.search(r"application/(activity|ld)\+json", accept):
        normalized = "application/activity+json"
    elif "application/jrd+json" in accept:
        normalized = "application/jrd+json"
    elif re.search(r"application/xrd\+xml|application/xml|text/xml", accept):
        normalized = "application/xrd+xml"
    elif "json" in accept:
        normalized = "application/json"
    elif "text/html" in accept:
        normalized = "text/html"
    else:
        normalized = ""
    key = "https://" + item["host"] + item["path"] + "|" + normalized + "|"
    digest = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()
    return Path("/var/cache/mastodon/nginx-federation") / digest[-1] / digest[-3:-1] / digest


def prime_needed(cfg):
    return cfg["nginx_federation_cache_enabled"] and (
        state_read("prime") != prime_key(cfg) or not all(cache_file(item).is_file() for item in prime_items(cfg))
    )


def prime(cfg):
    import urllib.request
    import time

    for item in prime_items(cfg):
        request = urllib.request.Request(
            "http://127.0.0.1:10044" + item["path"],
            headers={"X-Forwarded-Host": item["host"], "X-Forwarded-Proto": "https", "Accept": item["accept"]},
        )
        for attempt in range(6):
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    require(response.status == 200, "cache fill health failed")
                break
            except Exception:
                if attempt == 5:
                    raise ValueError("federation cache fill failed") from None
                time.sleep(5)
        with urllib.request.urlopen(request, timeout=10) as response:
            require(
                response.status == 200
                and response.headers.get("X-Cache-Status") in ("HIT", "STALE", "UPDATING", "REVALIDATED"),
                "federation second-request cache check failed",
            )
    state_write("prime", prime_key(cfg))


def verify_cache(cfg):
    # No completion marker writes during converged verification.
    import urllib.request

    for item in prime_items(cfg):
        request = urllib.request.Request(
            "http://127.0.0.1:10044" + item["path"],
            headers={"X-Forwarded-Host": item["host"], "X-Forwarded-Proto": "https", "Accept": item["accept"]},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            require(
                response.status == 200
                and response.headers.get("X-Cache-Status") in ("HIT", "STALE", "UPDATING", "REVALIDATED"),
                "existing federation cache verification failed",
            )


def health(cfg):
    import urllib.request
    import time

    for unit in ("mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx"):
        command(["systemctl", "is-active", "--quiet", unit])
    request = urllib.request.Request(
        "http://127.0.0.1:10044/api/v1/instance", headers={"Host": cfg["web_domain"], "X-Forwarded-Proto": "https"}
    )
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                require(response.status == 200, "instance health failed")
            return
        except Exception:
            if attempt == 5:
                raise ValueError("instance health failed") from None
            time.sleep(5)


if __name__ == "__main__":
    try:
        payload = json.load(sys.stdin)
        cfg = payload["config"]
        safe_paths(cfg)
        action = sys.argv[1]
        if action == "runtime-inspect":
            print(json.dumps(runtime_state(cfg)))
        elif action == "inspect":
            print(json.dumps(inspect(payload)))
        elif action == "migrate":
            migrate(payload)
        elif action == "env-debt":
            debt(False)
        elif action == "complete":
            require(not state_read("pending-cache-clear"), "cache clear remains incomplete")
            if (STATE / "pending-rollout").exists():
                (STATE / "pending-rollout").unlink()
        elif action in (
            "source",
            "ruby",
            "node",
            "bundle",
            "yarn",
            "assets",
            "cache_clear",
            "prime",
            "verify_cache",
            "health",
        ):
            globals()[action](cfg)
        else:
            raise ValueError("unknown Mastodon release action")
    except Exception as error:
        # Never log payload, environment, app stdout/stderr or credential digests.
        message = str(error) if isinstance(error, ValueError) else "action failed; deployment remains incomplete"
        print("mastodon release: " + message, file=sys.stderr)
        sys.exit(1)
