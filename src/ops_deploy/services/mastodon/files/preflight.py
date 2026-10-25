"""Read-only existing-install admission. Never runs application code as root."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


def require(ok):
    if not ok:
        raise ValueError("existing-install contract is not satisfied")


def main(payload):
    cfg = payload["config"]
    home = Path(cfg["home_path"])
    site = Path(cfg["site_path"])
    account = pwd.getpwnam("mastodon")
    require(account.pw_dir == str(home) and account.pw_uid != 0)
    for path in (home, site, site / ".git", site / "public/system", site / "vendor/bundle",
                 site / "node_modules", Path("/etc/mastodon"), Path("/etc/traefik/dynamic"),
                 Path("/var/lib/mastodon-nginx/body"), Path("/var/log/mastodon-nginx"), Path("/etc/systemd/system")):
        require(path.is_dir() and not path.is_symlink() and path.resolve() == path)
    destinations = [Path("/etc/systemd/system") / ("mastodon-" + name + ".service")
                    for name in ("web", "sidekiq", "streaming", "nginx")]
    destinations.extend([Path("/etc/mastodon/nginx.conf"), Path("/etc/traefik/dynamic/mastodon.yml")])
    for path in destinations:
        require(path.is_file() and not path.is_symlink() and path.resolve() == path)
    legacy_route = Path("/etc/traefik/dynamic/mastodon.traefik.yml")
    require(not legacy_route.exists() and not legacy_route.is_symlink())
    for name, digest in cfg["source_files"].items():
        path = site / name
        require(path.is_file() and not path.is_symlink())
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest)
    env = site / ".env.production"
    require(env.is_file() and not env.is_symlink())
    require(env.read_bytes() == base64.b64decode("".join(payload["environment_b64"].splitlines()), validate=True))
    require(env.stat().st_uid == account.pw_uid and stat.S_IMODE(env.stat().st_mode) == 0o600)
    # These are existing build products, not an invitation to build or migrate.
    require((site / "public/packs/manifest.json").is_file())
    require(any((site / "public/assets").glob(".sprockets-manifest*.json")))
    require((home / ".rbenv/versions" / cfg["ruby_version"] / "bin/ruby").is_file())
    versions = home / ".nvm/versions/node"
    matching = [p.name[1:] for p in versions.glob("v" + cfg["node_version"] + "*")
                if p.is_dir() and (p / "bin/node").is_file()
                and (p.name[1:] == cfg["node_version"] or p.name[1:].startswith(cfg["node_version"] + "."))]
    require(len(matching) == 1)
    cache = None
    if cfg.get("nginx_federation_cache_enabled", False):
        cache = Path("/var/cache/mastodon/nginx-federation")
        require(cache.is_dir() and not cache.is_symlink() and cache.resolve() == cache)
    def as_user(args):
        result = subprocess.run(["runuser", "-u", "mastodon", "--", *args],
                                capture_output=True, text=True, check=True)
        return result.stdout.strip()
    if cache is not None:
        as_user(["test", "-w", str(cache)])
        as_user(["test", "-x", str(cache)])
    require(as_user(["git", "--no-optional-locks", "-C", str(site), "rev-parse", "HEAD"]) == cfg["source_commit"])
    as_user(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(site), "diff",
             "--no-ext-diff", "--no-textconv", "--exit-code", "HEAD", "--"])
    require(as_user(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(site),
                     "status", "--porcelain", "--untracked-files=normal"]) == "")
    for unit in ("mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx",
                 "mastodon-maintenance.timer", "redis-server"):
        subprocess.run(["systemctl", "is-active", "--quiet", unit], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for unit in ("mastodon_web", "mastodon_sidekiq", "mastodon_streaming", "mastodon-maintenance.service"):
        result = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(result.returncode in (3, 4))
    print(matching[0])


if __name__ == "__main__":
    try:
        main(json.load(sys.stdin))
    except Exception:
        # No payload, environment, file content or application stderr may escape.
        print("mastodon: existing-install admission refused", file=sys.stderr)
        sys.exit(1)
