"""Real VM caller-chain. Never imported by ordinary unit-test collection."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
from base64 import urlsafe_b64encode
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any

HOME = Path("/home/mastodon")
SITE = HOME / "live"
UNITS = ("web", "sidekiq", "streaming", "nginx")
MASTODON_COMMIT = "32e8e7c70af88c7ff12d2db03fcc93aa777a8cfc"
RUBY_BUILD = "b6a92c15f0df872047c74f7dfa0b92dfd4de8a92"
RBENV = "07e9b1e297a5977298c6aadc9971ae0e9eb7f0dc"
NVM = "8db529c5350353f165e1e7f6abb6eb6909f7fd37"
OLD_RUBY = "4.0.4"
OLD_NODE = "24.16.0"


def generate_fixture_keys(path: Path) -> None:
    """Use the locked controller crypto library before any runtime compile."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = ec.generate_private_key(ec.SECP256R1())
    values = {
        "vapid_private_key": key.private_numbers().private_value.to_bytes(32, "big"),
        "vapid_public_key": key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump({name: urlsafe_b64encode(value).decode().rstrip("=") for name, value in values.items()}, output)


def fixture_failure_output(stdout: str, stderr: str) -> str:
    """Bound dummy-VM diagnostics; never echo generated fixture keys or env dumps."""
    values = {"a" * 64, "fixture-database-only"}
    try:
        vapid = HOME / "vapid.json"
        data = json.loads(vapid.read_text())
        values.update(data.values())
    except (OSError, ValueError, TypeError, AttributeError):
        return "tool output withheld: fixture key metadata unavailable"
    sections = []
    for label, content in (("stdout", stdout), ("stderr", stderr)):
        for value in values:
            if isinstance(value, str) and value:
                content = content.replace(value, "[redacted fixture value]")
        lines = []
        for line in content.splitlines():
            if re.search(r"(?:^|\s)(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=", line):
                continue
            if re.search(r"authorization|cookie|password|secret|(?:access|auth)[_-]?token", line, re.I):
                continue
            lines.append(re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", line))
        sections.append(label + ":\n" + "\n".join(lines)[-2000:])
    return "\n".join(sections)


def command(*args: str, user: bool = False) -> str:
    environment = {
        "HOME": str(HOME),
        "USER": "mastodon",
        "LOGNAME": "mastodon",
        "SHELL": "/bin/bash",
        "LANG": "C.UTF-8",
        "RBENV_ROOT": str(HOME / ".rbenv"),
        "NVM_DIR": str(HOME / ".nvm"),
        "PATH": os.environ.get("NODE_BOOTSTRAP_DIR", "/usr/bin") + ":/usr/local/bin:/usr/bin:/bin",
    }
    # Reproduce CI's package-manager behavior, without inheriting runner caches,
    # shell hooks, credentials or runtime/Git configuration.
    environment.update({name: os.environ[name] for name in ("CI", "GITHUB_ACTIONS") if name in os.environ})
    argv = ["runuser", "-u", "mastodon", "--", "env", "-i", *[k + "=" + v for k, v in environment.items()], *args]
    if not user:
        argv = list(args)
        if len(args) > 2 and args[:2] == ("git", "-C"):
            argv = ["git", "-c", "safe.directory=" + args[2], *args[1:]]
    result = subprocess.run(argv, cwd=HOME if user else None, text=True, capture_output=True, check=False)
    if result.returncode:
        # Only fixture data; generated key output is never logged on success.
        raise RuntimeError(
            f"{args[0]} failed ({result.returncode}):\n" + fixture_failure_output(result.stdout, result.stderr)
        )
    return result.stdout.strip()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def fixture(source: Path, ruby: str, node: str) -> None:
    """A real small Rails/PostgreSQL/Redis app, not a fake Mastodon build."""
    # Exact versions from selected Mastodon32e8 lock; no guessed latest stack.
    files = {
        ".gitignore": (
            "/.env.production\n/.bundle/\n/node_modules/\n/vendor/bundle/\n"
            "/public/system/\n/public/assets/\n/tmp/\n/log/\n/.yarn/install-state.gz\n"
        ),
        ".ruby-version": ruby + "\n",
        ".nvmrc": node + "\n",
        "Gemfile": """source "https://rubygems.org"
gem "rails", "= 8.1.3.1"
gem "pg", "= 1.6.3"
gem "puma", "= 8.0.2"
gem "sidekiq", "= 8.1.6"
gem "redis", "= 5.4.1"
gem "propshaft", "= 1.3.2"
""",
        "package.json": (
            '{"name":"release-fixture","private":true,"packageManager":"yarn@4.16.0","dependencies":{"ws":"8.18.3"}}\n'
        ),
        ".yarnrc.yml": "nodeLinker: node-modules\n",
        "Rakefile": """require_relative "config/application"
Rails.application.load_tasks
Rake::Task["assets:precompile"].enhance do
  if File.exist?("/home/mastodon/fail-assets")
    File.write("/home/mastodon/asset-fault-observed", "real task executed")
    abort "deliberate real asset task failure"
  end
end
""",
        "config/boot.rb": (
            'ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)\nrequire "bundler/setup"\n'
        ),
        "config/application.rb": """require_relative "boot"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
Bundler.require(*Rails.groups)
module ReleaseFixture
  class Application < Rails::Application
    config.load_defaults 8.1
    config.eager_load = true
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE")
    config.hosts.clear
    config.cache_store = :redis_cache_store, {url: ENV.fetch("REDIS_URL")}
    config.active_record.dump_schema_after_migration = false
    config.active_support.deprecation = :stderr
    config.assets.paths << Rails.root.join("app/assets")
  end
end
""",
        "config/environment.rb": 'require_relative "application"\nRails.application.initialize!\n',
        "config/database.yml": """production:
  adapter: postgresql
  host: <%= ENV.fetch("DB_HOST") %>
  database: <%= ENV.fetch("DB_NAME") %>
  username: <%= ENV.fetch("DB_USER") %>
  password: <%= ENV.fetch("DB_PASS") %>
""",
        "config/puma.rb": 'bind "tcp://127.0.0.1:#{ENV.fetch("PORT")}"\nenvironment "production"\n',
        "config/routes.rb": """Rails.application.routes.draw do
  get "/api/v1/instance", to: proc { [200, {"content-type" => "application/json"}, ["{}"]] }
end
""",
        "config.ru": 'require_relative "config/environment"\nrun Rails.application\n',
        "app/assets/fixture.css": "body { color: black; }\n",
        "db/migrate/20250101000000_create_widgets.rb": """class CreateWidgets < ActiveRecord::Migration[8.1]
  def change
    create_table :widgets do |t|
      t.string :name
    end
  end
end
""",
        "bin/rails": (
            '#!/usr/bin/env ruby\nAPP_PATH = File.expand_path("../config/application", __dir__)\n'
            'require_relative "../config/boot"\nrequire "rails/commands"\n'
        ),
        "bin/tootctl": """#!/usr/bin/env ruby
require_relative "../config/environment"
abort "fixture supports actual Rails cache clear only" unless ARGV == ["cache", "clear"]
Rails.cache.clear
""",
        "streaming/index.js": """const http = require('node:http');
require('ws');
http.createServer((req,res) => { res.writeHead(200); res.end('ok'); }).listen(Number(process.env.PORT),'127.0.0.1');
""",
    }
    for name, content in files.items():
        write(source / name, content)
    for name in ("bin/rails", "bin/tootctl"):
        (source / name).chmod(0o755)


def git_commit(source: Path, message: str, *, user: bool = False) -> str:
    command("git", "-C", str(source), "add", ".", user=user)
    command(
        "git",
        "-C",
        str(source),
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        message,
        user=user,
    )
    return command("git", "-C", str(source), "rev-parse", "HEAD", user=user)


def config(source: Path, repo: str, ref: str) -> dict[str, Any]:
    commit = command("git", "-C", str(source), "rev-parse", "HEAD")
    tracked = command("git", "-C", str(source), "ls-tree", "-r", "--name-only", commit).splitlines()
    migrations = sorted(
        {Path(p).name.split("_", 1)[0] for p in tracked if re.fullmatch(r"db/(?:post_)?migrate/[0-9]+_[^/]+\.rb", p)}
    )
    names = ("Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc")
    return dict(
        site_path=str(SITE),
        home_path=str(HOME),
        local_domain="social.example.test",
        web_domain="social.example.test",
        source_commit=commit,
        ruby_version=(source / ".ruby-version").read_text().strip(),
        node_version=(source / ".nvmrc").read_text().strip().removeprefix("v"),
        source_files={n: hashlib.sha256((source / n).read_bytes()).hexdigest() for n in names},
        smtp_server="smtp.example.test",
        smtp_login="fixture@example.test",
        smtp_from_address="fixture@example.test",
        smtp_domain="example.test",
        git_repo=repo,
        git_ref=ref,
        source_tracked_paths=tracked,
        migration_versions=migrations,
        runtime_tool_commits={"ruby_build": RUBY_BUILD},
        maintenance_timer_enabled=False,
        web_concurrency=1,
        max_threads=2,
        sidekiq_concurrency=2,
        db_pool=5,
    )


def secrets() -> Any:
    from ops_deploy.core.secrets import SecretRef, SecretValues
    from ops_deploy.services.mastodon.render import SECRET_KEYS

    values = {key: "a" * 64 for key in SECRET_KEYS}
    values["postgres_password"] = "fixture-database-only"
    # A real VAPID P-256 pair is generated for the actual Mastodon app below.
    vapid = HOME / "vapid.json"
    if vapid.exists():
        values.update(json.loads(vapid.read_text()))
    return SecretValues(SecretRef("fixture.yml"), values)


def deploy(cfg: dict[str, Any], evidence: Path, label: str, *, fails: bool = False) -> None:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    api = import_module("ops_deploy.services.mastodon")
    release_config = api.MastodonReleaseConfig
    deploy_mastodon = api.deploy_mastodon
    from ops_deploy.testing.harness import collect_ops

    state = State(Inventory(([("@local", {})], {})), Config())
    error: Exception | None = None
    try:
        connect_all(state)
        if len(state.activated_hosts) != 1:
            raise AssertionError("one real local connector required")
        add_deploy(state, deploy_mastodon, cfg=release_config(**cfg), secrets=secrets())
        run_ops(state)
    except Exception as exc:
        error = exc
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
    # Avoid serializing op.args: secret delivery commands can contain dummy values.
    result = dict(
        operations=[{k: v for k, v in asdict(op).items() if k != "args"} for op in ops],
        exception_type=type(error).__name__ if error else None,
    )
    write(evidence / f"{label}.json", json.dumps(result, indent=2))
    success = error is None and bool(ops) and all(op.succeeded for op in ops)
    if fails:
        if success:
            raise AssertionError("deliberate failing build unexpectedly succeeded")
        asset_indexes = [
            index
            for index, op in enumerate(ops)
            if op.name.endswith("Build and verify selected Mastodon production assets") and not op.succeeded
        ]
        if len(asset_indexes) != 1 or not all(op.succeeded for op in ops[: asset_indexes[0]]):
            raise AssertionError("expected the real named asset operation to fail after successful prior operations")
    else:
        if not (success):
            raise AssertionError(f"{label}: see private operation evidence; {type(error).__name__}")
    if label.endswith("repeat") and [op.name for op in ops if op.changed and not op.read_only]:
        raise AssertionError(result)


def services() -> dict[str, str]:
    result = {}
    for name in UNITS:
        unit = f"mastodon-{name}.service"
        if not (command("systemctl", "is-active", unit) == "active"):
            raise AssertionError("integration invariant failed")
        result[name] = command("systemctl", "show", unit, "-p", "MainPID", "-p", "InvocationID", "-p", "NRestarts")
        if not ("MainPID=0\n" not in result[name] + "\n"):
            raise AssertionError("integration invariant failed")
    return result


def running_runtimes(cfg: dict[str, Any]) -> dict[str, str]:
    result = {}
    for component, language in (("streaming", "node"), ("web", "ruby")):
        pid = command("systemctl", "show", "--value", "-p", "MainPID", f"mastodon-{component}.service")
        executable = Path("/proc") / pid / "exe"
        target = executable.resolve()
        expected_store = HOME / (".nvm/versions/node" if language == "node" else ".rbenv/versions")
        if not target.is_relative_to(expected_store):
            raise AssertionError("running service executable is outside its managed runtime store")
        actual = command(str(executable), "--version")
        if language == "node":
            expected = str(cfg["node_version"]).split(".")
            if actual.removeprefix("v").split(".")[: len(expected)] != expected:
                raise AssertionError("streaming runs a different Node version from selected source")
        elif not re.match(r"ruby " + re.escape(str(cfg["ruby_version"])) + r"(?: |$)", actual):
            raise AssertionError("web runs a different Ruby version from selected source")
        result[language] = actual
    return result


def protected() -> dict[str, str]:
    return {
        name: hashlib.sha256((SITE / name).read_bytes()).hexdigest()
        for name in ("public/system/protected.bin", "vendor/bundle/retained.bin")
    }


def pair(cfg: dict[str, Any], evidence: Path, label: str) -> None:
    before = protected()
    deploy(cfg, evidence, label + "-first")
    if not (protected() == before):
        raise AssertionError("integration invariant failed")
    first = services()
    runtime_versions = running_runtimes(cfg)
    default_alias = (HOME / ".nvm/alias/default").read_text().strip()
    expected_node = str(cfg["node_version"]).split(".")
    if default_alias.removeprefix("v").split(".")[: len(expected_node)] != expected_node:
        raise AssertionError("managed installer did not select requested Node as default")
    env_hash = hashlib.sha256((SITE / ".env.production").read_bytes()).hexdigest()
    history = command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-Atc",
        "SELECT version FROM schema_migrations ORDER BY version",
    )
    deploy(cfg, evidence, label + "-repeat")
    if running_runtimes(cfg) != runtime_versions:
        raise AssertionError("running runtime versions changed on repeat")
    if not (services() == first):
        raise AssertionError("integration invariant failed")
    if not (protected() == before):
        raise AssertionError("integration invariant failed")
    if not (hashlib.sha256((SITE / ".env.production").read_bytes()).hexdigest() == env_hash):
        raise AssertionError("integration invariant failed")
    if not (
        command(
            "runuser",
            "-u",
            "postgres",
            "--",
            "psql",
            "-d",
            "mastodon",
            "-Atc",
            "SELECT version FROM schema_migrations ORDER BY version",
        )
        == history
    ):
        raise AssertionError("integration invariant failed")
    check_http(actual=label.startswith("actual-mastodon"))
    if not (set(cfg["migration_versions"]).issubset(set(history.splitlines()))):
        raise AssertionError("integration invariant failed")
    write(
        evidence / f"{label}-proof.json",
        json.dumps(
            dict(
                protected_equal=True,
                services_stable=True,
                services=first,
                running_versions=runtime_versions,
                nvm_default_alias=default_alias,
                candidate_commit=cfg["source_commit"],
            ),
            indent=2,
        ),
    )


def seed_protected() -> None:
    write(SITE / "public/system/protected.bin", "owned VM media sentinel\n")
    write(SITE / "vendor/bundle/retained.bin", "owned VM dependency sentinel\n")
    command("chown", "-R", "mastodon:mastodon", str(SITE))


def check_http(*, actual: bool) -> None:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    request = urllib.request.Request(
        "http://127.0.0.1:10044/api/v1/instance", headers={"Host": "social.example.test", "X-Forwarded-Proto": "https"}
    )
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        if not (response.status == 200):
            raise AssertionError("integration invariant failed")
        body = json.load(response)
        if not (isinstance(body, dict)):
            raise AssertionError("integration invariant failed")
        if actual and not (body["uri"] == "social.example.test"):
            raise AssertionError("integration invariant failed")


def create_vm_marker(path: Path, run_id: str, machine_id: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(dict(run_id=run_id, machine_id=machine_id), output)


def safety_require(condition: bool, reason: str) -> None:
    if not condition:
        raise SystemExit("Unsafe integration environment: " + reason)


def assert_owned_vm() -> None:
    safety_require(os.getuid() == 0, "root required on owned ephemeral VM")
    safety_require(os.environ.get("GITHUB_ACTIONS") == "true", "GitHub runner required")
    safety_require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "self-hosted runner forbidden")
    safety_require(Path("/proc/1/comm").read_text().strip() == "systemd", "systemd VM required")
    marker = Path("/var/tmp/mastodon-release-owned-vm.json")
    safety_require(marker.is_file() and (not marker.is_symlink()), "owned VM marker missing or symlinked")
    safety_require(marker.stat().st_uid == 0, "marker must be root owned")
    safety_require(stat.S_IMODE(marker.stat().st_mode) == 384, "marker must be mode0600")
    identity = json.loads(marker.read_text())
    safety_require(identity["run_id"] == os.environ["GITHUB_RUN_ID"], "GitHub run marker mismatch")
    safety_require(identity["machine_id"] == Path("/etc/machine-id").read_text().strip(), "VM identity mismatch")


def preserve_runner_nvm(home: Path, evidence: Path, service_uid: int) -> Path | None:
    """Preserve the image-created leaf without reading contents or following links."""
    safety_require(home.is_dir() and not home.is_symlink(), "fixture HOME must be a real directory")
    safety_require(home.stat().st_uid == service_uid, "fixture HOME must belong to the new service user")
    target = home / ".nvm"
    if not target.exists() and not target.is_symlink():
        write(evidence / "image-nvm.json", json.dumps(dict(present=False)))
        return None
    metadata = target.lstat()
    safety_require(metadata.st_uid in (0, service_uid), "unexpected image nvm owner")
    saved = home / (".nvm-image-baseline-" + uuid.uuid4().hex)
    entries = []
    if stat.S_ISDIR(metadata.st_mode):
        for entry in sorted(target.iterdir()):
            leaf = entry.lstat()
            entries.append(dict(name=entry.name, mode=stat.S_IFMT(leaf.st_mode), owner=leaf.st_uid))
    write(
        evidence / "image-nvm.json",
        json.dumps(
            dict(
                present=True,
                owner=metadata.st_uid,
                mode=stat.S_IFMT(metadata.st_mode),
                entries=entries,
                preserved_as=saved.name,
            ),
            indent=2,
        ),
    )
    target.rename(saved)
    return saved


def bootstrap_existing(cfg: dict[str, Any], evidence: Path, *, actual: bool) -> None:
    """Provision a real existing app on ONLY the fresh, owned disposable VM DB."""
    assert_owned_vm()
    api = import_module("ops_deploy.services.mastodon")
    model = api.MastodonReleaseConfig(**cfg)
    if not actual:
        model = model.model_copy(update={"ruby_version": OLD_RUBY, "node_version": OLD_NODE})
    resolved = command(
        "bash", "-c", '. "$HOME/.nvm/nvm.sh"; nvm version ' + shlex.quote(model.node_version), user=True
    ).removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", resolved):
        raise AssertionError("fixture cannot resolve selected managed Node")
    model = model.model_copy(update={"node_version": resolved})
    from ops_deploy.services.mastodon.render import render, render_env

    env_path = SITE / ".env.production"
    descriptor = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    account = pwd.getpwnam("mastodon")
    with os.fdopen(descriptor, "wb") as output:
        output.write(render_env(model, secrets()).reveal())
    os.chown(env_path, account.pw_uid, account.pw_gid)
    # Reuse actual reviewed command executor, not completion/debt-mutating actions.
    if api.__file__ is None:
        raise AssertionError("candidate API module has no source file")
    helper = runpy.run_path(str(Path(api.__file__).parent / "files/release_host.py"))
    fields = model.model_dump()
    helper["verify_source"](fields)

    def run(argv: list[str], *, load_env: bool = False) -> None:
        print("BOOTSTRAP step: " + " ".join(argv[:4]), flush=True)
        result = helper["user"](fields, argv, load_env=load_env, optional=True)
        if result.returncode:
            raise RuntimeError(
                f"fixture bootstrap failed ({result.returncode}):\n"
                + fixture_failure_output(result.stdout, result.stderr)
            )

    print("BOOTSTRAP existing app locked dependencies", flush=True)
    for label, argv in (
        ("bundle-config-path", ["bundle", "config", "set", "--local", "path", fields["bundle_path"]]),
        ("bundle-config-without", ["bundle", "config", "set", "--local", "without", fields["bundle_without"]]),
        (
            "bundle-install",
            ["bundle", "install", "--jobs", str(fields["bundle_jobs"]), "--retry", str(fields["bundle_retry"])],
        ),
        ("corepack-enable", ["corepack", "enable"]),
        ("yarn-immutable-install", ["yarn", "install", "--immutable"]),
    ):
        print("BOOTSTRAP step: " + label, flush=True)
        run(argv)
    helper["verify_source"](fields)
    tables = command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-Atc",
        "SELECT count(*) FROM pg_tables WHERE schemaname='public'",
    )
    if tables != "0":
        raise AssertionError("schema load requires the newly recreated empty fixture DB")
    run(["bundle", "exec", "rails", "db:schema:load" if actual else "db:migrate"], load_env=True)
    if actual:
        run(["bundle", "exec", "rails", "db:seed"], load_env=True)
    else:
        # A business row written through ActiveRecord, after the real migration.
        run(
            [
                "bundle",
                "exec",
                "rails",
                "runner",
                'ActiveRecord::Base.connection.execute("INSERT INTO widgets (name) '
                "VALUES ('preserved-business-row')\")",
            ],
            load_env=True,
        )
    history = command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-Atc",
        "SELECT version FROM schema_migrations ORDER BY version",
    )
    if not set(cfg["migration_versions"]).issubset(set(history.splitlines())):
        raise AssertionError("real schema load did not cover candidate regular/post migration identities")
    run(["bundle", "exec", "rails", "assets:precompile"], load_env=True)
    if not helper["assets_output"](fields):
        raise AssertionError("baseline must have genuine complete Propshaft/Vite outputs")
    # Use the actual reviewed unit/config templates for this existing installation.
    write(Path("/etc/mastodon/nginx.conf"), render(model, "nginx.conf.j2"))
    for unit in UNITS:
        write(Path("/etc/systemd/system/mastodon-" + unit + ".service"), render(model, unit + ".service.j2"))
    command("systemctl", "daemon-reload")
    for unit in UNITS:
        command("systemctl", "start", "mastodon-" + unit + ".service")
    for attempt in range(30):
        try:
            check_http(actual=actual)
            break
        except (OSError, TimeoutError):
            if attempt == 29:
                raise
            time.sleep(2)
    baseline = services()
    runtimes = running_runtimes(fields)
    state = Path("/var/lib/ops-deploy-mastodon")
    if state.exists():
        raise AssertionError("baseline setup must not fabricate deployer completion state")
    write(
        evidence / ("actual-mastodon-existing-baseline.json" if actual else "minimal-existing-baseline.json"),
        json.dumps(
            dict(
                real_schema_load=actual,
                real_db_migrate=not actual,
                migration_count=len(history.splitlines()),
                regular_and_post_coverage=True,
                http200_instance=True,
                services=baseline,
                running_versions=runtimes,
                application_commit=cfg["source_commit"],
            ),
            indent=2,
        ),
    )


def main() -> None:
    assert_owned_vm()
    evidence = Path(sys.argv[1])
    api = import_module("ops_deploy.services.mastodon")
    controller_root = Path(sys.executable).parent.parent.parent
    if not (api.__file__ is not None):
        raise AssertionError("integration invariant failed")
    if not (Path(api.__file__).resolve().is_relative_to(controller_root.resolve())):
        raise AssertionError("integration invariant failed")
    if not (command("git", "-C", str(controller_root), "rev-parse", "HEAD") == os.environ["IMPLEMENTATION_SHA"]):
        raise AssertionError("integration invariant failed")
    harness_root = Path(__file__).resolve().parents[3]
    harness_sha = command("git", "-C", str(harness_root), "rev-parse", "HEAD")
    if harness_sha != os.environ["HARNESS_SHA"]:
        raise AssertionError("harness checkout does not match selected workflow SHA")
    source = Path("/var/tmp/mastodon-selected-source")
    command("git", "clone", "--depth=1", "--branch", "v4.6.9", "https://github.com/mastodon/mastodon.git", str(source))
    if not (command("git", "-C", str(source), "rev-parse", "HEAD") == MASTODON_COMMIT):
        raise AssertionError("integration invariant failed")
    ruby = (source / ".ruby-version").read_text().strip()
    node = (source / ".nvmrc").read_text().strip().removeprefix("v")
    write(
        evidence / "provenance.json",
        json.dumps(
            dict(
                harness_sha=harness_sha,
                implementation_sha=os.environ["IMPLEMENTATION_SHA"],
                implementation_checkout=str(controller_root),
                implementation_module=str(Path(api.__file__).resolve()),
                implementation_module_sha256=hashlib.sha256(Path(api.__file__).read_bytes()).hexdigest(),
                controller_executable=str(Path(sys.executable).resolve()),
                controller_proc_executable=str(Path("/proc/self/exe").resolve()),
                mastodon=MASTODON_COMMIT,
                ruby_build=RUBY_BUILD,
                rbenv=RBENV,
                nvm=NVM,
                ruby=ruby,
                node=node,
            )
        ),
    )
    # Real dummy keys exist before the first tool/compile, allowing bounded
    # diagnostics throughout setup; missing/unreadable metadata still fails shut.
    generate_fixture_keys(HOME / "vapid.json")
    context = dict(
        controller_cwd=str(Path.cwd()),
        service_cwd=command("pwd", "-P", user=True),
        service_uid=command("id", "-u", user=True),
    )
    if context["service_cwd"] != str(HOME.resolve()) or context["service_uid"] != str(pwd.getpwnam("mastodon").pw_uid):
        raise AssertionError("fixture service commands must run as mastodon in its accessible home")
    service_environment = json.loads(
        command(
            "python3",
            "-c",
            "import json,os; print(json.dumps({key:os.environ.get(key) for key in "
            "('HOME','USER','LOGNAME','SHELL','LANG','RBENV_ROOT','NVM_DIR','PATH','CI','GITHUB_ACTIONS')}))",
            user=True,
        )
    )
    expected = {"HOME": str(HOME), "RBENV_ROOT": str(HOME / ".rbenv"), "NVM_DIR": str(HOME / ".nvm")}
    if any(service_environment[key] != value for key, value in expected.items()):
        raise AssertionError("fixture runtime/cache roots must belong to the service home")
    write(
        evidence / "fixture-execution-context.json",
        json.dumps({**context, "service_environment": service_environment}, indent=2),
    )
    # Fixture prerequisites: exact tool checkouts; selected runtime itself remains absent.
    for repo, dest, ref in [
        ("rbenv/rbenv", HOME / ".rbenv", RBENV),
        ("rbenv/ruby-build", HOME / ".rbenv/plugins/ruby-build", RUBY_BUILD),
    ]:
        command("git", "clone", "https://github.com/" + repo + ".git", str(dest), user=True)
        command("git", "-C", str(dest), "checkout", "--detach", ref, user=True)
    # Clone nvm outside its possibly image-created destination, preserving it.
    nvm_stage = HOME / (".fixture-nvm-source-" + uuid.uuid4().hex)
    command("git", "clone", "https://github.com/nvm-sh/nvm.git", str(nvm_stage), user=True)
    command("git", "-C", str(nvm_stage), "checkout", "--detach", NVM, user=True)
    preserve_runner_nvm(HOME, evidence, pwd.getpwnam("mastodon").pw_uid)
    safety_require(
        not (HOME / ".nvm").exists() and not (HOME / ".nvm").is_symlink(),
        "nvm destination reappeared before fixture install",
    )
    nvm_stage.rename(HOME / ".nvm")
    # Existing-install prerequisite: login shells initialize the real runtimes.
    write(
        HOME / ".bash_profile",
        'export RBENV_ROOT="$HOME/.rbenv"\n'
        'export NVM_DIR="$HOME/.nvm"\n'
        'export PATH="$RBENV_ROOT/bin:$RBENV_ROOT/shims:$PATH"\n'
        '. "$NVM_DIR/nvm.sh"\n'
        "nvm use --silent default >/dev/null\n",
    )
    command("chown", "mastodon:mastodon", str(HOME / ".bash_profile"))
    minimal = HOME / "fixture-source"
    fixture(minimal, ruby, node)
    command("chown", "-R", "mastodon:mastodon", str(minimal))
    # Bootstrap with the retained real runtimes; do not depend on Ubuntu Ruby's
    # resolver/version or generate source locks under the still-absent target.
    command(str(HOME / ".rbenv/bin/rbenv"), "install", "-s", OLD_RUBY, user=True)
    command(str(HOME / ".rbenv/bin/rbenv"), "global", OLD_RUBY, user=True)
    old_ruby = HOME / ".rbenv/versions" / OLD_RUBY / "bin/ruby"
    old_ruby_version = command(str(old_ruby), "--version", user=True)
    command("bash", "-c", ". /home/mastodon/.nvm/nvm.sh && nvm install " + OLD_NODE, user=True)
    old_node = HOME / ".nvm/versions/node" / ("v" + OLD_NODE) / "bin/node"
    old_node_version = command(str(old_node), "--version", user=True)
    initial_old_alias = (HOME / ".nvm/alias/default").read_text().strip()
    if initial_old_alias.removeprefix("v") != OLD_NODE:
        raise AssertionError("fixture must start with old Node alias")
    write(
        evidence / "initial-retained-runtime.json",
        json.dumps(dict(old_ruby=old_ruby_version, old_node=old_node_version, nvm_default_alias=initial_old_alias)),
    )
    bootstrap_path = str(old_ruby.parent) + ":" + str(old_node.parent) + ":/usr/local/bin:/usr/bin:/bin"
    for script in (
        "gem install bundler -v 4.0.13 --no-document && bundle _4.0.13_ lock",
        # Only source-fixture lock generation may create a lock in CI. Actual
        # application installs below and in the API still use --immutable.
        "YARN_ENABLE_IMMUTABLE_INSTALLS=false npx --yes corepack@0.34.0 yarn install --mode=skip-build",
    ):
        command(
            "env",
            "PATH=" + bootstrap_path,
            "RBENV_ROOT=" + str(HOME / ".rbenv"),
            "RBENV_VERSION=" + OLD_RUBY,
            "bash",
            "-c",
            "cd " + shlex.quote(str(minimal)) + " && " + script,
            user=True,
        )
    shutil.rmtree(minimal / "node_modules", ignore_errors=True)
    shutil.rmtree(minimal / ".yarn", ignore_errors=True)
    command("git", "init", "-q", str(minimal), user=True)
    first_commit = git_commit(minimal, "minimal real Rails source", user=True)
    command("git", "-C", str(minimal), "tag", "fixture-first", user=True)
    command("chown", "-R", "mastodon:mastodon", str(minimal))
    shutil.rmtree(SITE)
    command("git", "clone", minimal.as_uri(), str(SITE), user=True)
    seed_protected()
    cfg = config(minimal, minimal.as_uri(), "fixture-first")
    bootstrap_existing(cfg, evidence, actual=False)
    if (HOME / ".rbenv/versions" / ruby).exists():
        raise AssertionError("integration invariant failed")
    if list((HOME / ".nvm/versions/node").glob("v" + node + "*")):
        raise AssertionError("selected Node must be absent to prove real installation")
    pair(cfg, evidence, "minimal-missing-runtime")
    if not (command(str(old_ruby), "--version", user=True) == old_ruby_version):
        raise AssertionError("integration invariant failed")
    if not (command(str(old_node), "--version", user=True) == old_node_version):
        raise AssertionError("integration invariant failed")
    # Actual new migration plus a real asset-task failure exercises partial-work debt/retry.
    write(
        minimal / "db/migrate/20250102000000_add_widget_note.rb",
        "class AddWidgetNote < ActiveRecord::Migration[8.1]\n"
        "  def change\n    add_column :widgets, :note, :string\n  end\nend\n",
    )
    write(minimal / "app/assets/fixture.css", "body { color: navy; }\n")
    command("chown", "-R", "mastodon:mastodon", str(minimal))
    git_commit(minimal, "pending migration and changed build input", user=True)
    command("git", "-C", str(minimal), "tag", "fixture-pending", user=True)
    cfg = config(minimal, minimal.as_uri(), "fixture-pending")
    write(HOME / "fail-assets", "deliberate fixture fault\n")
    old_services = services()
    deploy(cfg, evidence, "minimal-failed-build", fails=True)
    if not ((HOME / "asset-fault-observed").is_file()):
        raise AssertionError("integration invariant failed")
    if not (services() == old_services):
        raise AssertionError("integration invariant failed")
    if json.loads(Path("/var/lib/ops-deploy-mastodon/pending-rollout").read_text()) is not True:
        raise AssertionError("integration invariant failed")
    if json.loads(Path("/var/lib/ops-deploy-mastodon/pending-cache-clear").read_text()) is not True:
        raise AssertionError("integration invariant failed")
    check_http(actual=False)
    failed_history = command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-Atc",
        "SELECT version FROM schema_migrations ORDER BY version",
    )
    if not (set(cfg["migration_versions"]).issubset(set(failed_history.splitlines()))):
        raise AssertionError("integration invariant failed")
    if not (
        command(
            "runuser", "-u", "postgres", "--", "psql", "-d", "mastodon", "-Atc", "SELECT name FROM widgets ORDER BY id"
        )
        == "preserved-business-row"
    ):
        raise AssertionError("integration invariant failed")
    (HOME / "fail-assets").unlink()
    pair(cfg, evidence, "minimal-retry")
    applied = command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-Atc",
        "SELECT version FROM schema_migrations ORDER BY version",
    )
    if not (set(applied.splitlines()) == {"20250101000000", "20250102000000"}):
        raise AssertionError("integration invariant failed")
    # Reset ONLY this disposable VM's fixture app/DB; retain managed runtimes for full Mastodon.
    for unit in UNITS:
        command("systemctl", "stop", "mastodon-" + unit + ".service")
    shutil.rmtree(SITE)
    SITE.mkdir()
    state = Path("/var/lib/ops-deploy-mastodon")
    safety_require(state.is_dir() and not state.is_symlink(), "release state must be a real directory")
    safety_require(state.stat().st_uid == 0, "release state owner must be root")
    safety_require(stat.S_IMODE(state.stat().st_mode) == 0o700, "release state must be mode0700")
    shutil.rmtree(state)
    command("runuser", "-u", "postgres", "--", "dropdb", "mastodon")
    command("runuser", "-u", "postgres", "--", "createdb", "-O", "mastodon", "mastodon")
    command(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-d",
        "mastodon",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "CREATE EXTENSION pg_trgm; CREATE EXTENSION unaccent;",
    )
    SITE.rmdir()
    command(
        "git",
        "clone",
        "--depth=1",
        "--branch",
        "v4.6.9",
        "https://github.com/mastodon/mastodon.git",
        str(SITE),
        user=True,
    )
    seed_protected()
    full = config(source, "https://github.com/mastodon/mastodon.git", "v4.6.9")
    bootstrap_existing(full, evidence, actual=True)
    pair(full, evidence, "actual-mastodon-v4.6.9")
    if not (command(str(old_ruby), "--version", user=True) == old_ruby_version):
        raise AssertionError("integration invariant failed")
    if not (command(str(old_node), "--version", user=True) == old_node_version):
        raise AssertionError("integration invariant failed")
    write(
        evidence / "SUCCESS.json",
        json.dumps(
            dict(
                minimal_real_rails=True,
                actual_mastodon_build=True,
                failed_build_retry=True,
                pending_migration=True,
                retained_old_ruby=True,
                retained_old_node=True,
                all_actual_repeats_zero=True,
                selected_commit=MASTODON_COMMIT,
                minimal_first_commit=first_commit,
            ),
            indent=2,
        ),
    )


if __name__ == "__main__":
    main()
