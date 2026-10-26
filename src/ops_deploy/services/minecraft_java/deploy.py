"""Deploy Minecraft Java without changing existing backup jobs or archives."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections.abc import Generator
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, FindFiles
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops import secret_file, secret_stdin

PACKAGE = "ops_deploy.services.minecraft_java"
SafeText = Annotated[str, Field(pattern=r"^[^\r\n\\]*$")]
PropertiesText = Annotated[str, Field(pattern=r"^[\x20-\x5B\x5D-\x7E]*$")]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
PathText = Annotated[str, Field(pattern=r"^/[A-Za-z0-9_./-]+$")]
Url = Annotated[str, Field(pattern=r"^https://[^\s\"'\\$`]+$")]
Sha256 = Annotated[str, Field(pattern=r"^[a-fA-F0-9]{64}$")]
Port = Annotated[int, Field(ge=1, le=65535)]


class Mod(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    name: SafeText = Field(min_length=1)
    version: SafeText | None = Field(default=None, min_length=1)
    url: Url
    sha256: Sha256
    filename: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.+-]+\.jar$")]
    enabled: bool = True

    @model_validator(mode="before")
    @classmethod
    def filename_from_url(cls, value: Any) -> Any:
        if isinstance(value, dict) and "filename" not in value and isinstance(value.get("url"), str):
            value = {**value, "filename": value["url"].rsplit("/", 1)[-1]}
        return value


class MinecraftJavaConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("rcon_password",)
    service_name: ServiceName = "minecraft-java"
    user: UnixUser = "minecraft"
    group: UnixUser = "minecraft"
    site_path: PurePosixPath = PurePosixPath("/opt/minecraft/server")
    home: PathText = "/opt/minecraft"
    loader_mode: Literal["vanilla", "forge"] = "vanilla"
    allow_mode_switch_same_world: bool = False
    eula_agreed: Literal[True]
    java_version: Annotated[str, Field(pattern=r"^[0-9]+$")] = "21"
    memory_min: Annotated[str, Field(pattern=r"^[1-9][0-9]*[MG]$")] = "2G"
    memory_max: Annotated[str, Field(pattern=r"^[1-9][0-9]*[MG]$")] = "4G"
    extra_args: Annotated[str, Field(pattern=r"^[A-Za-z0-9=:+.,_ -]*$")] = (
        "-XX:+UseG1GC "
        "-XX:+ParallelRefProcEnabled "
        "-XX:MaxGCPauseMillis=200 "
        "-XX:+UnlockExperimentalVMOptions "
        "-XX:+DisableExplicitGC "
        "-XX:+AlwaysPreTouch "
        "-XX:G1NewSizePercent=30 "
        "-XX:G1MaxNewSizePercent=40 "
        "-XX:G1HeapRegionSize=8M "
        "-XX:G1ReservePercent=20 "
        "-XX:G1HeapWastePercent=5 "
        "-XX:G1MixedGCCountTarget=4 "
        "-XX:InitiatingHeapOccupancyPercent=15 "
        "-XX:G1MixedGCLiveThresholdPercent=90 "
        "-XX:G1RSetUpdatingPauseTimePercent=5 "
        "-XX:SurvivorRatio=32 "
        "-XX:+PerfDisableSharedMem "
        "-XX:MaxTenuringThreshold=1"
    )
    startup_timeout: int = Field(default=60, ge=1, le=1800)
    server_jar_url: Url | None = None
    server_jar_sha256: Sha256 | None = None
    forge_version: Annotated[str, Field(pattern=r"^[0-9][A-Za-z0-9_.-]+$")] | None = None
    forge_installer_url: Url | None = None
    forge_installer_sha256: Sha256 | None = None
    forge_installer_sha1: Annotated[str, Field(pattern=r"^[a-fA-F0-9]{40}$")] | None = None
    mods_enabled: bool = False
    mods_prune_unmanaged: bool = False
    mods: tuple[Mod, ...] = ()
    port: Port = 25565
    rcon_port: Port = 25575
    rcon_enabled: Literal[True] = True
    difficulty: Literal["peaceful", "easy", "normal", "hard"] = "normal"
    gamemode: Literal["survival", "creative", "adventure", "spectator"] = "survival"
    max_players: int = Field(default=20, ge=1)
    pvp: bool = True
    world_name: Name = "world"
    seed: PropertiesText = ""
    motd: PropertiesText = "A Minecraft Server"
    online_mode: bool = True
    view_distance: int = Field(default=10, ge=2, le=32)
    simulation_distance: int = Field(default=10, ge=2, le=32)
    spawn_protection: int = Field(default=16, ge=0)
    allow_flight: bool = False
    allow_nether: bool = True
    generate_structures: bool = True
    max_world_size: int = Field(default=29999984, ge=1, le=29999984)
    level_type: Annotated[str, Field(pattern=r"^[a-z0-9_:-]+$")] = "minecraft:normal"
    whitelist_enabled: bool = False
    whitelist_players: tuple[Name, ...] = ()
    ops: tuple[Name, ...] = ()
    service_state: Literal["started", "stopped"] = "started"
    firewall_enabled: Literal[True] = True
    firewall_allowed_networks: tuple[str, ...]

    @field_validator("firewall_allowed_networks")
    @classmethod
    def networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("at least one game client network is required")
        try:
            return tuple(str(ipaddress.ip_network(item, strict=False)) for item in value)
        except ValueError:
            raise ValueError("invalid game client network") from None

    @field_validator("motd", "seed")
    @classmethod
    def no_leading_property_space(cls, value: str) -> str:
        if value.startswith(" "):
            raise ValueError("MOTD and seed must not start with a space")
        return value

    @model_validator(mode="after")
    def runtime(self) -> Self:
        if self.loader_mode == "forge" and "startup_timeout" not in self.model_fields_set:
            object.__setattr__(self, "startup_timeout", 300)
        if self.loader_mode == "vanilla":
            if not self.server_jar_url or not self.server_jar_sha256:
                raise ValueError("vanilla requires server JAR URL and SHA256")
            if self.mods_enabled:
                raise ValueError("mods require Forge")
        elif not (
            self.forge_version
            and self.forge_installer_url
            and (self.forge_installer_sha256 or self.forge_installer_sha1)
        ):
            raise ValueError("Forge requires version, installer URL and checksum")
        if self.port == self.rcon_port:
            raise ValueError("game and RCON ports must differ")
        if len({mod.filename for mod in self.mods}) != len(self.mods):
            raise ValueError("mod filenames must be unique")
        urls = [self.server_jar_url, self.forge_installer_url, *(mod.url for mod in self.mods)]
        for url in urls:
            if url is not None:
                parsed = urlsplit(url)
                if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError("artifact URLs must be HTTPS URLs without credentials, query or fragment")
        for path in (str(self.site_path), self.home):
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", path) or ".." in PurePosixPath(path).parts:
                raise ValueError("paths must be absolute plain POSIX paths without parent traversal")
        if self.home == "/" or not self.site_path.is_relative_to(PurePosixPath(self.home)):
            raise ValueError("site_path must be below a non-root home directory")
        return self

    def context(self, secrets: SecretValues) -> dict[str, Any]:
        values = {"minecraft_java_" + key: value for key, value in self.model_dump().items()}
        values.update(
            minecraft_java_user=self.user,
            minecraft_java_group=self.group,
            minecraft_java_home=self.home,
            minecraft_java_server_dir=str(self.site_path),
            minecraft_java_forge_wrapper_script_path=str(self.site_path / "start-forge.sh"),
        )
        values["minecraft_java_rcon_password"] = secrets["rcon_password"]
        return values


def rendered(cfg: MinecraftJavaConfig, template: str, secrets: SecretValues) -> str:
    return render(PACKAGE, template, **cfg.context(secrets))


def validate_secrets(secrets: SecretValues) -> None:
    secrets.require(("rcon_password",))
    # Java properties + EnvironmentFile: refuse ambiguous escaping and injection.
    password = secrets["rcon_password"]
    if password == "CHANGEME" or len(password) < 8 or not re.fullmatch(r"[A-Za-z0-9_+/.=:@%-]+", password):
        raise ValueError("rcon_password must contain at least eight safe ASCII characters")


def _put(cfg: MinecraftJavaConfig, name: str, content: str, mode: str = "0644") -> OperationMeta:
    # Reuse the descriptor-pinned installer even for nonsecret managed text.
    return secret_file(
        name=f"Write Minecraft {name}",
        path=cfg.site_path / name,
        content=SecretContent(content),
        user=cfg.user,
        group=cfg.group,
        mode=mode,
    )


CONFIG_STATE_SOURCE = (Path(__file__).parent / "files/config_state.py").read_text()


def config_command(cfg: MinecraftJavaConfig, name: str, kind: str, mode: str) -> str:
    return shlex.join(
        [
            "runuser",
            "-u",
            cfg.user,
            "-g",
            cfg.group,
            "--",
            "python3",
            "-I",
            "-c",
            CONFIG_STATE_SOURCE,
            str(cfg.site_path / name),
            kind,
            mode,
        ]
    )


def _config_file(cfg: MinecraftJavaConfig, name: str, content: str, kind: str, mode: str) -> OperationMeta:
    request = json.dumps({"content": content})
    command = config_command(cfg, name, kind, mode)
    current = (
        probe(command, name="Minecraft " + name, stdin=request)
        if host.get_fact(File, path=str(cfg.site_path / name))
        else "pending"
    )
    if current == "unsupported":
        raise ValueError("Minecraft configuration uses unsupported file syntax; no changes scheduled")
    write = secret_file(
        name="Write Minecraft " + name,
        path=cfg.site_path / name,
        content=SecretContent(content),
        user=cfg.user,
        group=cfg.group,
        mode=mode,
        _if=lambda: current != "current",
    )
    verify_probe(command, name="Minecraft " + name, expect="current", stdin=request)
    return write


# The subshell used by probe() permits exit here without failing fact loading.
MCRCON_CHECK = (
    "out=$(/usr/local/bin/mcrcon -v 2>&1) || exit 1; "
    "printf '%s\n' \"$out\" | grep -Eq '^mcrcon 0[.]7[.]2([[:space:]]|$)'"
)


MODE_GUARD = """import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
state=root/'.loader_state.json'
marker=root/'.loader_mode'
props=root/'server.properties'
mode=marker.read_text().strip().lower() if marker.exists() else 'vanilla'
world=''
if props.exists():
    for line in props.read_text().splitlines():
        if line.startswith('level-name='): world=line.split('=',1)[1].strip(); break
if state.exists():
    saved=json.loads(state.read_text())
    if 'pending_loader_mode' in saved:
        if (sys.argv[2],sys.argv[3]) != (saved['pending_loader_mode'],saved['pending_world_name']):
            sys.exit('Resume the pending Minecraft loader/world candidate before changing it')
        if (mode not in (saved['loader_mode'],saved['pending_loader_mode'])
                or world not in (saved['world_name'],saved['pending_world_name'])):
            sys.exit('Unexpected Minecraft state drift during pending deployment')
        mode,world=saved['loader_mode'],saved['world_name']
if mode not in ('vanilla','forge') or not isinstance(world,str):
    sys.exit('Invalid Minecraft loader state')
if mode != sys.argv[2] and world == sys.argv[3] and sys.argv[4] != 'true':
    sys.exit('Unsafe loader switch on the same world')
print('safe '+json.dumps({'loader_mode':mode,'world_name':world},sort_keys=True))
"""


def guard_command(cfg: MinecraftJavaConfig) -> str:
    return shlex.join(
        [
            "python3",
            "-c",
            MODE_GUARD,
            str(cfg.site_path),
            cfg.loader_mode,
            cfg.world_name,
            str(cfg.allow_mode_switch_same_world).lower(),
        ]
    )


@deploy("Deploy Minecraft Java")
def deploy_minecraft_java(cfg: MinecraftJavaConfig, secrets: SecretValues) -> None:
    validate_secrets(secrets)
    # A remote guard is first, before any managed files or packages change. No
    # server.properties contents (including RCON credentials) leave the host.
    result = host.get_fact(Command, command=guard_command(cfg))
    if not result or not result.startswith("safe "):
        raise ValueError("Minecraft loader/world guard did not pass")
    try:
        previous = json.loads(result.removeprefix("safe "))
    except ValueError:
        raise ValueError("Minecraft loader/world guard returned invalid state") from None
    if cfg.service_state == "started":
        if (host.get_fact(Command, command="LC_ALL=C ufw status") or "").splitlines()[:1] != ["Status: active"]:
            raise ValueError("Minecraft requires active UFW before starting; no changes scheduled")
    else:
        # Stop before replacing any runtime inputs, including the old unit/env.
        systemd.service(name="Keep Minecraft stopped", service=cfg.service_name, running=False)
    apt.packages(
        packages=[
            f"openjdk-{cfg.java_version}-jre-headless",
            "build-essential",
            "git",
            "ufw",
            "curl",
            "ca-certificates",
        ],
        update=True,
        cache_time=3600,
    )
    server.group(group=cfg.group)
    server.user(user=cfg.user, group=cfg.group, home=cfg.home, shell="/bin/bash", ensure_home=True)
    for path in (str(cfg.site_path), str(cfg.site_path / "logs")):
        files.directory(path=path, user=cfg.user, group=cfg.group, mode="0755")
    # Persist the original pair before changing properties. A failed new-world
    # switch can retry without deriving history from already-overwritten inputs.
    if previous["loader_mode"] != cfg.loader_mode:
        pending = {**previous, "pending_loader_mode": cfg.loader_mode, "pending_world_name": cfg.world_name}
        _put(cfg, ".loader_state.json", json.dumps(pending, sort_keys=True) + "\n")
    # Unique build directory, removed on both success and failure. No mutable
    # checkout under a shared fixed temporary path.
    version = (
        probe(MCRCON_CHECK, name="Minecraft mcrcon") if host.get_fact(File, path="/usr/local/bin/mcrcon") else None
    )
    build = """set -eu
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
git clone --depth 1 --branch v0.7.2 https://github.com/Tiiffi/mcrcon.git "$build_dir"
test "$(git -C "$build_dir" rev-parse HEAD)" = b5951e96349ec2ecf72b468459fc503a7067ba1f
make -C "$build_dir"
install -o root -g root -m 0755 "$build_dir/mcrcon" /usr/local/bin/mcrcon"""
    server.shell(
        name="Install mcrcon if missing",
        commands=["bash -c " + shlex.quote(build)],
        _if=lambda: version is None,
    )
    verify_probe(MCRCON_CHECK, name="Minecraft mcrcon")
    changes: list[OperationMeta] = []
    if cfg.loader_mode == "vanilla":
        assert cfg.server_jar_url is not None
        changes.append(
            _download(
                src=cfg.server_jar_url,
                dest=str(cfg.site_path / "server.jar"),
                sha256sum=cfg.server_jar_sha256,
                user=cfg.user,
                group=cfg.group,
                mode="0644",
            )
        )
    else:
        changes.extend(_forge(cfg))
        for template, target, mode in (
            ("user_jvm_args.txt.j2", "user_jvm_args.txt", "0644"),
            ("start-forge.sh.j2", "start-forge.sh", "0755"),
        ):
            changes.append(_put(cfg, target, rendered(cfg, template, secrets), mode))
    changes.append(
        _config_file(cfg, "server.properties", rendered(cfg, "server.properties.j2", secrets), "properties", "0640")
    )
    changes.append(
        secret_file(
            path=PurePosixPath(cfg.home) / ".env",
            content=SecretContent(rendered(cfg, "minecraft-java.env.j2", secrets)),
            user=cfg.user,
            group=cfg.group,
            mode="0600",
        )
    )
    _put(
        cfg,
        "eula.txt",
        "# By setting eula=true you are accepting the Minecraft EULA\n# https://aka.ms/MinecraftEULA\neula=true\n",
    )
    if cfg.ops:
        changes.append(_config_file(cfg, "ops.json", rendered(cfg, "ops.json.j2", secrets), "players", "0644"))
    if cfg.whitelist_enabled:
        changes.append(
            _config_file(cfg, "whitelist.json", rendered(cfg, "whitelist.json.j2", secrets), "players", "0644")
        )
    if cfg.loader_mode == "forge" and cfg.mods_enabled:
        changes.extend(_mods(cfg))
    # Maintain the role's rules even on a stopped server with inactive UFW.
    # Starting requires active UFW above; never enable/reset it here.
    rules = [f"ufw deny {cfg.rcon_port}/tcp"]
    rules += [f"ufw allow from {network} to any port {cfg.port} proto tcp" for network in cfg.firewall_allowed_networks]
    for command in rules:
        # UFW's own duplicate rule handling is idempotent, but inspect first to
        # avoid scheduling changes on an already converged firewall.
        server.shell(
            name="Ensure Minecraft firewall rule",
            commands=[command],
            _if=partial(_firewall_missing, command),
        )
    unit = systemd_unit(cfg.service_name, rendered(cfg, "minecraft-java.service.j2", secrets))
    if cfg.service_state == "stopped":
        systemd.daemon_reload(name="Reload stopped Minecraft unit", _if=any_changed(unit))
        systemd.service(name="Enable stopped Minecraft", service=cfg.service_name, running=None, enabled=True)
        mark_read_only(
            server.shell(
                name="Verify Minecraft remains stopped",
                commands=[stopped_check(cfg)],
            )
        )
    else:
        service_rollout(cfg.service_name, units=[unit], restart_when=changes)
        _verify_running(cfg, secrets)
    _put(cfg, ".loader_mode", cfg.loader_mode + "\n")
    _put(
        cfg,
        ".loader_state.json",
        json.dumps({"loader_mode": cfg.loader_mode, "world_name": cfg.world_name}, sort_keys=True) + "\n",
    )


def stopped_check(cfg: MinecraftJavaConfig) -> str:
    # The old role unit records Forge's clean RCON shutdown as failed/143.
    # Preserve that known stopped state without hiding other runtime failures.
    return (
        f"state=$(systemctl show -p ActiveState --value {cfg.service_name}); "
        f"result=$(systemctl show -p Result --value {cfg.service_name}); "
        f"code=$(systemctl show -p ExecMainStatus --value {cfg.service_name}); "
        '[ "$state" = inactive ] || { [ "$state" = failed ] && '
        '[ "$result" = exit-code ] && [ "$code" = 143 ]; } || exit 1; '
        f"listeners=$(ss -H -ltn '( sport = :{cfg.port} or sport = :{cfg.rcon_port} )') || exit 1; "
        'test -z "$listeners"'
    )


def _verify_running(cfg: MinecraftJavaConfig, secrets: SecretValues) -> None:
    check = (
        f"systemctl is-active --quiet {cfg.service_name}; "
        f"for i in $(seq 1 {cfg.startup_timeout}); do "
        f"(echo > /dev/tcp/127.0.0.1/{cfg.port}) 2>/dev/null && exit 0; sleep 1; done; exit 1"
    )
    mark_read_only(server.shell(name="Verify Minecraft game port", commands=["bash -ec " + shlex.quote(check)]))
    command = shlex.join(
        [
            "/bin/sh",
            "-c",
            "IFS= read -r MCRCON_PASS && export MCRCON_PASS; "
            f"for i in $(seq 1 {cfg.startup_timeout}); do "
            f"/usr/local/bin/mcrcon -H 127.0.0.1 -P {cfg.rcon_port} list >/dev/null 2>&1 && exit 0; "
            "sleep 1; done; exit 1",
        ]
    )
    mark_read_only(
        secret_stdin(
            name="Verify Minecraft RCON", command=command, content=SecretContent(secrets["rcon_password"] + "\n")
        )
    )


@operation()
def _download(
    src: str, dest: str, user: str, group: str, mode: str, sha256sum: str | None = None, sha1sum: str | None = None
) -> Generator[StringCommand, None, None]:
    """Verify in a private sibling directory before atomically replacing a JAR."""
    digest = sha256sum or sha1sum
    assert digest is not None
    algorithm = "sha256sum" if sha256sum else "sha1sum"
    info = host.get_fact(File, path=dest)
    if info is False:
        raise ValueError("Minecraft JAR destination is not a regular file")
    check = shlex.join(["runuser", "-u", user, "-g", group, "--", algorithm, dest])
    output = (host.get_fact(Command, command=check) or "") if info else ""
    remote = output.split()[0] if output.split() else None
    if (
        remote == digest.lower()
        and info
        and info["user"] == user
        and info["group"] == group
        and info["mode"] == int(mode.lstrip("0"))
    ):
        host.noop("Minecraft JAR is verified with expected ownership and mode")
        return
    parent = str(PurePosixPath(dest).parent)
    script = (
        "set -eu; stage=$(mktemp -d " + shlex.quote(parent + "/.minecraft-download.XXXXXX") + "); "
        "trap 'rm -rf \"$stage\"' EXIT; "
        "curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 300 "
        + shlex.quote(src)
        + ' --output "$stage/artifact"; '
        + "printf '%s  %s\\n' "
        + shlex.quote(digest)
        + ' "$stage/artifact" | '
        + algorithm
        + " --check --status; "
        + "chmod "
        + mode
        + ' "$stage/artifact"; mv -f "$stage/artifact" '
        + shlex.quote(dest)
    )
    yield StringCommand(shlex.join(["runuser", "-u", user, "-g", group, "--", "bash", "-c", script]))


def _firewall_missing(command: str) -> bool:
    # UFW show added emits the canonical CLI, unlike the locale-sensitive status.
    existing = host.get_fact(Command, command="LC_ALL=C ufw show added") or ""

    def canonical(line: str) -> tuple[str, ...]:
        parts = shlex.split(line)
        if "comment" in parts:
            parts = parts[: parts.index("comment")]
        # UFW may move an explicit protocol before the source/destination.
        if "proto" in parts:
            index = parts.index("proto")
            protocol = parts[index : index + 2]
            del parts[index : index + 2]
            parts.extend(protocol)
        # Explicit inbound direction is the default; never equate an out rule.
        if len(parts) > 2 and parts[2] == "in":
            del parts[2]
        return tuple(parts)

    desired = canonical(command)
    return not any(canonical(line) == desired for line in existing.splitlines() if line.startswith("ufw "))


def _forge(cfg: MinecraftJavaConfig) -> list[OperationMeta]:
    assert cfg.forge_installer_url is not None
    root = cfg.site_path
    checksum = (
        "sha256:" + cfg.forge_installer_sha256
        if cfg.forge_installer_sha256
        else "sha1:" + str(cfg.forge_installer_sha1)
    )
    args = root / f"libraries/net/minecraftforge/forge/{cfg.forge_version}/unix_args.txt"
    probe = shlex.join(
        [
            "python3",
            "-c",
            (
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                "print('yes' if (p/'.forge_version').is_file() and "
                "(p/'.forge_installer_checksum').is_file() and "
                "(p/'.forge_version').read_text().strip()==sys.argv[2] and "
                "(p/'.forge_installer_checksum').read_text().strip()==sys.argv[3] and "
                "pathlib.Path(sys.argv[4]).is_file() and (p/'run.sh').is_file() else 'no')"
            ),
            str(root),
            str(cfg.forge_version),
            checksum,
            str(args),
        ]
    )
    needed = host.get_fact(Command, command=probe) != "yes"
    download = _download(
        src=cfg.forge_installer_url,
        dest=str(root / "forge-installer.jar"),
        sha256sum=cfg.forge_installer_sha256,
        sha1sum=None if cfg.forge_installer_sha256 else cfg.forge_installer_sha1,
        user=cfg.user,
        group=cfg.group,
        mode="0644",
        _if=lambda: needed,
    )
    install = server.shell(
        name="Install Forge runtime",
        commands=[
            shlex.join(
                [
                    "runuser",
                    "-u",
                    cfg.user,
                    "--",
                    "/bin/sh",
                    "-c",
                    "cd " + shlex.quote(str(root)) + " && exec /usr/bin/java -jar forge-installer.jar --installServer",
                ]
            )
        ],
        _if=lambda: needed,
    )
    mark_read_only(
        server.shell(
            name="Verify Forge artifacts",
            commands=[f"test -f {shlex.quote(str(args))} && test -f {shlex.quote(str(root / 'run.sh'))}"],
        )
    )
    files.file(path=str(root / "run.sh"), user=cfg.user, group=cfg.group, mode="0755")
    _put(cfg, ".forge_version", str(cfg.forge_version) + "\n")
    _put(cfg, ".forge_installer_checksum", checksum + "\n")
    return [download, install]


def _mods(cfg: MinecraftJavaConfig) -> list[OperationMeta]:
    directory = cfg.site_path / "mods"
    files.directory(path=str(directory), user=cfg.user, group=cfg.group, mode="0755")
    changes = []
    enabled = {mod.filename for mod in cfg.mods if mod.enabled}
    for mod in cfg.mods:
        target = str(directory / mod.filename)
        if mod.enabled:
            changes.append(
                _download(src=mod.url, dest=target, sha256sum=mod.sha256, user=cfg.user, group=cfg.group, mode="0644")
            )
        else:
            changes.append(files.file(path=target, present=False))
    if cfg.mods_prune_unmanaged:
        for path in host.get_fact(FindFiles, path=str(directory), maxdepth=1, fname="*.jar") or []:
            if PurePosixPath(path).name not in enabled:
                changes.append(files.file(path=path, present=False))
    return changes
