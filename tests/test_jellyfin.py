"""Deploy-level scenarios for jellyfin against the fake connector."""

from typing import Any

import pytest
from pydantic import SecretStr

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers import BasicAuth
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.jellyfin import JellyfinConfig, deploy_jellyfin
from ops_deploy.services.jellyfin.deploy import render_route, repository_line, traefik_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

PASSWORD = "jellyfin-fixture-basic-pw"
AUTH = BasicAuth(user="admin", password=SecretStr(PASSWORD))
_HASH = hash_password(PASSWORD)
KEYRING = "/usr/share/keyrings/jellyfin-archive-keyring.gpg"
LIST = "/etc/apt/sources.list.d/jellyfin.list"
ROUTE = "/etc/traefik/dynamic/jellyfin.yml"
MEDIA = ("/mnt/cryptdata/media/video/movies", "/mnt/cryptdata/media/video/tv")
YOUTUBE = "/mnt/cryptdata/media/video/youtube"
OWN_DIRS = ("/var/lib/jellyfin", "/etc/jellyfin", "/var/log/jellyfin")
P = "Deploy Jellyfin | "
READ_ONLY = [
    f"{P}Require the mount /mnt/cryptdata",
    f"{P}Wait for Jellyfin port to be open",
    f"{P}Perform Jellyfin HTTP health check",
]
# Probe commands (substrings of the fact commands).
OS_RELEASE = '. /etc/os-release && echo "$ID|'
KEYRING_STATE = f"head -c 5 {KEYRING}"
POLICY = "LC_ALL=C apt-cache policy jellyfin-ffmpeg6"
INSTALLED = "dpkg-query -W -f="


@pytest.fixture
def cfg() -> JellyfinConfig:
    # A production-like config: two media dirs in a shared, setgid media group.
    return JellyfinConfig(
        repo_distro="ubuntu",
        repo_release="noble",
        repo_arch="amd64",
        traefik_host="media.example.com",
        media_directories=MEDIA,
        media_dir_group="media",
        media_dir_mode="02775",
        mounts_required=("/mnt/cryptdata",),
    )


def policies(**candidates: str | None) -> list[str]:
    """``apt-cache policy`` output per candidate: a version, ``(none)``, or None (unknown package)."""

    lines: list[str] = []
    for name in ("jellyfin-ffmpeg6", "jellyfin-ffmpeg5", "jellyfin-ffmpeg"):
        lines.append(f">>{name}")
        version = candidates.get(name.replace("-", "_"))
        if version is not None:
            lines += [f"{name}:", "  Installed: (none)", f"  Candidate: {version}", "  Version table:"]
    return lines


def overlay(base: dict[str, Any], **drift: Any) -> dict[str, Any]:
    """``base`` with ``drift`` taking precedence (first matching key wins, so drift goes first)."""

    return {**drift, **{key: value for key, value in base.items() if key not in drift}}


def installed(*names: str) -> dict[str, Any]:
    return {INSTALLED: [f"ii |{name}|" for name in names]}


def host_facts() -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        "command -v apt-get": ["/usr/bin/apt-get"],
        "command -v gpg": ["/usr/bin/gpg"],
        OS_RELEASE: ["ubuntu|noble"],
        "uname -m": ["x86_64"],
    }


def converged(cfg: JellyfinConfig, **drift: Any) -> dict[str, Any]:
    """Facts of a host where the role (or this deploy) already ran."""

    responses: dict[str, Any] = {
        **host_facts(),
        KEYRING_STATE: ["binary"],
        POLICY: policies(jellyfin_ffmpeg6="6.0.1-1"),
        **installed("jellyfin", "apache2-utils", "jellyfin-ffmpeg6"),
        "stat -c %a ": ["750"],
        **fakehost.stat(KEYRING),
        **fakehost.file(LIST, repository_line(cfg)),
        **fakehost.directory("/etc/apt/sources.list.d"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, render_route(cfg, traefik_config(cfg, AUTH), _HASH)),
        **fakehost.service("jellyfin.service"),
    }
    for path in OWN_DIRS:
        responses.update(fakehost.stat(path, user="jellyfin", mode="drwxr-x---"))
    for path in MEDIA:
        responses.update(fakehost.stat(path, user="root", group="media", mode="drwxrwsr-x"))
    return overlay(responses, **{**{f"stat -c %a {path}": ["2775"] for path in MEDIA}, **drift})


def deploy(cfg: JellyfinConfig, responses: dict[str, Any], basic_auth: BasicAuth | None = AUTH) -> FakeRun:
    run = run_deploy_fake(deploy_jellyfin, cfg, basic_auth, responses=responses)
    assert run.succeeded, run.error
    return run


def changed(*names: str) -> list[str]:
    return [f"{P}{name}" for name in names]


def test_first_run_installs_everything(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, host_facts())

    commands = run.executed_commands
    key = next(c for c in commands if "gpg --batch --yes --dearmor" in c)
    update = commands.index("apt-get update")
    install = next(c for c in commands if "apt-get -y" in c and "install" in c and "jellyfin" in c)
    ffmpeg = next(c for c in commands if "for p in jellyfin-ffmpeg6 jellyfin-ffmpeg5 jellyfin-ffmpeg" in c)
    start = "systemctl start jellyfin.service"
    order = [key, commands[update], install, ffmpeg, start]
    assert [commands.index(c) for c in order] == sorted(commands.index(c) for c in order)
    assert "jellyfin" in install
    assert "apache2-utils" in install
    assert "jellyfin-ffmpeg6" not in install  # picked by the install step, after the cache refresh
    assert {LIST, ROUTE} <= set(run.uploaded_paths)
    assert run.upload(LIST).decode() == repository_line(cfg)
    assert f"{P}Install Jellyfin repository key" in run.mutating_changed_ops
    assert "systemctl enable jellyfin.service" in commands
    # Nothing restarts or reloads Traefik or Jellyfin.
    assert not any("restart" in c or "reload" in c for c in commands)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY


def test_first_run_creates_the_media_dirs_setgid_in_the_media_group(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, host_facts())

    for path in MEDIA:
        assert f"mkdir -p {path}" in run.executed_commands
        assert f"chmod =2775 {path}" in run.executed_commands
        assert f"chown root:media {path}" in run.executed_commands
    assert not any(YOUTUBE in c for c in run.executed_commands + run.fact_commands)
    for path in OWN_DIRS:
        assert f"chown jellyfin:jellyfin {path}" in run.executed_commands
        assert f"chmod =0750 {path}" in run.executed_commands


def test_second_run_changes_nothing_mutating(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    # No network fetch, no cache refresh, no install on a converged host.
    assert not any("curl -fsSL" in c or "apt-get" in c for c in run.executed_commands)
    assert not any("curl -fsSL" in c for c in run.fact_commands)


def test_converged_route_keeps_the_deployed_hash(cfg: JellyfinConfig) -> None:
    first = deploy(cfg, converged(cfg))
    second = deploy(cfg, converged(cfg))

    assert f"{P}Write Traefik route jellyfin" not in first.changed_ops + second.changed_ops
    assert ROUTE not in first.uploaded_paths + second.uploaded_paths


def test_password_rotation_only_rewrites_the_route(cfg: JellyfinConfig) -> None:
    rotated = BasicAuth(user="admin", password=SecretStr("rotated-fixture-pw"))

    run = deploy(cfg, converged(cfg), basic_auth=rotated)

    assert run.mutating_changed_ops == changed("Write Traefik route jellyfin")
    route = run.upload(ROUTE).decode()
    assert _HASH not in route
    assert '          - "admin:$2y$05$' in route
    assert not any("traefik" in c and "systemctl" in c for c in run.executed_commands)


def test_route_drift_is_repaired_with_the_same_hash(cfg: JellyfinConfig) -> None:
    deployed = render_route(cfg, traefik_config(cfg, AUTH), _HASH)
    drift = fakehost.file(ROUTE, deployed.replace("priority: 120", "priority: 1"))

    run = deploy(cfg, converged(cfg, **drift))

    assert run.mutating_changed_ops == changed("Write Traefik route jellyfin")
    assert run.upload(ROUTE).decode() == deployed


def test_missing_ffmpeg_candidate_is_installed_alone(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **installed("jellyfin", "apache2-utils")))

    assert run.mutating_changed_ops == changed("Update apt cache", "Install Jellyfin packages")
    install = next(c for c in run.executed_commands if "install" in c and "jellyfin-ffmpeg6" in c)
    assert "apache2-utils" not in install
    assert "--no-remove" in install


def test_first_candidate_with_a_version_wins(cfg: JellyfinConfig) -> None:
    drift = {
        **installed("jellyfin", "apache2-utils"),
        POLICY: policies(jellyfin_ffmpeg6="(none)", jellyfin_ffmpeg5="5.1.4-3", jellyfin_ffmpeg="4.4.1-1"),
    }

    run = deploy(cfg, converged(cfg, **drift))

    install = next(c for c in run.executed_commands if "install" in c and "jellyfin-ffmpeg" in c)
    assert "jellyfin-ffmpeg5" in install
    assert "jellyfin-ffmpeg6" not in install


def test_no_ffmpeg_candidate_continues_without(cfg: JellyfinConfig, caplog: pytest.LogCaptureFixture) -> None:
    drift = {**installed("jellyfin", "apache2-utils"), POLICY: policies(jellyfin_ffmpeg6="(none)")}

    run = deploy(cfg, converged(cfg, **drift))

    assert run.mutating_changed_ops == []
    assert "No jellyfin-ffmpeg package available" in caplog.text


def test_missing_base_package_is_installed_then_the_pick_runs_after_it(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **installed("jellyfin", "jellyfin-ffmpeg6")))

    # The pick waits for the base install (a new jellyfin pulls its own jellyfin-ffmpeg).
    assert run.mutating_changed_ops == changed(
        "Update apt cache", "Install Jellyfin packages", "Install the first available Jellyfin ffmpeg package"
    )
    commands = run.executed_commands
    install = next(c for c in commands if "install" in c and "apache2-utils" in c)
    assert "--no-remove" in install
    assert "jellyfin-ffmpeg6" not in install
    pick = next(c for c in commands if c.startswith("if dpkg-query"))
    assert commands.index("apt-get update") < commands.index(install) < commands.index(pick)
    assert not any("apt-cache policy" in c for c in run.fact_commands)


def test_an_installed_newer_jellyfin_ffmpeg_satisfies_the_pick(cfg: JellyfinConfig) -> None:
    # Current jellyfin depends on jellyfin-ffmpeg8, which conflicts with the role's candidates.
    run = deploy(cfg, converged(cfg, **installed("jellyfin", "apache2-utils", "jellyfin-ffmpeg8")))

    assert run.mutating_changed_ops == []
    assert not any("apt-cache policy" in c for c in run.fact_commands)


def test_held_packages_count_as_installed(cfg: JellyfinConfig) -> None:
    drift = {INSTALLED: ["hi |jellyfin|", "ii |apache2-utils|", "hi |jellyfin-ffmpeg6|", "rc |jellyfin-ffmpeg5|"]}

    run = deploy(cfg, converged(cfg, **drift))

    assert run.mutating_changed_ops == []


def test_packages_are_never_removed_to_install_another(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, host_facts())

    installs = [c for c in run.executed_commands if "apt-get" in c and " install " in c and "jellyfin" in c]
    assert installs
    assert all("--no-remove" in c for c in installs)
    assert not any(" remove " in c or " purge " in c or "autoremove" in c for c in run.executed_commands)


@pytest.mark.parametrize("state", ["armored", ""])
def test_missing_or_armored_keyring_is_reinstalled(cfg: JellyfinConfig, state: str) -> None:
    run = deploy(cfg, converged(cfg, **{KEYRING_STATE: [state] if state else []}))

    assert run.mutating_changed_ops == changed(
        "Install Jellyfin repository key",
        "Update apt cache",
        "Install the first available Jellyfin ffmpeg package",
    )
    key = next(c for c in run.executed_commands if "--dearmor" in c)
    assert "https://repo.jellyfin.org/ubuntu/jellyfin_team.gpg.key" in key
    assert f"mv -f {KEYRING}.ops-deploy-new {KEYRING}" in key


def test_list_file_drift_rewrites_it_and_refreshes_the_cache(cfg: JellyfinConfig) -> None:
    drift = fakehost.file(LIST, "deb https://repo.jellyfin.org/ubuntu jammy main\n")

    run = deploy(cfg, converged(cfg, **drift))

    assert run.mutating_changed_ops == changed(
        "Configure Jellyfin apt repository",
        "Update apt cache",
        "Install the first available Jellyfin ffmpeg package",
    )
    assert run.upload(LIST).decode() == repository_line(cfg)


def test_keyring_mode_is_repaired_alone(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **fakehost.stat(KEYRING, mode="-rw-------")))

    assert run.mutating_changed_ops == changed("Set Jellyfin keyring permissions")


def test_media_dir_without_setgid_gets_the_mode(cfg: JellyfinConfig) -> None:
    drift = {f"stat -c %a {MEDIA[0]}": ["755"], **fakehost.stat(MEDIA[0], group="root", mode="drwxr-xr-x")}

    run = deploy(cfg, converged(cfg, **drift))

    assert run.mutating_changed_ops == changed(f"Ensure {MEDIA[0]}", f"Set mode 2775 on {MEDIA[0]}")
    assert f"chmod =2775 {MEDIA[0]}" in run.executed_commands
    assert f"chown root:media {MEDIA[0]}" in run.executed_commands


def test_setgid_on_an_own_directory_is_cleared_as_ansible_does(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **{"stat -c %a /var/log/jellyfin": ["2750"]}))

    assert run.mutating_changed_ops == changed("Set mode 0750 on /var/log/jellyfin")
    assert "chmod =0750 /var/log/jellyfin" in run.executed_commands


@pytest.mark.parametrize(("mode", "chmod"), [("01777", "=1777"), ("0000", "=0000"), ("0755", "=0755")])
def test_media_mode_is_set_exactly_with_its_special_bits(cfg: JellyfinConfig, mode: str, chmod: str) -> None:
    # GNU ``chmod 1777`` would keep a directory's setgid bit; ``chmod =1777`` clears it.
    other = cfg.model_copy(update={"media_dir_mode": mode})

    run = deploy(other, converged(cfg))

    assert run.mutating_changed_ops == changed(*(f"Set mode {chmod[1:]} on {path}" for path in MEDIA))
    for path in MEDIA:
        assert f"chmod {chmod} {path}" in run.executed_commands


@pytest.mark.parametrize("tool", ["curl", "gpg"])
def test_missing_key_tools_fail_before_any_change(cfg: JellyfinConfig, tool: str) -> None:
    responses = overlay(host_facts(), **{f"command -v {tool}": []})

    run = run_deploy_fake(deploy_jellyfin, cfg, AUTH, responses=responses)

    # Refused while planning: nothing ran.
    assert not run.succeeded
    assert tool in str(run.error)
    assert [op.name for op in run.ops if op.changed] == []
    assert run.executed_commands == []


def test_key_tools_are_not_needed_on_a_converged_host(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **{"command -v curl": [], "command -v gpg": []}))

    assert run.mutating_changed_ops == []


def test_stopped_service_is_started(cfg: JellyfinConfig) -> None:
    run = deploy(cfg, converged(cfg, **fakehost.service("jellyfin.service", running=False)))

    assert run.mutating_changed_ops == changed("Enable and start jellyfin.service")
    assert "systemctl start jellyfin.service" in run.executed_commands


def test_missing_mount_stops_before_any_change(cfg: JellyfinConfig) -> None:
    responses = overlay(host_facts(), **{"findmnt --mountpoint /mnt/cryptdata": {"success": False, "stderr": "x"}})

    run = run_deploy_fake(deploy_jellyfin, cfg, AUTH, responses=responses)

    assert not run.succeeded
    assert [op.name for op in run.ops if op.changed] == []
    assert not any("gpg" in c or "apt-get" in c or "mkdir" in c for c in run.executed_commands)


@pytest.mark.parametrize(
    ("os_release", "machine"),
    [("ubuntu|questing", "x86_64"), ("debian|noble", "x86_64"), ("ubuntu|noble", "aarch64"), ("", "x86_64")],
)
def test_host_other_than_the_frozen_repo_settings_is_refused(
    cfg: JellyfinConfig, os_release: str, machine: str
) -> None:
    responses = overlay(host_facts(), **{OS_RELEASE: [os_release] if os_release else [], "uname -m": [machine]})

    run = run_deploy_fake(deploy_jellyfin, cfg, AUTH, responses=responses)

    # Refused while planning: no operation exists, nothing ran.
    assert not run.succeeded
    assert "jellyfin" in str(run.error)
    assert run.ops == []
    assert run.executed_commands == []


def test_unknown_distribution_maps_like_the_role() -> None:
    cfg = JellyfinConfig(repo_distro="debian", repo_release="vera", repo_arch="amd64", mounts_required=())
    responses = converged(cfg, **{OS_RELEASE: ["linuxmint|vera"]})

    run = deploy(cfg, responses)

    assert f"{P}Install Jellyfin packages" not in run.changed_ops


def test_without_repo_configuration_no_repo_is_touched(cfg: JellyfinConfig) -> None:
    plain = cfg.model_copy(update={"configure_repo": False})
    # A host the frozen settings do not describe: not checked when the repository is not managed.
    responses = converged(plain, **{OS_RELEASE: ["debian|bookworm"]})

    run = deploy(plain, responses)

    assert run.mutating_changed_ops == []
    assert not any(KEYRING in c or LIST in c for c in run.fact_commands + run.executed_commands)


def test_traefik_disabled_writes_no_route(cfg: JellyfinConfig) -> None:
    plain = cfg.model_copy(update={"traefik_enabled": False})

    run = deploy(plain, host_facts(), basic_auth=None)

    assert ROUTE not in run.uploaded_paths
    assert not any("/etc/traefik" in c for c in run.executed_commands)


def test_without_basic_auth_the_route_has_one_https_router(cfg: JellyfinConfig) -> None:
    plain = cfg.model_copy(update={"basic_auth_enabled": False})

    run = deploy(plain, host_facts(), basic_auth=None)

    route = run.upload(ROUTE).decode()
    assert "jellyfin-secure:" in route
    assert "basicAuth" not in route
    assert "jellyfin-int:" not in route


def test_without_media_dirs_none_are_managed(cfg: JellyfinConfig) -> None:
    plain = cfg.model_copy(update={"create_media_dirs": False})

    run = deploy(plain, host_facts())

    assert not any("/mnt/cryptdata/media" in c for c in run.executed_commands + run.fact_commands)


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_password_never_recorded(cfg: JellyfinConfig, scenario: str) -> None:
    rotated = "r" * 60
    auth = BasicAuth(user="admin", password=SecretStr(rotated)) if scenario == "rotated" else AUTH

    run = deploy(cfg, host_facts() if scenario == "first" else converged(cfg), basic_auth=auth)

    text = run.all_text() + repr(run.ops) + "".join(stdin for _, stdin in run.stdin)
    for value in (PASSWORD, rotated):
        assert value not in text


@pytest.mark.parametrize(
    ("changes", "basic_auth", "match"),
    [
        ({}, None, "basic_auth is required"),
        ({"basic_auth_enabled": False}, AUTH, "basic_auth given"),
        ({"traefik_enabled": False}, AUTH, "basic_auth given"),
        ({}, BasicAuth(user="admin", password=SecretStr("CHANGEME")), "placeholder"),
    ],
)
def test_basic_auth_rules_fail_before_any_operation(
    cfg: JellyfinConfig, changes: dict[str, Any], basic_auth: BasicAuth | None, match: str
) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_jellyfin, cfg.model_copy(update=changes), basic_auth, responses=host_facts())
    assert PASSWORD not in str(excinfo.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"media_directories": ()},
        {"media_directories": ("/mnt/media/../etc",)},
        {"media_directories": ("relative/path",)},
        {"media_directories": (MEDIA[0], MEDIA[0])},
        {"media_directories": ("/var/lib/jellyfin",)},
        {"media_dir_mode": "rwx"},
        {"media_dir_group": "Media Group"},
        {"traefik_entrypoints": ()},
        {"traefik_entrypoints": ("true",)},
        {"traefik_entrypoints": ("web secure",)},
        {"traefik_cert_resolver": "le: x"},
        {"traefik_middlewares": ("a, b",)},
        {"internal_ip_ranges": ()},
        {"internal_ip_ranges": ("not-a-network",)},
        {"internal_ip_ranges": ("10.0.0.0/8`) || Host(`x",)},
        {"traefik_host": "media example"},
        {"repo_base": "http://repo.jellyfin.org"},
        {"repo_base": "https://repo.jellyfin.org/x y"},
        {"repo_release": "noble main"},
        {"repo_key_url": "https://repo.jellyfin.org/$(id)"},
        {"packages_base": ()},
        {"packages_base": ("jellyfin", "jellyfin")},
        {"ffmpeg_candidates": ("jellyfin",)},
        {"healthcheck_expected_statuses": (99,)},
        {"healthcheck_url": "http://127.0.0.1:8096/$(id)"},
        {"healthcheck_url": "ftp://127.0.0.1/"},
    ],
)
def test_config_validation(overrides: dict[str, Any]) -> None:
    base = {"repo_distro": "ubuntu", "repo_release": "noble", "repo_arch": "amd64"}
    with pytest.raises((ConfigValidationError, ValueError)):
        JellyfinConfig(**{**base, **overrides})


def test_repo_settings_have_no_default() -> None:
    with pytest.raises(ValueError, match="repo_distro"):
        JellyfinConfig()  # type: ignore[call-arg]


def test_key_url_follows_the_distribution() -> None:
    cfg = JellyfinConfig(repo_distro="debian", repo_release="bookworm", repo_arch="arm64")

    assert cfg.key_url == "https://repo.jellyfin.org/debian/jellyfin_team.gpg.key"
    assert repository_line(cfg) == (
        f"deb [signed-by={KEYRING} arch=arm64] https://repo.jellyfin.org/debian bookworm main\n"
    )
