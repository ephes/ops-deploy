"""Transitional: django_site does what services/heis does, scenario by scenario.

Every fake-connector scenario of ``test_heis.py`` runs through both
``deploy_heis`` and ``deploy_django_site`` (configured like ops-control's heis
SiteSpec) with the same facts, each host holding the files its own module
writes. The normalized transcripts (fact and executed commands, uploads,
stdin) must be equal except for:

- the marker fact and the marker ``touch``/``rm`` operations, which only
  change runs execute, and the primary-group facts (``id -gn`` and the move
  marker; the old module never fixed an existing user's group);
- the markers' place: ``/var/lib/ops-deploy/heis/`` instead of the home
  (normalized, so the content marker's operations are still compared);
- the content of the files the canonical file set changes on purpose
  (``docs/services/django_site.md``): the launcher, the unit, the route and
  the fish config are django_site's renders, and ``.env`` carries the same
  keys and values in its own quoting;
- the byte count in ``.env``'s install command (a different length).

This file goes when ``services/heis`` is removed (after heis production runs
django_site).
"""

from __future__ import annotations

import base64
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.django_site import deploy_django_site
from ops_deploy.services.django_site.django import admin_stamp
from ops_deploy.services.django_site.render import render, render_env
from ops_deploy.services.heis import HeisConfig, deploy_heis
from ops_deploy.services.heis.deploy import render_route as render_heis_route
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests import test_heis as old
from tests.django_site_fixtures import from_heis
from tests.heis_fixtures import make_source

HOME = "/home/heis"
SITE = f"{HOME}/site"
ENV = f"{SITE}/.env"
LAUNCHER = f"{SITE}/gunicorn.sh"
FISH = f"{HOME}/.config/fish/config.fish"
UNIT = "/etc/systemd/system/heis.service"
ROUTE = "/etc/traefik/dynamic/heis.traefik.yml"
STAMP = f"{HOME}/.ops-deploy-admin"
ITEMIZED_CHANGE = [">f.st...... apps/heis/views.py"]
RECORD = f"{SITE}/.ops-deploy-source"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
MARKER_FACT = "grep -x -e .ops-deploy-pending"
STATE = "/var/lib/ops-deploy/heis"
# The markers' place: the old module kept them in the home, django_site in a
# root-only directory it creates with its first marker.
NEW_PLACE = (f"install -d -o root -g root -m 0700 {STATE} && ", f"{STATE}/")
GROUP_FACTS = ("id -gn heis", f"cat {STATE}/.ops-deploy-regroup")
MARKER_OPS = {
    f"{NEW_PLACE[0]}touch {STATE}/.ops-deploy-pending",
    f"{NEW_PLACE[0]}touch {STATE}/.ops-deploy-restart-heis",
    f"rm -f {STATE}/.ops-deploy-pending {STATE}/.ops-deploy-restart-heis",
}
MARK_SOURCE = "Deploy heis | Mark the heis source change pending"
MARK_RESTART = "Deploy heis | Mark heis for a restart"
CLEAR = "Deploy heis | Clear the pending markers"
MARKER_OP_NAMES = {MARK_SOURCE, MARK_RESTART, CLEAR}
SOURCE_MARKERS = frozenset({MARK_SOURCE, CLEAR})
RESTART_MARKERS = frozenset({MARK_RESTART, CLEAR})
# pyinfra reads the host's temp directory once, at its first upload: not a deploy step.
TEMP_DIR_FACT = 'if [ -n "$TMPDIR" ]'
ROTATED = {"django_secret_key": "rotated-fixture-django-key-0123456789"}
PRODUCTION = {
    "setup_default_pages": False,
    "seed_content": False,
    "serve_media": True,
    "traefik_tls_host_rule": "Host(`heis.example.com`) || Host(`www.heis.example.com`)",
    "traefik_canonical_redirect_regex": r"^https?://www\.heis\.example\.com(.*)$",
    "traefik_canonical_redirect_replacement": "https://heis.example.com${1}",
    "django_allowed_hosts": "heis.example.com,www.heis.example.com,localhost",
}


@dataclass(frozen=True)
class Scenario:
    first: bool = False
    rsync: dict[str, list[str]] = field(default_factory=dict)
    facts: Callable[[SecretValues], dict[str, Any]] = lambda _secrets: {}
    drift: dict[str, str] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    cfg: dict[str, Any] = field(default_factory=dict)
    # Marker operations django_site adds to the run.
    markers: frozenset[str] = frozenset()


SCENARIOS = {
    "first run": Scenario(first=True, rsync={"--dry-run": ITEMIZED_CHANGE}, markers=frozenset(MARKER_OP_NAMES)),
    "first run, production": Scenario(
        first=True, rsync={"--dry-run": ITEMIZED_CHANGE}, cfg=PRODUCTION, markers=frozenset(MARKER_OP_NAMES)
    ),
    "converged": Scenario(),
    "converged, production": Scenario(cfg=PRODUCTION),
    "code change": Scenario(rsync={"--dry-run": ITEMIZED_CHANGE}, markers=SOURCE_MARKERS),
    "code change, production": Scenario(rsync={"--dry-run": ITEMIZED_CHANGE}, cfg=PRODUCTION, markers=SOURCE_MARKERS),
    "env change": Scenario(secrets=ROTATED, markers=RESTART_MARKERS),
    "admin url change": Scenario(secrets={"django_admin_url": "rotated-admin/"}, markers=RESTART_MARKERS),
    "admin password change": Scenario(secrets={"admin_password": "rotated-fixture-admin-pw"}),
    "not a superuser": Scenario(facts=lambda s: {old.ADMIN_PROBE: old.admin_rows(s)[1:]}),
    "other email": Scenario(facts=lambda s: {old.ADMIN_PROBE: old.admin_rows(s)[:1]}),
    "unapplied migrations": Scenario(facts=lambda _s: {"migrate --check": []}),
    "failing migrations probe": Scenario(facts=lambda _s: {"migrate --check": [FAILED]}),
    "stale environment": Scenario(facts=lambda _s: {"--python 3.13 --dry-run": []}, markers=SOURCE_MARKERS),
    "missing static manifest": Scenario(facts=lambda _s: {"staticfiles.json": []}),
    "wrong ownership": Scenario(facts=lambda _s: {"-print -quit": [f"{SITE}/media/x.jpg"]}),
    "leftover content marker": Scenario(facts=lambda _s: {".ops-deploy-content-pending": ["pending"]}),
    "launcher change": Scenario(drift={LAUNCHER: "#!/bin/sh\n"}, markers=RESTART_MARKERS),
    "unit change": Scenario(drift={UNIT: "[Unit]\n"}, markers=RESTART_MARKERS),
    "route change": Scenario(drift={ROUTE: "http: {}\n"}),
    "prerequisite missing": Scenario(facts=lambda _s: fakehost.deb_installed("fish", "rsync")),
    "git source recorded": Scenario(cfg={"source_commit": COMMIT}),
    "git source again": Scenario(
        cfg={"source_commit": COMMIT}, facts=lambda _s: fakehost.file(RECORD, f"{COMMIT}\n", user="heis")
    ),
    "another commit": Scenario(
        cfg={"source_commit": COMMIT}, facts=lambda _s: fakehost.file(RECORD, f"{'f' * 40}\n", user="heis")
    ),
    "local source forgets the record": Scenario(facts=lambda _s: fakehost.file(RECORD, f"{COMMIT}\n", user="heis")),
}


def parse_env(text: str) -> dict[str, str]:
    """``KEY=value`` lines as ``sh`` reads them (comments and blank lines skipped)."""

    pairs = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            [pairs[key]] = shlex.split(value)
    return pairs


def _normalized(command: str) -> str:
    # The decoded length of .env, an argument of its installer, and the
    # content marker's place.
    command = command.replace(NEW_PLACE[0], "").replace(NEW_PLACE[1], f"{HOME}/")
    return re.sub(r"( \.env \S+ )\d+( 0600)", r"\1<size>\2", command)


def transcript(run: FakeRun) -> list[tuple[str, str, str]]:
    events: list[tuple[str, str, str]] = []
    for event in run.events:
        if event.kind == "fact" and (
            MARKER_FACT in event.value or event.value.startswith((TEMP_DIR_FACT, *GROUP_FACTS))
        ):
            continue
        if event.kind == "shell" and event.value in MARKER_OPS:
            continue
        events.append((event.phase, event.kind, _normalized(event.value)))
    return events


def _payload(text: str) -> str:
    try:
        return base64.b64decode("".join(text.split()), validate=True).decode()
    except ValueError:
        return text


def new_files(cfg: HeisConfig, secrets: SecretValues) -> dict[str, str]:
    site = from_heis(cfg)
    assert site.admin is not None
    return {
        ENV: render_env(site, secrets).reveal().decode(),
        LAUNCHER: render("gunicorn.sh.j2", site),
        FISH: render("config.fish.j2", site),
        UNIT: render("unit.service.j2", site),
        ROUTE: render("route.traefik.yml.j2", site),
        STAMP: admin_stamp(site, site.admin, secrets),
    }


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_django_site_runs_what_heis_runs(tmp_path: Path, name: str) -> None:
    scenario = SCENARIOS[name]
    heis = HeisConfig.model_validate(
        {
            "source_path": make_source(tmp_path),
            "secrets": SecretRef("secrets/prod/heis.yml"),
            "fqdn": old.FQDN,
            "traefik_host_rule": f"Host(`{old.FQDN}`) || Host(`www.{old.FQDN}`)",
            **scenario.cfg,
        }
    )
    # The host as the scenario finds it: deployed with the same config, minus the record.
    base = heis.model_copy(update={"source_commit": None})
    site = from_heis(heis)
    secrets = old.values(heis)
    used = old.values(heis, **scenario.secrets)
    if scenario.first:
        old_facts, new_facts = old.first_host(), old.first_host()
    else:
        extra = scenario.facts(secrets)
        old_facts = {**old.converged(base, secrets, **scenario.drift), **extra}
        new_facts = {**old.converged(base, secrets, **{**new_files(base, secrets), **scenario.drift}), **extra}

    before = run_deploy_fake(
        deploy_heis, heis, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=old_facts
    )
    after = run_deploy_fake(
        deploy_django_site, site, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=new_facts
    )

    assert before.succeeded, before.error
    assert after.succeeded, after.error
    assert transcript(after) == transcript(before)
    assert [op for op in after.mutating_changed_ops if op not in MARKER_OP_NAMES] == before.mutating_changed_ops
    assert {op for op in after.mutating_changed_ops if op in MARKER_OP_NAMES} == scenario.markers
    # Uploads: the same paths; the documented files carry django_site's render.
    assert after.uploaded_paths == before.uploaded_paths
    documented = {path: text for path, text in new_files(heis, used).items() if path not in (ENV, STAMP)}
    for (path, new), (_, previous) in zip(after.uploads, before.uploads, strict=True):
        assert new == (documented[path].encode() if path in documented else previous), path
    # Stdin: the same commands and payloads; .env as the same keys and values.
    assert len(after.stdin) == len(before.stdin)
    for (command, new_payload), (previous_command, previous_payload) in zip(after.stdin, before.stdin, strict=True):
        assert _normalized(command) == _normalized(previous_command)
        if " .env " in command:
            assert parse_env(_payload(new_payload)) == parse_env(_payload(previous_payload))
        else:
            assert new_payload == previous_payload


def test_the_production_route_keeps_the_canonical_redirect(tmp_path: Path) -> None:
    heis = HeisConfig.model_validate(
        {
            "source_path": make_source(tmp_path),
            "secrets": SecretRef("secrets/prod/heis.yml"),
            "fqdn": old.FQDN,
            "traefik_host_rule": f"Host(`{old.FQDN}`)",
            **PRODUCTION,
        }
    )
    route = render("route.traefik.yml.j2", from_heis(heis))

    # The heis role's route below django_site's two header lines.
    assert route.split("\n", 2)[2] == render_heis_route(heis)
