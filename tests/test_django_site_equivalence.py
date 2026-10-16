"""Transitional: django_site does what services/marina does, scenario by scenario.

Every fake-connector scenario of ``test_marina.py`` runs through both
``deploy_marina`` and ``deploy_django_site`` (configured like marina) with the
same facts, each host holding the files its own module writes. The normalized
transcripts (fact and executed commands, uploads, stdin) must be equal except
for:

- the marker fact and the marker ``touch``/``rm`` operations, which only
  change runs execute;
- the content of the files the canonical file set changes on purpose
  (``docs/services/django_site.md``): the launcher, the unit, the route and
  the fish config are django_site's renders, and ``.env`` carries the same
  keys and values in its own quoting;
- the byte count in ``.env``'s install command (a different length).

This file goes when ``services/marina`` is removed.
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
from ops_deploy.services.django_site.render import render
from ops_deploy.services.marina import MarinaConfig, deploy_marina
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests import test_marina as old
from tests.django_site_fixtures import ADMIN_PROBE, FISH, LAUNCHER, ROUTE, SITE, UNIT, converged, from_marina, values
from tests.marina_fixtures import make_source

ITEMIZED_CHANGE = [">f.st...... apps/marina/views.py"]
RECORD = f"{SITE}/.ops-deploy-source"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
MARKER_FACT = "ls -1A | grep -x -e .ops-deploy-pending"
MARKER_OPS = {
    "touch /home/marina/.ops-deploy-pending",
    "touch /home/marina/.ops-deploy-restart-marina",
    "rm -f /home/marina/.ops-deploy-pending /home/marina/.ops-deploy-restart-marina",
}
MARKER_OP_NAMES = {
    "Deploy marina | Mark the marina source change pending",
    "Deploy marina | Mark marina for a restart",
    "Deploy marina | Clear the pending markers",
}
SOURCE_MARKERS = frozenset(
    {"Deploy marina | Mark the marina source change pending", "Deploy marina | Clear the pending markers"}
)
RESTART_MARKERS = frozenset({"Deploy marina | Mark marina for a restart", "Deploy marina | Clear the pending markers"})
# pyinfra reads the host's temp directory once, at its first upload: not a deploy step.
TEMP_DIR_FACT = 'if [ -n "$TMPDIR" ]'
ROTATED = {"django_secret_key": "rotated-fixture-django-key-0123456789"}


@dataclass(frozen=True)
class Scenario:
    first: bool = False
    rsync: dict[str, list[str]] = field(default_factory=dict)
    facts: Callable[[SecretValues], dict[str, Any]] = lambda _secrets: {}
    drift: dict[str, str] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    cfg: dict[str, Any] = field(default_factory=dict)
    # Expected mutating changes beyond the converged run, by marker ops (django_site only).
    markers: frozenset[str] = frozenset()


SCENARIOS = {
    "first run": Scenario(first=True, rsync={"--dry-run": ITEMIZED_CHANGE}, markers=frozenset(MARKER_OP_NAMES)),
    "converged": Scenario(),
    "code change": Scenario(
        rsync={"--dry-run": ITEMIZED_CHANGE},
        markers=frozenset(
            {"Deploy marina | Mark the marina source change pending", "Deploy marina | Clear the pending markers"}
        ),
    ),
    "env change": Scenario(
        secrets=ROTATED,
        markers=RESTART_MARKERS,
    ),
    "admin password change": Scenario(secrets={"admin_password": "rotated-fixture-admin-pw"}),
    "not a superuser": Scenario(facts=lambda s: {ADMIN_PROBE: old.admin_rows(s)[1:]}),
    "other email": Scenario(facts=lambda s: {ADMIN_PROBE: old.admin_rows(s)[:1]}),
    "unapplied migrations": Scenario(facts=lambda _s: {"migrate --check": []}),
    "failing migrations probe": Scenario(facts=lambda _s: {"migrate --check": [FAILED]}),
    "stale environment": Scenario(
        facts=lambda _s: {"--python 3.13 --dry-run": []},
        markers=frozenset(
            {"Deploy marina | Mark the marina source change pending", "Deploy marina | Clear the pending markers"}
        ),
    ),
    "missing static manifest": Scenario(facts=lambda _s: {"staticfiles.json": []}),
    "wrong ownership": Scenario(facts=lambda _s: {"-print -quit": [f"{SITE}/media/x.jpg"]}),
    "launcher change": Scenario(
        drift={LAUNCHER: "#!/bin/sh\n"},
        markers=RESTART_MARKERS,
    ),
    "unit change": Scenario(
        drift={UNIT: "[Unit]\n"},
        markers=RESTART_MARKERS,
    ),
    "route change": Scenario(drift={ROUTE: "http: {}\n"}),
    "hardening": Scenario(
        cfg={"systemd_hardening": True},
        markers=RESTART_MARKERS,
    ),
    "git source recorded": Scenario(cfg={"source_commit": COMMIT}),
    "git source again": Scenario(
        cfg={"source_commit": COMMIT}, facts=lambda _s: fakehost.file(RECORD, f"{COMMIT}\n", user="marina")
    ),
    "another commit": Scenario(
        cfg={"source_commit": COMMIT}, facts=lambda _s: fakehost.file(RECORD, f"{'f' * 40}\n", user="marina")
    ),
    "local source forgets the record": Scenario(facts=lambda _s: fakehost.file(RECORD, f"{COMMIT}\n", user="marina")),
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
    # The decoded length of .env, an argument of its installer.
    return re.sub(r"( \.env \S+ )\d+( 0600)", r"\1<size>\2", command)


def transcript(run: FakeRun) -> list[tuple[str, str, str]]:
    events: list[tuple[str, str, str]] = []
    for event in run.events:
        if event.kind == "fact" and (MARKER_FACT in event.value or event.value.startswith(TEMP_DIR_FACT)):
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


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_django_site_runs_what_marina_runs(tmp_path: Path, name: str) -> None:
    scenario = SCENARIOS[name]
    marina = MarinaConfig.model_validate(
        {
            "source_path": make_source(tmp_path),
            "secrets": SecretRef("secrets/prod/marina.yml"),
            "fqdn": old.FQDN,
            "traefik_host_rule": f"Host(`{old.FQDN}`) || Host(`www.{old.FQDN}`)",
            **scenario.cfg,
        }
    )
    base_marina = marina.model_copy(update={"source_commit": None, "systemd_hardening": False})
    site, base_site = from_marina(marina), from_marina(base_marina)
    secrets = old.values(marina)
    used = old.values(marina, **scenario.secrets)
    if scenario.first:
        old_facts, new_facts = old.first_host(), old.first_host()
    else:
        extra = scenario.facts(secrets)
        old_facts = {**old.converged(base_marina, secrets, **scenario.drift), **extra}
        new_facts = {**converged(base_site, secrets, **scenario.drift), **extra}

    before = run_deploy_fake(
        deploy_marina, marina, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=old_facts
    )
    after = run_deploy_fake(
        deploy_django_site, site, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=new_facts
    )

    assert before.succeeded, before.error
    assert after.succeeded, after.error
    assert transcript(after) == transcript(before)
    marker_changes = [op for op in after.mutating_changed_ops if op in MARKER_OP_NAMES]
    assert [op for op in after.mutating_changed_ops if op not in MARKER_OP_NAMES] == before.mutating_changed_ops
    assert set(marker_changes) == scenario.markers
    # Uploads: the same paths; the documented files carry django_site's render.
    assert after.uploaded_paths == before.uploaded_paths
    documented = {
        LAUNCHER: render("gunicorn.sh.j2", site),
        UNIT: render("unit.service.j2", site),
        ROUTE: render("route.traefik.yml.j2", site),
        FISH: render("config.fish.j2", site),
    }
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


def test_the_equivalence_covers_every_documented_file(tmp_path: Path) -> None:
    site = from_marina(
        MarinaConfig(
            source_path=make_source(tmp_path),
            secrets=SecretRef("secrets/prod/marina.yml"),
            fqdn=old.FQDN,
            traefik_host_rule=f"Host(`{old.FQDN}`)",
        )
    )
    first = run_deploy_fake(
        deploy_django_site,
        site,
        values(site),
        rsync=RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE}),
        responses=old.first_host(),
    )
    assert {LAUNCHER, UNIT, ROUTE, FISH} <= set(first.uploaded_paths)
