"""Incident upgrade of existing, role-managed Mastodon 4.6.9 to 4.7.4."""

from pathlib import Path
from shlex import quote

from pyinfra.operations import files, server


def upgrade_mastodon(domain: str) -> None:
    """Back up and upgrade an existing installation; not a bootstrap deploy."""
    script = "/usr/local/libexec/mastodon-upgrade-4.7.4"
    files.directory(name="Ensure upgrade script directory", path="/usr/local/libexec", mode="755")
    files.put(
        name="Install Mastodon incident upgrade script",
        src=str(Path(__file__).parent / "files" / "upgrade.sh"),
        dest=script,
        user="root",
        group="root",
        mode="700",
    )
    for step in (
        "preflight",
        "backup",
        "runtime",
        "dependencies",
        "assets",
        "pre-migrate",
        "restart",
        "post-migrate",
        "verify",
    ):
        server.shell(
            name=f"Mastodon 4.7.4 | {step}",
            commands=f"{script} {quote(step)} {quote(domain)}",
        )
