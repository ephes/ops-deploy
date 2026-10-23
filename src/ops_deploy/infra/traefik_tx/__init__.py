"""Guarded Traefik transactions, ported from ops-library's ``traefik_deploy`` role.

:mod:`ops_deploy.infra.traefik_tx.engine` is the program that runs on the host
(standard library only, as root under ``/usr/bin/python3``);
:mod:`ops_deploy.infra.traefik_tx.proof`, next to it there, makes the isolated
compatibility proof its ``binary`` action requires.
:mod:`ops_deploy.infra.traefik_tx.transport` runs the engine detached in a
transient systemd unit there, with :mod:`ops_deploy.infra.traefik_tx.runner` as
the host side and a safe-restore unit for an interrupted engine. Nothing calls
the transport or uploads the proof yet; see ``docs/traefik.md``.
"""
