"""Guarded Traefik transactions, ported from ops-library's ``traefik_deploy`` role.

:mod:`ops_deploy.infra.traefik_tx.engine` is the program that runs on the host
(standard library only, as root under ``/usr/bin/python3``).
:mod:`ops_deploy.infra.traefik_tx.transport` runs it detached in a transient
systemd unit there, with :mod:`ops_deploy.infra.traefik_tx.runner` as the host
side and a safe-restore unit for an interrupted engine. Nothing calls the
transport yet; see ``docs/traefik.md``.
"""
