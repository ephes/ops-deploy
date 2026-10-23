"""Guarded Traefik transactions, ported from ops-library's ``traefik_deploy`` role.

:mod:`ops_deploy.infra.traefik_tx.engine` is the program that runs on the host
(standard library only, as root under ``/usr/bin/python3``). Nothing in
ops-deploy uploads or starts it yet; see ``docs/traefik.md``.
"""
