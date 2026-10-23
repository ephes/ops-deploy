"""Guarded Traefik transactions, ported from ops-library's ``traefik_deploy`` role.

:mod:`ops_deploy.infra.traefik_tx.engine` is the program that runs on the host
(standard library only, as root under ``/usr/bin/python3``);
:mod:`ops_deploy.infra.traefik_tx.proof`, next to it there, makes the isolated
compatibility proof its ``binary`` action requires. Nothing in ops-deploy
uploads or starts either yet; see ``docs/traefik.md``.
"""
