# ops-deploy

Typed [pyinfra](https://pyinfra.com) deploys for self-hosted services.

This is the public half of a pyinfra-based deployment setup: typed service
configuration and deploy functions. Inventory and SOPS-encrypted secrets live
in a separate private repository, which builds a config, decrypts its secrets
on the controller and calls a deploy function from here.

Status: foundation. It contains the configuration base class, secret
references, the `sync_tree` and `secret_file` operations, deploy helpers
(users, systemd, uv/Django, Traefik, health checks), an in-process test
harness, two toy services, the nyxmon, fastdeploy and delve services and host-level
base deploys (hostname, unit masks, headless mode, authorized keys, uv,
Node.js, shell basics, SSH guard) and the shared host services PostgreSQL, Redis and
Traefik (deploy, backup, restore, remove).

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) and [just](https://just.systems)
- pyinfra is pinned to `3.10.*`

## Development

```bash
just sync        # create the locked environment
just test        # pytest (in-process, no network)
just typecheck   # mypy --strict
just lint        # ruff check + format check
just docs        # mkdocs build --strict
just check       # all of the above, as CI runs it
```

Documentation lives in `docs/` (`just docs-serve` to browse it).

## License

MIT
