"""The files the old haushalt deploy script (its own repository, 2026-10-29) wrote, for synthetic values.

Copied from that script's templates and rendered by hand for the fixture host
``haushalt.example.invalid``; independent of this repository's templates, so the
takeover test sees any unintended change to values, unit settings or routing.
"""

LEGACY_ENV = """\
# haushalt environment - managed by deploy/deploy.py in the haushalt repo, do not edit
DJANGO_SETTINGS_MODULE=site_config.settings
DJANGO_SECRET_KEY={secret_key}
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=haushalt.example.invalid,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=https://haushalt.example.invalid
HAUSHALT_DATABASE_PATH=/home/haushalt/data/db.sqlite3
DJANGO_STATIC_ROOT=/home/haushalt/static
HAUSHALT_UPLOAD_TOKEN_SHA256={token_sha256}
"""

LEGACY_UNIT = """\
# haushalt - managed by deploy/deploy.py in the haushalt repo, do not edit
[Unit]
Description=haushalt (family finance dashboard behind a login)
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
User=haushalt
Group=haushalt
WorkingDirectory=/home/haushalt/site/web
EnvironmentFile=/home/haushalt/haushalt.env
UMask=0077
ExecStart=/home/haushalt/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:10067 \
--forwarded-allow-ips 127.0.0.1 --access-logfile - site_config.wsgi:application

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/home/haushalt/data
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=512M

[Install]
WantedBy=multi-user.target
"""

LEGACY_ROUTE = """\
# haushalt - managed by deploy/deploy.py in the haushalt repo, do not edit.
# The tailnet allowlist is the first barrier, the Django login the second.
http:
  routers:
    haushalt-secure:
      rule: "Host(`haushalt.example.invalid`)"
      entryPoints:
        - web-secure
      middlewares:
        - haushalt-allowlist
      service: haushalt
      tls: {}
    haushalt-http:
      rule: "Host(`haushalt.example.invalid`)"
      entryPoints:
        - web
      middlewares:
        - haushalt-allowlist
        - haushalt-redirect
      service: noop@internal

  middlewares:
    haushalt-allowlist:
      ipAllowList:
        sourceRange: ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
    haushalt-redirect:
      redirectScheme:
        scheme: https
        permanent: true

  services:
    haushalt:
      loadBalancer:
        passHostHeader: true
        servers:
          - url: "http://127.0.0.1:10067"
"""
