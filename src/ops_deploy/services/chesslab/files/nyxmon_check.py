# Run by ``manage.py shell -c`` in the Nyxmon site, after a ``PARAMS = {...}``
# line the deploy prepends. The playbook's "Upsert Nyxmon health check" step,
# plus a read-only "check" mode that prints "unchanged" when an "apply" would
# not write anything (the playbook always reports a change).
from nyxboard.models import HealthCheck, Service

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

wanted = {
    "check_type": "http",
    "url": P["url"],
    "check_interval": 300,
    "disabled": False,
    "data": {"timeout": 5, "retries": 1, "retry_delay": 2},
}
service = Service.objects.filter(name=P["service"]).first()
check = HealthCheck.objects.filter(name=P["name"], service=service).first() if service else None
stale = [name for name, value in wanted.items() if check is None or getattr(check, name) != value]
if not stale:
    print("unchanged")
elif P["mode"] == "check":
    print("pending")
else:
    service, _ = Service.objects.get_or_create(name=P["service"])
    check, created = HealthCheck.objects.get_or_create(name=P["name"], service=service, defaults=wanted)
    for name, value in wanted.items():
        setattr(check, name, value)
    check.save()
    print("created" if created else "updated")
