# Run by ``manage.py shell -c`` in the Nyxmon site, after a ``PARAMS = {...}``
# line the deploy prepends. The playbook's "Upsert Nyxmon health check for the
# work app" step, plus a read-only "check" mode that prints "unchanged" when an
# "apply" would not write anything (the playbook always reports a change).
# Earlier deploys created "Work app login page"; that check is reused and
# renamed, as the playbook does.
from nyxboard.models import HealthCheck, Service

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

wanted = {
    "name": P["name"],
    "check_type": "http",
    "url": P["url"],
    "check_interval": 300,
    "disabled": False,
    "data": {"timeout": 5, "retries": 1, "retry_delay": 2},
}
service = Service.objects.filter(name=P["service"]).first()
check = None
if service is not None:
    check = HealthCheck.objects.filter(service=service, name=P["name"]).first()
    if check is None:
        check = HealthCheck.objects.filter(service=service, name=P["legacy_name"]).first()
stale = [name for name, value in wanted.items() if check is None or getattr(check, name) != value]
if not stale:
    print("unchanged")
elif P["mode"] == "check":
    print("pending")
else:
    service, _ = Service.objects.get_or_create(name=P["service"])
    created = check is None
    if created:
        check = HealthCheck(service=service)
    for name, value in wanted.items():
        setattr(check, name, value)
    check.save()
    print("created" if created else "updated")
