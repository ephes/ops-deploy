# Run by nyxmon's ``manage.py shell -c`` as the nyxmon user. Port of the
# "Upsert the Nyxmon health check" task in deploy-opaq-app.yml.
# OPAQ_NYXMON (JSON) holds the check; with "apply" false it only prints
# "unchanged" or "pending" and writes nothing.
import json
import os

from nyxboard.models import HealthCheck, Service

params = json.loads(os.environ["OPAQ_NYXMON"])
wanted = {
    "name": params["check_name"],
    "check_type": "http",
    "url": params["url"],
    "check_interval": params["interval"],
    "disabled": False,
    "data": params["data"],
}
service = Service.objects.filter(name=params["service_name"]).first()
check = None if service is None else HealthCheck.objects.filter(service=service, name=params["check_name"]).first()
changes = wanted if check is None else {key: value for key, value in wanted.items() if getattr(check, key) != value}
if service is not None and check is not None and not changes:
    print("unchanged")
elif not params["apply"]:
    print("pending")
else:
    if service is None:
        service = Service.objects.create(name=params["service_name"])
    if check is None:
        check = HealthCheck(service=service)
    for key, value in wanted.items():
        setattr(check, key, value)
    check.save()
    print("updated")
