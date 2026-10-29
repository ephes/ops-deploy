"""Django-shell program for only the explicitly declared Paperless accounts.

No unrelated user enumeration and no returned names/email/password verifiers.
Existing bootstrap passwords are never reset. Missing strict promotion targets
fail after the same earlier creation/promotions as the original role.
"""


def inspect_admin(settings):
    from django.contrib.auth import get_user_model

    users = get_user_model().objects
    create = settings["manage_superuser"] and not users.filter(username=settings["admin_user"]).exists()
    promote, missing = [], []
    for index, username in enumerate(settings["existing_superusers"]):
        flags = users.filter(username=username).values_list("is_active", "is_staff", "is_superuser").first()
        if flags is None:
            missing.append(index)
        elif not all(flags):
            promote.append(index)
    return {"create": bool(create), "promote": promote, "missing": missing}


def apply_admin(settings):
    from django.contrib.auth import get_user_model

    users = get_user_model().objects
    changed = 0
    if settings["manage_superuser"] and not users.filter(username=settings["admin_user"]).exists():
        users.create_superuser(settings["admin_user"], settings["admin_email"], settings["admin_password"])
        changed += 1
    missing = 0
    for username in settings["existing_superusers"]:
        user = users.filter(username=username).only("id", "is_active", "is_staff", "is_superuser").first()
        if user is None:
            missing += 1
            continue
        fields = []
        for field in ("is_active", "is_staff", "is_superuser"):
            if not getattr(user, field):
                setattr(user, field, True)
                fields.append(field)
        if fields:
            user.save(update_fields=fields)
            changed += 1
    if missing and settings["existing_superusers_strict"]:
        raise RuntimeError("configured promotion targets are missing after earlier account changes")
    return {"changed": changed, "missing": missing}
