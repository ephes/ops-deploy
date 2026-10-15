# Run by archive's ``manage.py shell -c`` as the archive user; read-only.
# One line per staff or superuser account:
#   <sha256(username)> <sha256(email)> <is_staff><is_superuser> <algorithm$iterations$salt> <sha256(password hash)>
# Names, addresses and password hashes are only printed as digests; the
# deploy compares them with the values it would set.
import hashlib

from django.contrib.auth import get_user_model
from django.db.models import Q


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


for user in get_user_model().objects.filter(Q(is_staff=True) | Q(is_superuser=True)):
    algorithm, _, rest = user.password.partition("$")
    iterations, _, rest = rest.partition("$")
    salt = rest.partition("$")[0]
    flags = f"{int(user.is_staff)}{int(user.is_superuser)}"
    print(digest(user.username), digest(user.email), flags, f"{algorithm}${iterations}${salt}", digest(user.password))
