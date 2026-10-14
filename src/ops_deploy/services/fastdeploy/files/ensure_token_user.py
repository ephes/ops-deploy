"""Create a FastDeploy user that cannot log in with a password.

Run with FastDeploy's own interpreter and the site directory as working
directory. The user is created by FastDeploy's ``commands.py createuser``;
this wrapper only supplies its inputs in-process: the name read from stdin and
the hash of a random password that is generated here and never stored or
printed. Neither appears on a command line.

``createuser`` exits 0 when the user already exists and prints the database
error, which can quote the hash: callers must not log the output.
"""

import os
import runpy
import secrets
import sys

sys.path.insert(0, "src")

from deploy.auth import get_password_hash  # noqa: E402

username = sys.stdin.readline().strip()
if not username:
    sys.exit("no user name on stdin")

os.environ["INITIAL_USER_NAME"] = username
os.environ["INITIAL_PASSWORD_HASH"] = get_password_hash(secrets.token_urlsafe(48))
# createuser prints through rich, which wraps at the terminal width; keep its
# messages on one line so the caller can recognise them.
os.environ["COLUMNS"] = "1000"
sys.argv = ["commands.py", "createuser"]
runpy.run_path("commands.py", run_name="__main__")
