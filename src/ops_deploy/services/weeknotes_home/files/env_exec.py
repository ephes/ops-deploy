# Uploaded to the host and run with the venv's interpreter:
#   python env_exec.py ENV_FILE PROGRAM [ARGS...]
# Reads the KEY="value" lines of ENV_FILE (undoing the escapes the env template
# applies), then replaces itself by PROGRAM run with that interpreter, so
# secrets never reach a command line. A file, not ``python -c``: the source
# then never passes through the remote shells (root's login shell on macmini
# is fish, which treats backslashes in single quotes as escapes).
import os
import re
import sys

env = dict(os.environ)
with open(sys.argv[1]) as fh:
    for line in fh:
        key, sep, value = line.rstrip("\n").partition("=")
        if not sep or not key or key.startswith("#"):
            continue
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = re.sub(r'\\(["\\])', r"\1", value[1:-1])
        env[key] = value
os.execve(sys.executable, [sys.executable, *sys.argv[2:]], env)
