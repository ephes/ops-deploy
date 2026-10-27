"""HTTP mirror transport before the shared checksum-pinned release installer.

Read the complete installer stdin before any early failure. Otherwise a soft
rollback's early exit can close SSH while pyinfra is still transmitting it.
"""

import pathlib
import subprocess
import sys

installer = sys.stdin.read()
upload, url, impl = sys.argv[1:4]
result = subprocess.run([
    "curl", "--fail", "--silent", "--show-error", "--location",
    "--connect-timeout", "15", "--max-time", "120", "--output", upload, url,
], check=False)
if result.returncode:
    pathlib.Path(upload).unlink(missing_ok=True)
    print("WARNING: Rust archive download failed; Python rollback continues" if impl == "python"
          else "Rust archive download failed", file=sys.stderr)
    print("failed download")
    sys.exit(0 if impl == "python" else 1)
sys.exit(subprocess.run(
    ["/usr/bin/python3", "-I", "-", *sys.argv[4:]],
    input=installer, text=True, check=False,
).returncode)
