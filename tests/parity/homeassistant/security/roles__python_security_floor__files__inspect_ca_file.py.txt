"""Print the SHA-256 fingerprints of the CA certificates OpenSSL loads from a CA file and directories.

Run with a system interpreter and ``-I``:
``python3 -I -c <this> <ca-file> [<cert-dir> ...]``. Native-store loaders such
as rustls-native-certs read both the CA file and every file in the certificate
directory, so both are read here: the CA file must load (fail closed); each
regular file (symlinks followed) in an existing directory is loaded on its
own. Only files without any PEM boundary are skipped (both loaders read PEM
only); a file with PEM content that OpenSSL cannot load fails the check, so
a distrusted root next to a malformed block is never skipped. Prints a JSON
object.
Standard library only.
"""

import hashlib
import json
import os
import ssl
import sys


def load(path):
    protocol = getattr(ssl, "PROTOCOL_TLS_CLIENT", None) or ssl.PROTOCOL_SSLv23
    context = ssl.SSLContext(protocol)
    context.load_verify_locations(cafile=path)
    return {hashlib.sha256(der).hexdigest() for der in context.get_ca_certs(binary_form=True)}


fingerprints = load(sys.argv[1])
read = [os.path.realpath(sys.argv[1])]
seen = set()
for directory in sys.argv[2:]:
    real = os.path.realpath(directory)
    if real in seen or not os.path.isdir(real):
        continue
    seen.add(real)
    for name in sorted(os.listdir(real)):
        path = os.path.join(real, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as handle:
            if b"-----BEGIN" not in handle.read():
                continue
        try:
            fingerprints |= load(path)
        except ssl.SSLError as exc:
            sys.exit("{}: PEM content OpenSSL cannot load ({})".format(path, exc.reason or exc))
        read.append(path)
print(json.dumps({"fingerprints": sorted(fingerprints), "directories": sorted(seen), "files": len(read)}))
