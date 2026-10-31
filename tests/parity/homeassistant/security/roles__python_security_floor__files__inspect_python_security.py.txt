"""Report the certifi and pip trust bundles one Python environment uses.

Run with the environment's interpreter and ``-I`` (isolated: no current
directory, user site or PYTHON* variables on the path), as the application
user. It imports only certifi and pip's vendored certifi, never application
code, and prints one JSON object for the ``python_security_report_violations``
filter. Standard library only, so it also runs in old environments.
"""

import argparse
import glob
import hashlib
import importlib
import importlib.util
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys

# Package name -> (distribution, module providing where()).
PACKAGES = {"certifi": ("certifi", "certifi"), "pip": ("pip", "pip._vendor.certifi")}


def version(module_file, name):
    # The Version of the one <name>-*.dist-info next to the imported package
    # (stdlib only, any Python; tied to the module actually imported). None
    # when there is not exactly one, so the caller fails closed.
    site = os.path.dirname(os.path.dirname(module_file))
    infos = glob.glob(os.path.join(site, name + "-*.dist-info", "METADATA"))
    if len(infos) != 1:
        return None
    with open(infos[0], encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                break
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
    return None


def inside(path, prefix):
    return os.path.realpath(path).startswith(os.path.realpath(prefix) + os.sep)


def in_environment(path, managed_base_prefix=""):
    if managed_base_prefix:
        return (
            os.path.realpath(sys.prefix)
            == os.path.realpath(sys.base_prefix)
            == os.path.realpath(managed_base_prefix)
            and inside(sys.executable, managed_base_prefix)
            and inside(path, managed_base_prefix)
        )
    if sys.prefix == sys.base_prefix:
        return False
    return inside(path, sys.prefix)


def distro_owner(path):
    query = shutil.which("dpkg-query")
    if not query:
        return None
    try:
        output = subprocess.run(
            [query, "-S", os.path.realpath(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            universal_newlines=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    owners = output.split(":", 1)[0].strip().split(", ")
    return owners[0] if len(owners) == 1 else None


def fingerprints(path):
    # SHA-256 of every CA certificate this interpreter's OpenSSL loads from
    # the bundle, in OpenSSL's own DER (what `openssl x509 -fingerprint`
    # hashes): CERTIFICATE and TRUSTED CERTIFICATE blocks alike, whatever
    # their encoding in the file. A bundle OpenSSL cannot load raises
    # (ssl.SSLError is an OSError), so the caller fails closed.
    protocol = getattr(ssl, "PROTOCOL_TLS_CLIENT", None) or ssl.PROTOCOL_SSLv23
    context = ssl.SSLContext(protocol)
    context.load_verify_locations(cafile=path)
    return [
        hashlib.sha256(der).hexdigest()
        for der in context.get_ca_certs(binary_form=True)
    ]


def inspect(distribution, module_name, managed_base_prefix=""):
    top = module_name.split(".")[0]
    if importlib.util.find_spec(top) is None:
        return {"installed": False}
    result = {"installed": True}
    try:
        package = importlib.import_module(top)
        result["module_file"] = os.path.realpath(package.__file__)
        result["version"] = version(result["module_file"], distribution)
        result["in_environment"] = in_environment(package.__file__, managed_base_prefix)
        result["distro_owner"] = (
            None if result["in_environment"] else distro_owner(package.__file__)
        )
        bundle_module = importlib.import_module(module_name)
        if managed_base_prefix:
            result["bundle_module_file"] = os.path.realpath(bundle_module.__file__)
            result["bundle_version"] = getattr(bundle_module, "__version__", None)
            result["module_origins"] = {
                name: os.path.realpath(module.__file__)
                for name, module in list(sys.modules.items())
                if (name == top or name.startswith(top + "."))
                and getattr(module, "__file__", None)
            }
        bundle = bundle_module.where()
        result["bundle"] = os.path.realpath(bundle)
    except Exception as exc:  # report, never guess
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
        return result
    try:
        result["bundle_fingerprints"] = fingerprints(result["bundle"])
    except (OSError, ValueError) as exc:
        result["bundle_error"] = "{}: {}".format(type(exc).__name__, exc)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--managed-base-prefix", default="")
    args = parser.parse_args()
    report = {
        "python_version": platform.python_version(),
        "prefix": os.path.realpath(sys.prefix),
        "packages": {
            name: inspect(*spec, managed_base_prefix=args.managed_base_prefix)
            for name, spec in PACKAGES.items()
        },
    }
    if args.managed_base_prefix:
        report.update(
            expected_base_prefix=os.path.realpath(args.managed_base_prefix),
            base_prefix=os.path.realpath(sys.base_prefix),
            executable=os.path.realpath(sys.executable),
        )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
