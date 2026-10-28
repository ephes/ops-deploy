"""Bound direct identity verification under existing Python, no site startup.

Only used as a child captured by the remote resource helper. Its plan hash stays
in that remote parent's memory for the original root-proof comparison; the outer
pyinfra operation must emit only schema_version/identity_verified. This is not an
operator CLI. No private application source is packaged here.
"""

import hashlib
import hmac
import json
import os
import pathlib
import re
import stat
import sys
import types

# Dependency order for the reviewed verifier's closed twelve-module surface.
MODULES = (
    "__init__", "composer", "weeknotes", "token_http", "cast_client",
    "archive_quote_sink", "weeknotes_quotes", "sessions", "weeknotes_privacy",
    "weeknotes_authoring", "weeknotes_reconcile", "weeknotes_identity_migration",
)
MAX_CODE = 2 * 1024 * 1024


class IdentityError(RuntimeError):
    pass


def code_bytes(name, expected):
    path = pathlib.Path(name)
    if not path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise IdentityError("sessions_identity_code_binding_failed")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = following
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_CODE:
                raise IdentityError("sessions_identity_code_binding_failed")
            chunks, remaining = [], MAX_CODE + 1
            while remaining:
                piece = os.read(fd, min(remaining, 65536))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
            body = b"".join(chunks)
            if len(body) > MAX_CODE or not hmac.compare_digest(hashlib.sha256(body).hexdigest(), expected):
                raise IdentityError("sessions_identity_code_binding_failed")
            return body
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def verify(data):
    action = data.get("action", "verify")
    if action not in {"verify", "policy"}:
        raise IdentityError("sessions_identity_request_invalid")
    version = ".".join(str(v) for v in sys.version_info[:3])
    if version != data["python_version"]:
        raise IdentityError("sessions_identity_interpreter_mismatch")
    hashes = data["module_hashes"]
    expected_paths = {"src/daybook/" + name + ".py" for name in MODULES}
    if not isinstance(hashes, dict) or set(hashes) != expected_paths:
        raise IdentityError("sessions_identity_code_binding_failed")
    checkout = pathlib.Path(data["checkout"])
    # Read and verify ALL bytes before importing any application module. Loading
    # these in-memory bytes bypasses .pth/sitecustomize and stale/mutated .pyc.
    bodies = {name: code_bytes(str(checkout / ("src/daybook/" + name + ".py")),
                              hashes["src/daybook/" + name + ".py"]) for name in MODULES}
    helper = code_bytes(data["helper"], data["helper_sha256"]) if action == "verify" else None
    for name in MODULES:
        module_name = "daybook" if name == "__init__" else "daybook." + name
        module = types.ModuleType(module_name)
        module.__file__ = str(checkout / ("src/daybook/" + name + ".py"))
        module.__package__ = "daybook"
        if name == "__init__":
            # No file finder: only the explicit verified closure is importable.
            module.__path__ = []
        sys.modules[module_name] = module
        exec(compile(bodies[name], module.__file__, "exec"), module.__dict__)
    if action == "policy":
        # Original pinned policy validator: parses only the supplied repository
        # declaration, no API/client/Journal/identity-store calls.
        sys.modules["daybook.weeknotes_privacy"].public_repository_policy_from_env(data["policy_environment"])
        return {"schema_version": 1, "policy_verified": True}
    module = types.ModuleType("ops_bound_weeknotes_identity")
    module.__file__ = data["helper"]
    sys.modules[module.__name__] = module
    exec(compile(helper, data["helper"], "exec"), module.__dict__)
    paths = [pathlib.Path(name) for name in data["paths"]]
    if len(paths) != 3:
        raise IdentityError("sessions_identity_paths_invalid")
    result = module.verify(*paths)
    if (not isinstance(result, dict) or set(result) != {"schema_version", "status", "plan_hash"}
            or type(result["schema_version"]) is not int or result["schema_version"] != 1
            or result["status"] != "attestation_verified"
            or not isinstance(result["plan_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", result["plan_hash"])):
        raise IdentityError("sessions_identity_verification_failed")
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise IdentityError("sessions_identity_request_invalid")
        result = verify(json.loads(raw))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        # Never print an input, exception message, identity or traceback.
        print('{"schema_version":1,"status":"failed","reason_code":"identity_gate_failed"}')
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
