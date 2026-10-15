# Read-only: does MinIO already look the way minio_bootstrap.sh leaves it?
# bash -c <this> minio-probe MC ADMIN ENDPOINT BUCKET POLICY APP_ENV
# Prints "ok" or "bootstrap:<reason>". Admin calls go through ADMIN, root's
# MinIO admin alias; the app's credentials come from archive's .env (parsed,
# never sourced: it belongs to the service user). Nothing is printed but the
# verdict.
set -u
mc="$1" admin="$2" endpoint="$3" bucket="$4" policy="$5" app_env="$6"
verdict() { echo "$1"; exit 0; }
[ -x "$mc" ] || verdict "bootstrap:no-mc"
[ -r "$app_env" ] || verdict "bootstrap:no-app-env"
value() { sed -n "s/^$1=//p" "$2" | tail -n 1; }
tmpdir="$(mktemp -d)" || verdict "bootstrap:mktemp"
trap 'rm -rf "$tmpdir"' EXIT
# The app's alias lives in a private, temporary mc configuration.
app_mc() { MC_CONFIG_DIR="$tmpdir/mc" "$mc" "$@"; }
"$mc" admin info "$admin" >/dev/null 2>&1 || verdict "bootstrap:admin"
app_key="$(value ARCHIVE_MEDIA_STORAGE_ACCESS_KEY_ID "$app_env")"
app_secret="$(value ARCHIVE_MEDIA_STORAGE_SECRET_ACCESS_KEY "$app_env")"
[ -n "$app_key" ] && [ -n "$app_secret" ] || verdict "bootstrap:no-app-key"
"$mc" ls "$admin/$bucket" >/dev/null 2>&1 || verdict "bootstrap:bucket"
"$mc" anonymous get --json "$admin/$bucket" 2>/dev/null \
  | grep -q '"permission": *"private"' || verdict "bootstrap:anonymous"
"$mc" admin policy info --json "$admin" "$policy" >"$tmpdir/policy.json" 2>/dev/null \
  || verdict "bootstrap:policy"
"$mc" admin user info --json "$admin" "$app_key" >"$tmpdir/user.json" 2>/dev/null \
  || verdict "bootstrap:user"
python3 - "$bucket" "$policy" "$tmpdir/policy.json" "$tmpdir/user.json" <<'PY' || verdict "bootstrap:policy-mismatch"
import json, sys

bucket, name, policy_path, user_path = sys.argv[1:]
arn = f"arn:aws:s3:::{bucket}"
wanted = [
    ("Allow", sorted(["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]), [arn]),
    (
        "Allow",
        sorted(["s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:ListMultipartUploadParts", "s3:PutObject"]),
        [f"{arn}/*"],
    ),
]


def as_list(value):
    return [value] if isinstance(value, str) else list(value or [])


info = json.load(open(policy_path))
document = (info.get("policyInfo") or {}).get("Policy") or {}
have = sorted(
    (s.get("Effect"), sorted(as_list(s.get("Action"))), sorted(as_list(s.get("Resource"))))
    for s in document.get("Statement") or []
)
user = json.load(open(user_path))
policies = sorted(p for p in (user.get("policyName") or "").split(",") if p)
ok = have == sorted(wanted) and policies == [name] and user.get("userStatus") == "enabled"
sys.exit(0 if ok else 1)
PY
# The alias JSON reaches mc on stdin; python reads the credentials from .env
# itself (the last assignment, as value() does), so they are in no process's
# arguments or environment.
python3 -c 'import json, sys
found = {}
for line in open(sys.argv[1]):
    key, sep, value = line.rstrip("\n").partition("=")
    if sep:
        found[key] = value
print(json.dumps({"url": sys.argv[2], "accessKey": found["ARCHIVE_MEDIA_STORAGE_ACCESS_KEY_ID"],
                  "secretKey": found["ARCHIVE_MEDIA_STORAGE_SECRET_ACCESS_KEY"], "api": "s3v4", "path": "auto"}))' \
  "$app_env" "$endpoint" | app_mc alias import probe-app >/dev/null 2>&1 || verdict "bootstrap:app-access"
app_mc ls "probe-app/$bucket" >/dev/null 2>&1 || verdict "bootstrap:app-access"
verdict ok
