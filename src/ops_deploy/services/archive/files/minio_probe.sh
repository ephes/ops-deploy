# Read-only: does MinIO already look the way minio_bootstrap.sh leaves it?
# bash -c <this> minio-probe MC ENDPOINT BUCKET POLICY ROOT_ENV APP_ENV
# Prints "ok" or "bootstrap:<reason>". Root credentials come from MinIO's own
# environment file, the app's from archive's .env (parsed, never sourced: it
# belongs to the service user). Nothing is printed but the verdict.
set -u
mc="$1" endpoint="$2" bucket="$3" policy="$4" root_env="$5" app_env="$6"
verdict() { echo "$1"; exit 0; }
[ -x "$mc" ] || verdict "bootstrap:no-mc"
[ -r "$root_env" ] || verdict "bootstrap:no-minio-env"
[ -r "$app_env" ] || verdict "bootstrap:no-app-env"
# Credentials reach mc through MC_HOST_<alias> (its environment, readable
# only by root), never through its arguments.
mc_host() {
  local creds
  creds="$(MC_USER="$2" MC_SECRET="$3" python3 -c 'import os, urllib.parse as u
print(":".join(u.quote(os.environ[k], safe="") for k in ("MC_USER", "MC_SECRET")))')"
  export "MC_HOST_$1=${endpoint%%://*}://${creds}@${endpoint#*://}"
}
value() { sed -n "s/^$1=//p" "$2" | tail -n 1; }
tmpdir="$(mktemp -d)" || verdict "bootstrap:mktemp"
trap 'rm -rf "$tmpdir"' EXIT
export MC_CONFIG_DIR="$tmpdir"
root_user="$(set -a; . "$root_env" >/dev/null 2>&1; printf '%s' "${MINIO_ROOT_USER:-}")"
root_password="$(set -a; . "$root_env" >/dev/null 2>&1; printf '%s' "${MINIO_ROOT_PASSWORD:-}")"
[ -n "$root_user" ] && [ -n "$root_password" ] || verdict "bootstrap:no-root-credentials"
mc_host probe_root "$root_user" "$root_password" || verdict "bootstrap:root-login"
"$mc" admin info probe_root >/dev/null 2>&1 || verdict "bootstrap:root-login"
app_key="$(value ARCHIVE_MEDIA_STORAGE_ACCESS_KEY_ID "$app_env")"
app_secret="$(value ARCHIVE_MEDIA_STORAGE_SECRET_ACCESS_KEY "$app_env")"
[ -n "$app_key" ] && [ -n "$app_secret" ] || verdict "bootstrap:no-app-key"
"$mc" ls "probe_root/$bucket" >/dev/null 2>&1 || verdict "bootstrap:bucket"
"$mc" anonymous get --json "probe_root/$bucket" 2>/dev/null \
  | grep -q '"permission": *"private"' || verdict "bootstrap:anonymous"
"$mc" admin policy info --json probe_root "$policy" >"$tmpdir/policy.json" 2>/dev/null \
  || verdict "bootstrap:policy"
"$mc" admin user info --json probe_root "$app_key" >"$tmpdir/user.json" 2>/dev/null \
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
mc_host probe_app "$app_key" "$app_secret" || verdict "bootstrap:app-access"
"$mc" ls "probe_app/$bucket" >/dev/null 2>&1 || verdict "bootstrap:app-access"
verdict ok
