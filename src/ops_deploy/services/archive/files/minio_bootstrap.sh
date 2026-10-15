# Port of "Ensure Archive media bucket and service account exist in MinIO"
# (deploy-archive.yml). bash -c <this> minio-bootstrap MC ENDPOINT BUCKET POLICY;
# standard input: root user, root password, app access key, app secret key
# (one per line), so no credential is on the deploy's command line.
set -euo pipefail
mc="$1" endpoint="$2" bucket="$3" policy="$4"
IFS= read -r root_user
IFS= read -r root_password
IFS= read -r app_key
IFS= read -r app_secret
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
export MC_CONFIG_DIR="$tmpdir"
policy_file="$tmpdir/archive-media-policy.json"
# Credentials reach mc through MC_HOST_<alias> (its environment, readable
# only by root), never through its arguments.
mc_host() {
  local creds
  creds="$(MC_USER="$2" MC_SECRET="$3" python3 -c 'import os, urllib.parse as u
print(":".join(u.quote(os.environ[k], safe="") for k in ("MC_USER", "MC_SECRET")))')"
  export "MC_HOST_$1=${endpoint%%://*}://${creds}@${endpoint#*://}"
}
cat >"$policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": [
        "arn:aws:s3:::${bucket}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:ListMultipartUploadParts",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::${bucket}/*"
      ]
    }
  ]
}
JSON

mc_host archive_root "$root_user" "$root_password"

if "$mc" ls "archive_root/$bucket" >/dev/null 2>&1; then
  echo "archive_media_bucket_exists"
else
  "$mc" mb "archive_root/$bucket" >/dev/null
  echo "archive_media_bucket_created"
fi
"$mc" anonymous set private "archive_root/$bucket" >/dev/null

"$mc" admin policy detach archive_root "$policy" --user "$app_key" >/dev/null 2>&1 || true
"$mc" admin policy remove archive_root "$policy" >/dev/null 2>&1 || true
"$mc" admin policy create archive_root "$policy" "$policy_file" >/dev/null

if ! "$mc" admin user info archive_root "$app_key" >/dev/null 2>&1; then
  echo "archive_media_user_created"
  printf '%s\n' "$app_secret" | "$mc" admin user add archive_root "$app_key" >/dev/null
fi

# Only this policy stays attached (the playbook detaches the built-in ones;
# any other attachment is removed too, so the probe can converge).
attached="$("$mc" admin user info --json archive_root "$app_key" \
  | python3 -c 'import json, sys; print("\n".join(p for p in (json.load(sys.stdin).get("policyName") or "").split(",") if p))')"
while IFS= read -r other; do
  [[ -z "$other" || "$other" == "$policy" ]] && continue
  "$mc" admin policy detach archive_root "$other" --user "$app_key" >/dev/null
done <<<"$attached"
"$mc" admin policy attach archive_root "$policy" --user "$app_key" >/dev/null

mc_host archive_app "$app_key" "$app_secret"
if ! "$mc" ls "archive_app/$bucket" >/dev/null 2>&1; then
  "$mc" admin user remove archive_root "$app_key" >/dev/null 2>&1 || true
  printf '%s\n' "$app_secret" | "$mc" admin user add archive_root "$app_key" >/dev/null
  "$mc" admin policy attach archive_root "$policy" --user "$app_key" >/dev/null
  echo "archive_media_user_recreated"
fi
"$mc" ls "archive_app/$bucket" >/dev/null
