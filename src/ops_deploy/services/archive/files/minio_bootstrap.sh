# Port of "Ensure Archive media bucket and service account exist in MinIO"
# (deploy-archive.yml). bash -c <this> minio-bootstrap MC ADMIN BUCKET USER POLICY;
# standard input: the app secret key, then the app's mc alias as JSON (one per
# line), so no credential is on the deploy's command line. Bucket, policy and
# user are managed through ADMIN, root's MinIO admin alias (the MinIO deploy
# configured it); the MinIO root credentials are never handled here.
set -euo pipefail
mc="$1" admin="$2" bucket="$3" user="$4" policy="$5"
IFS= read -r app_secret
IFS= read -r app_alias
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
policy_file="$tmpdir/archive-media-policy.json"
# The app's alias lives in a private, temporary mc configuration.
app_mc() { MC_CONFIG_DIR="$tmpdir/mc" "$mc" "$@"; }
add_user() { printf '%s\n%s\n' "$user" "$app_secret" | "$mc" admin user add "$admin" >/dev/null; }
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

if "$mc" ls "$admin/$bucket" >/dev/null 2>&1; then
  echo "archive_media_bucket_exists"
else
  "$mc" mb "$admin/$bucket" >/dev/null
  echo "archive_media_bucket_created"
fi
"$mc" anonymous set private "$admin/$bucket" >/dev/null

"$mc" admin policy detach "$admin" "$policy" --user "$user" >/dev/null 2>&1 || true
"$mc" admin policy remove "$admin" "$policy" >/dev/null 2>&1 || true
"$mc" admin policy create "$admin" "$policy" "$policy_file" >/dev/null

if ! "$mc" admin user info "$admin" "$user" >/dev/null 2>&1; then
  echo "archive_media_user_created"
  add_user
fi

# Only this policy stays attached (the playbook detaches the built-in ones;
# any other attachment is removed too, so the probe can converge).
attached="$("$mc" admin user info --json "$admin" "$user" \
  | python3 -c 'import json, sys; print("\n".join(p for p in (json.load(sys.stdin).get("policyName") or "").split(",") if p))')"
while IFS= read -r other; do
  [[ -z "$other" || "$other" == "$policy" ]] && continue
  "$mc" admin policy detach "$admin" "$other" --user "$user" >/dev/null
done <<<"$attached"
"$mc" admin policy attach "$admin" "$policy" --user "$user" >/dev/null

printf '%s\n' "$app_alias" | app_mc alias import archive-app >/dev/null
if ! app_mc ls "archive-app/$bucket" >/dev/null 2>&1; then
  "$mc" admin user remove "$admin" "$user" >/dev/null 2>&1 || true
  add_user
  "$mc" admin policy attach "$admin" "$policy" --user "$user" >/dev/null
  echo "archive_media_user_recreated"
fi
app_mc ls "archive-app/$bucket" >/dev/null
