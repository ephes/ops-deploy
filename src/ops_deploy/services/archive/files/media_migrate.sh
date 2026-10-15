# Port of "Migrate local archive-media tree into MinIO when needed"
# (deploy-archive.yml). bash -c <this> media-migrate MC ENDPOINT BUCKET LOCAL_DIR [probe]
# With "probe" it only prints the state (missing, empty, migrated or pending)
# and needs no credentials. Otherwise standard input holds the app access key
# and secret key (one per line).
set -euo pipefail
mc="$1" endpoint="$2" bucket="$3" local_dir="$4" mode="${5:-migrate}"
marker="${local_dir}/.minio-migrated"
# Credentials reach mc through MC_HOST_<alias> (its environment, readable
# only by root), never through its arguments.
mc_host() {
  local creds
  creds="$(MC_USER="$2" MC_SECRET="$3" python3 -c 'import os, urllib.parse as u
print(":".join(u.quote(os.environ[k], safe="") for k in ("MC_USER", "MC_SECRET")))')"
  export "MC_HOST_$1=${endpoint%%://*}://${creds}@${endpoint#*://}"
}

if [[ ! -d "$local_dir" ]]; then
  echo "archive_media_local_dir_missing"
  exit 0
fi
file_count="$(find "$local_dir" -type f ! -name '.minio-migrated' | wc -l | tr -d ' ')"
if [[ "$file_count" == "0" ]]; then
  echo "archive_media_local_dir_empty"
  exit 0
fi
if [[ -f "$marker" ]] && ! find "$local_dir" -type f ! -name '.minio-migrated' -newer "$marker" -print -quit | grep -q .; then
  echo "archive_media_already_migrated"
  exit 0
fi
if [[ "$mode" == probe ]]; then
  echo "archive_media_pending"
  exit 0
fi

IFS= read -r app_key
IFS= read -r app_secret
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
export MC_CONFIG_DIR="$tmpdir"
mc_host archive_app "$app_key" "$app_secret"
"$mc" mirror --exclude '.minio-migrated' "${local_dir}/" "archive_app/${bucket}/" >/dev/null
touch "$marker"
echo "archive_media_migrated_files=${file_count}"
