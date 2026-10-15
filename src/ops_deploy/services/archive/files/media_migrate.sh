# Port of "Migrate local archive-media tree into MinIO when needed"
# (deploy-archive.yml). bash -c <this> media-migrate MC BUCKET LOCAL_DIR [probe]
# With "probe" it only prints the state (missing, empty, migrated or pending)
# and needs no credentials. Otherwise standard input holds the app's mc alias
# as JSON (one line), so no credential is on the deploy's command line.
set -euo pipefail
mc="$1" bucket="$2" local_dir="$3" mode="${4:-migrate}"
marker="${local_dir}/.minio-migrated"

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

IFS= read -r app_alias
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
export MC_CONFIG_DIR="$tmpdir"
printf '%s\n' "$app_alias" | "$mc" alias import archive-app >/dev/null
"$mc" mirror --exclude '.minio-migrated' "${local_dir}/" "archive-app/${bucket}/" >/dev/null
touch "$marker"
echo "archive_media_migrated_files=${file_count}"
