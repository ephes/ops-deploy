#!/bin/bash
# Managed by ops-deploy infra.dsstore_cleanup; local changes are overwritten.
# Removes macOS .DS_Store files below each directory argument: regular files
# named exactly .DS_Store, on the argument's file system only (-xdev), never
# through a symlink. Logs one count line per directory; exits 1 when a
# directory is missing or find reports an error (the other directories still
# run).
set -uo pipefail

status=0
for root in "$@"; do
    if [[ ! -d $root || -L $root ]]; then
        echo "dsstore-cleanup: $root is not a directory, skipped" >&2
        status=1
        continue
    fi
    # -print0 after -delete: one NUL per file actually removed.
    if count=$(find "$root" -xdev -type f -name .DS_Store -delete -print0 | tr -dc '\0' | wc -c); then
        echo "dsstore-cleanup: removed $((count)) .DS_Store file(s) below $root"
    else
        echo "dsstore-cleanup: find reported errors below $root; removed $((count)) .DS_Store file(s)" >&2
        status=1
    fi
done
exit "$status"
