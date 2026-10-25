# The Rust nyxmon agent below its install root (nyxmon_deploy's agent_rust.yml
# and agent_verify.yml). bash -c <this> nyxmon-agent COMMAND ARGS...
#
#   install ROOT VERSION SHA256 URL USER DB [UPLOAD]
#       Stage the pinned release archive (downloaded from URL, or the local
#       archive already uploaded to UPLOAD), refuse it unless its sha256 is
#       SHA256 and it holds only the regular files nyxmon-agent and LICENSE,
#       move it into ROOT/VERSION (root-owned, .archive-sha256 recorded) and
#       validate it; a rejected fresh install is removed again.
#   validate ROOT VERSION USER DB
#       --version reports VERSION and --check-schema passes, as USER by the
#       versioned path. Changes nothing.
#   prune ROOT VERSION UNIT KEEP [--dry-run]
#       Remove version directories beyond the KEEP newest (by mtime), keeping
#       VERSION, the one in ROOT/.previous-version and the one UNIT runs.
#       Prints each directory it removes (or would remove).
set -euo pipefail
VERSIONED='^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$'

fail() { echo "nyxmon-agent: $*" >&2; exit 1; }

validate() {
    local bin="$1/$2/nyxmon-agent" version="$2" user="$3" db="$4" out rc=0
    # As the service user, from a directory it may enter.
    out=$(cd / && runuser -u "$user" -- "$bin" --version) || rc=$?
    local words
    read -r -d '' -a words <<<"$out" || true
    [ "$rc" = 0 ] && [ "${words[0]:-}" = nyxmon-agent ] && [ "${words[1]:-}" = "$version" ] \
        || fail "$bin --version exited $rc with '$out'; expected 'nyxmon-agent $version (<commit>)'"
    rc=0
    out=$(cd / && runuser -u "$user" -- "$bin" --check-schema --db "$db" 2>&1) || rc=$?
    [ "$rc" = 0 ] || fail "$bin --check-schema exited $rc: $out"
}

install_release() {
    local root="$1" version="$2" sha256="$3" url="$4" user="$5" db="$6" upload="${7:-}"
    local dir="$root/$version" staging="$root/.staging"
    local archive="$staging/archive.tar.gz"
    [ ! -e "$dir" ] || fail "$dir exists already; an installed version is never replaced"
    rm -rf "$staging"
    install -d -o root -g root -m 0755 "$staging" "$staging/tree"
    if [ -n "$upload" ]; then
        mv -- "$upload" "$archive"
    else
        curl -fsSL --retry 3 -o "$archive" "$url" || fail "downloading $url failed"
    fi
    chown root:root "$archive"
    chmod 0600 "$archive"
    local actual
    actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
    [ "$actual" = "$sha256" ] || fail "the staged archive has sha256 $actual, expected $sha256"
    # Checked before extraction: only the regular files nyxmon-agent and
    # LICENSE, each once (a link or device member could reach outside).
    local names types members
    names=$(tar --list --gzip --file "$archive") || fail "cannot list $archive"
    types=$(tar --list --verbose --gzip --file "$archive") || fail "cannot list $archive"
    members=$(printf '%s\n' "$names" | sed 's|^[.]/||')
    if ! printf '%s\n' "$members" | grep -qx nyxmon-agent \
        || printf '%s\n' "$members" | grep -qvx -e nyxmon-agent -e LICENSE \
        || [ -n "$(printf '%s\n' "$members" | sort | uniq -d)" ] \
        || [ "$(printf '%s\n' "$types" | wc -l)" != "$(printf '%s\n' "$members" | wc -l)" ] \
        || printf '%s\n' "$types" | grep -qv '^-'; then
        fail "the release archive must hold the regular files nyxmon-agent (and LICENSE) at its root, once each; found: $types"
    fi
    tar --extract --gzip --no-same-owner --file "$archive" --directory "$staging/tree"
    chown -R root:root "$staging/tree"
    [ -f "$staging/tree/nyxmon-agent" ] && [ ! -L "$staging/tree/nyxmon-agent" ] \
        || fail "$staging/tree/nyxmon-agent is not a regular file"
    chmod 0755 "$staging/tree/nyxmon-agent"
    printf '%s\n' "$sha256" >"$staging/tree/.archive-sha256"
    chmod 0644 "$staging/tree/.archive-sha256"
    mv --no-target-directory "$staging/tree" "$dir"
    rm -rf "$staging"
    # Validated by the versioned path; the unit does not point at it yet.
    ( validate "$root" "$version" "$user" "$db" ) || { rm -rf "$dir"; exit 1; }
}

prune() {
    local root="$1" pinned="$2" unit="$3" keep="$4" dry="${5:-}"
    local previous="" live="" pid exe
    [ -f "$root/.previous-version" ] && previous=$(tr -d '[:space:]' <"$root/.previous-version")
    pid=$(systemctl show --property=MainPID --value "$unit")
    if [ "${pid:-0}" -gt 0 ] 2>/dev/null; then
        exe=$(readlink "/proc/$pid/exe" || true)
        case "$exe" in "$root"/*/*) live=${exe#"$root"/}; live=${live%%/*} ;; esac
    fi
    [ -d "$root" ] || return 0
    local versions newest version
    versions=$(find "$root" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' | sort -rn | cut -d ' ' -f 2- \
        | { grep -E "$VERSIONED" || true; })
    newest=$(printf '%s\n' "$versions" | head -n "$keep")
    for version in $versions; do
        case " $pinned $previous $live " in *" $version "*) continue ;; esac
        printf '%s\n' "$newest" | grep -qxF -e "$version" && continue
        echo "$root/$version"
        [ "$dry" = --dry-run ] || rm -rf -- "${root:?}/$version"
    done
}

command="$1"
shift
case "$command" in
    install) install_release "$@" ;;
    validate) validate "$@" ;;
    prune) prune "$@" ;;
    *) fail "unknown command $command" ;;
esac
