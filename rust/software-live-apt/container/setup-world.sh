#!/bin/bash
# The fake APT world of software-live PLAN.md 13.1 and 13.6, for comparing
# software-live-apt with python-apt (container/compare.py). It changes the
# container's APT configuration and installs fake packages: run it as root
# in a throwaway ubuntu:24.04 or debian:13 container only, never on a host.
#
# - /etc/apt/apt.conf.d/docker-clean is removed: the hosts have no
#   Dir::Cache override, so the cache files behave as on the hosts (13.3
#   item 4).
# - A foreign architecture is added (i386 next to amd64, armhf next to
#   arm64) and the image's own lists are refreshed (real security
#   InRelease files and real packages).
# - Fake packages (installed version 1.0) and flat file: repositories cover
#   every branch of security_origin: trusted ESM, untrusted security,
#   label Debian-Security, archive spelled Trixie-SECURITY, an older
#   security version, the same .deb in a trusted and an untrusted
#   repository (both ways round), an untrusted ESM origin; a held native
#   and a held foreign-architecture package; a candidate pinned below the
#   newest security version.
set -euo pipefail

if [ ! -f /.dockerenv ] && [ "${SOFTWARE_LIVE_APT_CONTAINER:-}" != yes ]; then
    echo "setup-world.sh: refusing to run outside a container" >&2
    exit 1
fi

. /etc/os-release
native=$(dpkg --print-architecture)
case "$native" in
    amd64) foreign=i386 ;;
    arm64) foreign=armhf ;;
    *)
        echo "setup-world.sh: unsupported architecture $native" >&2
        exit 1
        ;;
esac
case "$ID" in
    ubuntu) vendor=Ubuntu ;;
    debian) vendor=Debian ;;
    *)
        echo "setup-world.sh: unsupported distribution $ID" >&2
        exit 1
        ;;
esac
codename=$VERSION_CODENAME
world=/srv/apt-world
export DEBIAN_FRONTEND=noninteractive

rm -f /etc/apt/apt.conf.d/docker-clean
rm -rf "$world"
mkdir -p "$world/debs"
dpkg --add-architecture "$foreign"

# A minimal binary package: deb <name> <version> <arch>
deb() {
    local name=$1 version=$2 arch=$3
    local dir="$world/build/${name}_${version}_${arch}"
    mkdir -p "$dir/DEBIAN"
    cat >"$dir/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: $arch
Maintainer: software-live tests <root@localhost>
Description: fake package for the software-live-apt comparison
EOF
    dpkg-deb --root-owner-group --build "$dir" "$world/debs/${name}_${version}_${arch}.deb" >/dev/null
}

# Installed versions.
for name in fakenative fakeheld fakepin fakedual fakemulti fakeesmun fakelow fakecase; do
    deb "$name" 1.0 "$native"
done
deb fakeforeign 1.0 "$foreign"
deb fakeall 1.0 all
# Newer versions for the repositories.
deb fakenative 1.1 "$native"
deb fakenative 9.9 "$native"
deb fakeforeign 1.1 "$foreign"
deb fakeheld 1.1 "$native"
deb fakepin 1.1 "$native"
deb fakepin 1.2 "$native"
deb fakeall 0.9 all
deb fakeall 1.1 all
deb fakeall 1.2 all
deb fakeall 1.3 all
deb fakedual 2.0 "$native"
deb fakemulti 2.0 "$native"
deb fakeesmun 1.1 "$native"
deb fakelow 0.5 "$native"
deb fakecase 1.2 "$native"

dpkg -i "$world"/debs/*_1.0_*.deb >/dev/null
apt-mark hold fakeheld "fakeforeign:$foreign" >/dev/null

# A flat repository: repo <dir> <origin> <label> <suite> <package files...>
repo() {
    local dir="$world/repos/$1" origin=$2 label=$3 suite=$4
    shift 4
    mkdir -p "$dir"
    for file in "$@"; do
        cp "$world/debs/$file" "$dir/"
    done
    (
        cd "$dir"
        apt-ftparchive packages . >Packages
        apt-ftparchive \
            -o "APT::FTPArchive::Release::Origin=$origin" \
            -o "APT::FTPArchive::Release::Label=$label" \
            -o "APT::FTPArchive::Release::Suite=$suite" \
            -o "APT::FTPArchive::Release::Codename=$suite" \
            release . >Release
    )
}

repo esm UbuntuESMApps "Ubuntu ESM Apps" esm-apps \
    "fakenative_1.1_${native}.deb" "fakeforeign_1.1_${foreign}.deb" \
    "fakeheld_1.1_${native}.deb" "fakepin_1.1_${native}.deb" "fakepin_1.2_${native}.deb" \
    "fakedual_2.0_${native}.deb"
repo untrusted-security "$vendor" "$vendor" "${codename}-security" \
    "fakenative_9.9_${native}.deb" "fakedual_2.0_${native}.deb" "fakemulti_2.0_${native}.deb"
repo updates "$vendor" "$vendor" "${codename}-updates" "fakemulti_2.0_${native}.deb"
repo label Example Debian-Security example fakeall_1.1_all.deb fakeall_1.3_all.deb
repo case Debian Debian Trixie-SECURITY fakeall_1.2_all.deb "fakecase_1.2_${native}.deb"
repo old-security Debian Debian "${codename}-security" fakeall_0.9_all.deb "fakelow_0.5_${native}.deb"
repo esm-untrusted UbuntuESMInfra "Ubuntu ESM Infra" esm-infra "fakeesmun_1.1_${native}.deb"

{
    for name in esm updates label case old-security; do
        echo "deb [trusted=yes] file:$world/repos/$name ./"
    done
    for name in untrusted-security esm-untrusted; do
        echo "deb [allow-insecure=yes] file:$world/repos/$name ./"
    done
} >/etc/apt/sources.list.d/software-live-apt-world.list

cat >/etc/apt/preferences.d/software-live-apt-world <<'EOF'
Package: fakepin
Pin: version 1.1
Pin-Priority: 1001
EOF

apt-get update >/dev/null
echo "setup-world.sh: $ID $codename $native (+$foreign), fake repositories in $world/repos"
