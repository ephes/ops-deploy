#!/usr/bin/env bash
# Owns one disposable GitHub VM and two systemd-nspawn systems on it. Never run
# against inventory. Mail packages stay absent until the API installs them.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ $(id -u) == 0 && $(ps -p 1 -o comm=) == systemd && $(uname -m) == x86_64 ]]
[[ ${IMPLEMENTATION_SHA:?} =~ ^[0-9a-f]{40}$ && ${HARNESS_SHA:?} =~ ^[0-9a-f]{40}$ ]]
[[ ${GITHUB_RUN_ID:?} =~ ^[0-9]+$ ]]
[[ ! -e /var/lib/machines/mc-backend && ! -e /var/lib/machines/mc-edge && ! -e /var/lib/mail-core-host ]]
[[ ! -e /etc/postfix && ! -e /etc/dovecot && ! -e /etc/rspamd ]]  # the runner itself carries no mail stack
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMPLEMENTATION_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "${CONTROLLER_PYTHON:?}")")")
[[ $(git -C "$IMPLEMENTATION_ROOT" rev-parse HEAD) == "$IMPLEMENTATION_SHA" ]]
[[ $(git -C "$HERE" rev-parse HEAD) == "$HARNESS_SHA" ]]
unset OPS_DEPLOY_PATH OPS_LIBRARY_PATH
export IMPLEMENTATION_ROOT
EVIDENCE=/var/tmp/mail-core-evidence
STATE=/var/lib/mail-core-host
install -d -m 0700 "$EVIDENCE" "$STATE"

# Exhaustive proof that the controller imports the immutable, non-editable
# implementation and that every installed package file equals its Git bytes.
"$CONTROLLER_PYTHON" - <<'PY'
import hashlib, importlib.metadata, json, os, subprocess, sysconfig
from pathlib import Path
import ops_deploy
selected = os.environ['IMPLEMENTATION_SHA']
source = Path(os.environ['IMPLEMENTATION_ROOT'])
installed = Path(ops_deploy.__file__).resolve().parent
direct = json.loads(importlib.metadata.distribution('ops-deploy').read_text('direct_url.json'))
assert direct.get('vcs_info', {}).get('commit_id') == selected
assert not direct.get('dir_info', {}).get('editable', False)
assert installed == (Path(sysconfig.get_paths()['purelib']) / 'ops_deploy').resolve()
assert not installed.is_relative_to(source / 'src')
tracked = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-r', '--name-only', selected, 'src/ops_deploy/'], text=True).splitlines()
assert tracked
names = {name.removeprefix('src/ops_deploy/') for name in tracked}
actual = {str(p.relative_to(installed)) for p in installed.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
assert actual == names
resources = {}
for name in tracked:
    relative = name.removeprefix('src/ops_deploy/')
    expected = subprocess.check_output(['git', '-C', str(source), 'show', selected + ':' + name])
    data = (installed / relative).read_bytes()
    assert data == expected, name
    resources[relative] = hashlib.sha256(data).hexdigest()
Path('/var/tmp/mail-core-evidence/installed-artifact.json').write_text(json.dumps(
    {'implementation_sha': selected, 'harness_sha': os.environ['HARNESS_SHA'], 'direct_url': direct,
     'installed_root': str(installed), 'resources': resources}, indent=2))
PY

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Host-side fixture tooling only; nothing here is a mail package for the guests.
apt-get install -y -qq --no-install-recommends debootstrap systemd-container dnsmasq-base openssl

# One minimal Ubuntu 24.04 rootfs (no mail packages), copied per system.
BASE=$STATE/rootfs-base
debootstrap --variant=minbase --components=main,universe \
  --include=systemd,systemd-sysv,dbus,openssh-server,python3,iproute2,ca-certificates,curl,gnupg,netbase,fish,sudo,procps,less \
  noble "$BASE" http://archive.ubuntu.com/ubuntu > "$EVIDENCE/debootstrap.log" 2>&1
cat > "$BASE/etc/apt/sources.list.d/ubuntu.sources" <<'SOURCES'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
rm -f "$BASE/etc/apt/sources.list"
rm -f "$BASE"/etc/ssh/ssh_host_*
install -d -m 0755 "$BASE/var/log/journal"
for name in backend edge; do
  cp -a "$BASE" "/var/lib/machines/mc-$name"
done
rm -rf "$BASE"

ssh-keygen -q -t ed25519 -N '' -C mail-core-fixture -f "$STATE/controller_ed25519"
: > "$STATE/known_hosts"
declare -A ADDRESSES=([backend]="192.168.104.1/24 192.168.104.21/24 198.18.0.21/32" [edge]="192.168.104.3/24 192.168.104.20/24")
declare -A PRIMARY=([backend]=192.168.104.1 [edge]=192.168.104.3)
for name in backend edge; do
  root=/var/lib/machines/mc-$name
  echo "$name" > "$root/etc/hostname"
  printf '127.0.0.1 localhost\n127.0.1.1 %s.fixture.test %s\n192.168.104.1 backend.fixture.test\n192.168.104.3 edge.fixture.test\n' "$name" "$name" > "$root/etc/hosts"
  rm -f "$root/etc/resolv.conf"
  printf 'nameserver 192.168.104.254\n' > "$root/etc/resolv.conf"
  {
    printf '[Match]\nName=host0\n\n[Network]\n'
    for address in ${ADDRESSES[$name]}; do printf 'Address=%s\n' "$address"; done
    printf 'Gateway=192.168.104.254\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n'
    if [[ $name == edge ]]; then printf '\n[Route]\nDestination=198.18.0.21/32\nGateway=192.168.104.1\n'; fi
  } > "$root/etc/systemd/network/10-host0.network"
  chroot "$root" systemctl enable systemd-networkd.service ssh.service > /dev/null 2>&1
  chroot "$root" ssh-keygen -q -A
  chroot "$root" chsh -s /usr/bin/fish root
  install -d -m 0700 "$root/root/.ssh"
  install -m 0600 "$STATE/controller_ed25519.pub" "$root/root/.ssh/authorized_keys"
  printf '%s %s\n' "${PRIMARY[$name]}" "$(cut -d' ' -f1,2 "$root/etc/ssh/ssh_host_ed25519_key.pub")" >> "$STATE/known_hosts"
  install -d -m 0755 "$root/var/lib/mail-core-fixture"
  echo "$GITHUB_RUN_ID" > "$root/var/lib/mail-core-fixture/OWNED"
done

# Private bridge, NAT for package mirrors and real DNS recursion, no SMTP egress.
ip link add mcbr0 type bridge
ip addr add 192.168.104.254/24 dev mcbr0
ip link set mcbr0 up
sysctl -q -w net.ipv4.ip_forward=1
iptables -I FORWARD 1 -i mcbr0 ! -o mcbr0 -p tcp -m multiport --dports 25,465,587,2525 -j REJECT
iptables -I FORWARD 2 -i mcbr0 -j ACCEPT
iptables -I FORWARD 3 -o mcbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.104.0/24 ! -o mcbr0 -j MASQUERADE
ip6tables -I FORWARD 1 -i mcbr0 -j REJECT
iptables -S FORWARD > "$EVIDENCE/host-forward-rules.txt"

cat > "$STATE/dnsmasq.conf" <<'DNS'
interface=mcbr0
bind-interfaces
except-interface=lo
no-resolv
no-hosts
server=127.0.0.53
local=/test/
host-record=backend.fixture.test,192.168.104.1
host-record=edge.fixture.test,192.168.104.3
host-record=sink.fixture.test,192.168.104.20
host-record=client.fixture.test,192.168.104.21
mx-host=example.test,edge.fixture.test,10
mx-host=alias.example.test,edge.fixture.test,10
mx-host=remote.fixture.test,sink.fixture.test,10
DNS
systemd-run --quiet --unit=mail-core-fixture-dns /usr/sbin/dnsmasq --keep-in-foreground --conf-file="$STATE/dnsmasq.conf"

cat > /etc/systemd/system/mail-core-fixture-nspawn@.service <<'UNIT'
[Unit]
Description=Owned mail core fixture system %i
After=network.target

[Service]
# No binds of any host path, home, workspace, credential or socket.
ExecStart=/usr/bin/systemd-nspawn --quiet --keep-unit --boot --link-journal=no --resolv-conf=off --timezone=off --private-users=no --settings=no --network-bridge=mcbr0 --machine=%i --directory=/var/lib/machines/%i
KillMode=mixed
Type=notify
Slice=machine.slice
Delegate=yes
TasksMax=16384
UNIT
systemctl daemon-reload
for name in backend edge; do
  systemctl start "mail-core-fixture-nspawn@mc-$name.service"
done
for name in backend edge; do
  for _ in $(seq 1 90); do
    if ssh -i "$STATE/controller_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=yes \
         -o BatchMode=yes -o ConnectTimeout=3 "root@${PRIMARY[$name]}" true 2> /dev/null; then
      break
    fi
    sleep 2
  done
  ssh -i "$STATE/controller_ed25519" -o UserKnownHostsFile="$STATE/known_hosts" -o StrictHostKeyChecking=yes \
    -o BatchMode=yes -o ConnectTimeout=3 "root@${PRIMARY[$name]}" true
done
systemctl show 'mail-core-fixture-nspawn@mc-backend.service' 'mail-core-fixture-nspawn@mc-edge.service' \
  -p Id -p ExecStart > "$EVIDENCE/nspawn-units.txt"

export MAIL_CORE_STATE=$STATE MAIL_CORE_FIXTURE=$HERE
"$CONTROLLER_PYTHON" "$HERE/harness.py" "$EVIDENCE"
