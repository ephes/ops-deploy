#!/usr/bin/env bash
# Only an ephemeral GitHub-hosted Ubuntu x86 systemd runner; never inventory.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      ! "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ || "${RUNNER_TEMP:-}" != /home/runner/work/_temp ]]; then
    echo 'Refusing Mailgun fixture outside an owned GitHub-hosted runner' >&2
    exit 2
fi
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 && "$(cat /proc/1/comm)" == systemd ]]
unset MAILGUN_FIXTURE_TRANSLATED OPS_LIBRARY_PATH VIRTUAL_ENV
task_dir="$RUNNER_TEMP/mailgun-relay-fixture"
evidence="$RUNNER_TEMP/mailgun-relay-evidence"
mkdir -p "$task_dir/artifacts" "$evidence"
chmod 0700 "$task_dir"
git diff --exit-code
git rev-parse HEAD > "$evidence/implementation-sha.txt"
git -C .relay-source rev-parse HEAD > "$evidence/python-source-sha.txt"
[[ "$(cat "$evidence/python-source-sha.txt")" == d113daeb5388740e4dc0cf5119fbca1e9f4e4016 ]]
uname -a > "$evidence/kernel.txt"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends openssh-server rsync curl openssl >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$task_dir/key"
sudo install -d -m 0700 /root/.ssh
sudo install -d -m 0755 /run/sshd
cat "$task_dir/key.pub" | sudo tee -a /root/.ssh/authorized_keys >/dev/null
sudo chmod 0600 /root/.ssh/authorized_keys
printf 'PermitRootLogin prohibit-password\nPubkeyAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/00-mailgun-fixture.conf >/dev/null
sudo /usr/sbin/sshd -t
sudo systemctl restart ssh
sudo cat /etc/ssh/ssh_host_ed25519_key.pub | awk '{print "127.0.0.1 " $1 " " $2}' > "$task_dir/known_hosts"
uvbin="$(command -v uv)"
sudo install -m 0755 "$uvbin" /usr/local/bin/uv
for version in 0.2.1 0.2.2; do
    archive="mailgun-relay-$version-x86_64-unknown-linux-gnu.tar.gz"
    curl --fail --silent --show-error --location --retry 3 \
        "https://github.com/ephes/mailgun-relay/releases/download/rs-v$version/$archive" \
        --output "$task_dir/artifacts/$archive"
done
(
    cd "$task_dir/artifacts"
    printf '%s\n' \
        '01d0f886ffc2d53dac689a25407c7af4843fde38efe9f784de5128393c59b342  mailgun-relay-0.2.1-x86_64-unknown-linux-gnu.tar.gz' \
        '6da71db3eb4f70c9a9d178e41220fd6afd36223531b4c25683a542dfc6e3bc7a  mailgun-relay-0.2.2-x86_64-unknown-linux-gnu.tar.gz' \
        | sha256sum --check | tee "$evidence/archive-checks.txt"
    tar -xOf mailgun-relay-0.2.2-x86_64-unknown-linux-gnu.tar.gz mailgun-relay \
        | sha256sum > "$evidence/selected-binary-sha256.txt"
)
export SMOKE_SSH_HOST=127.0.0.1 SMOKE_SSH_PORT=22
export SMOKE_SSH_KEY="$task_dir/key" SMOKE_SSH_KNOWN_HOSTS="$task_dir/known_hosts"
export MAILGUN_FIXTURE_SOURCE="$PWD/.relay-source" MAILGUN_FIXTURE_ARTIFACT_DIR="$task_dir/artifacts"
export MAILGUN_FIXTURE_EVIDENCE_DIR="$evidence"
uv run --locked pytest tests/smoke/test_mailgun_relay_smoke.py -vv -rA \
    --junitxml="$evidence/junit.xml" | tee "$evidence/pytest.log"
python3 - "$evidence/junit.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
cases = ET.parse(sys.argv[1]).getroot().findall('.//testcase')
assert len(cases) == 1, 'expected exactly one native integration scenario'
assert not any(case.find(tag) is not None for case in cases for tag in ['skipped', 'failure', 'error']), \
    'native scenario must pass without skips'
PY
