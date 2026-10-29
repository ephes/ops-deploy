#!/bin/bash
# Targeted 2026-10-29 incident procedure, not a general Mastodon deploy.
set -euo pipefail
umask 077
step=${1:?step required}
domain=${2:?web domain required}
site=/home/mastodon/live
backup=/opt/backups/mastodon/security-4.7.4
units=(mastodon-web mastodon-sidekiq mastodon-streaming)
target=v4.7.4
target_commit=d04059fc80be5cbba6b4dd5a8b94d63ffff09f2c
ruby=4.0.9
node=v24.19.0
runtime_path="/home/mastodon/.nvm/versions/node/$node/bin:/home/mastodon/.rbenv/bin:/home/mastodon/.rbenv/shims:/usr/local/bin:/usr/bin:/bin"

as_app() {
    sudo -u mastodon -H /bin/bash -c '
        set -euo pipefail
        export RBENV_ROOT=/home/mastodon/.rbenv
        export RBENV_VERSION=4.0.9
        export NVM_DIR=/home/mastodon/.nvm
        export PATH="$1"
        cd /home/mastodon/live
        shift
        eval "$1"
    ' bash "$runtime_path" "$1"
}

rails() {
    as_app "set -a; . ./.env.production; set +a; export RAILS_ENV=production; $1"
}

case "$step" in
    preflight)
        test "$(id -u)" = 0
        test -f "$site/.env.production"
        checkout_state=$(sudo -u mastodon git -C "$site" status --porcelain)
        test -z "$checkout_state"
        current=$(sudo -u mastodon git -C "$site" describe --tags --exact-match)
        [[ "$current" = v4.6.9 || "$current" = "$target" ]]
        test "$(df --output=avail -B1 "$site" | tail -1)" -gt 21474836480
        systemctl is-active "${units[@]}" mastodon-nginx
        # This incident procedure supports only the existing enabled timer.
        systemctl is-enabled --quiet mastodon-maintenance.timer
        # Do not race a maintenance task or allow its timer to fire during upgrade.
        if systemctl is-active --quiet mastodon-maintenance.service; then
            echo 'Maintenance is running; wait for it to finish before upgrading' >&2
            exit 1
        fi
        test -f /usr/local/bin/mastodon-maintenance
        for unit in "${units[@]}" mastodon-maintenance; do
            grep -q '^Environment=RBENV_VERSION=' "/etc/systemd/system/$unit.service"
            grep -q '^Environment=PATH=' "/etc/systemd/system/$unit.service"
        done
        sudo -u mastodon -H /bin/bash -c '. /home/mastodon/live/.env.production; test "${DB_NAME:-}" = mastodon'
        curl --fail --silent --show-error --max-time 15 \
            -H "Host: $domain" -H 'X-Forwarded-Proto: https' http://127.0.0.1:10042/api/v2/instance \
            | python3 -c 'import json,sys; assert json.load(sys.stdin)["version"] == sys.argv[1]' "${current#v}"
        curl --fail --silent --show-error --max-time 15 http://127.0.0.1:10043/api/v1/streaming/health > /dev/null
        ;;
    backup)
        if test -f "$backup/COMPLETE"; then
            (cd "$backup" && sha256sum -c SHA256SUMS)
            exit 0
        fi
        # Refuse to accidentally back up an already migrated database as the original.
        test "$(sudo -u mastodon git -C "$site" describe --tags --exact-match)" = v4.6.9
        test ! -e "$backup"
        mkdir -p /opt/backups/mastodon
        mkdir -m 700 "$backup"
        systemctl is-enabled mastodon-maintenance.timer > "$backup/timer-state"
        systemctl stop mastodon-maintenance.timer
        trap 'systemctl start "${units[@]}"; if grep -qx enabled "$backup/timer-state"; then systemctl start mastodon-maintenance.timer; fi' EXIT
        systemctl stop "${units[@]}"
        sudo -u postgres pg_dump -Fc mastodon > "$backup/database.dump"
        sudo -u postgres pg_restore --list < "$backup/database.dump" > "$backup/database.list"
        sudo -u postgres pg_dumpall --globals-only > "$backup/globals.sql"
        sudo -u mastodon git -C "$site" rev-parse HEAD > "$backup/source-commit"
        tar -czf "$backup/config.tar.gz" -C / \
            home/mastodon/live/.env.production \
            home/mastodon/live/.bundle \
            etc/systemd/system/mastodon-web.service \
            etc/systemd/system/mastodon-sidekiq.service \
            etc/systemd/system/mastodon-streaming.service \
            etc/systemd/system/mastodon-maintenance.service \
            usr/local/bin/mastodon-maintenance
        tar -czf "$backup/media.tar.gz" --exclude=public/system/cache -C "$site" public/system
        (cd "$backup" && sha256sum database.dump globals.sql config.tar.gz media.tar.gz timer-state source-commit > SHA256SUMS)
        touch "$backup/COMPLETE"
        ;;
    runtime)
        test -f "$backup/COMPLETE"
        sudo -u mastodon git -C "$site" fetch origin tag "$target"
        resolved_target=$(sudo -u mastodon git -C "$site" rev-parse "$target^{commit}")
        test "$resolved_target" = "$target_commit"
        test "$(sudo -u mastodon git -C "$site" show "$target:.ruby-version")" = "$ruby"
        test "$(sudo -u mastodon git -C "$site" show "$target:.nvmrc")" = 24.19
        as_app 'git -C "$RBENV_ROOT/plugins/ruby-build" pull --ff-only; RUBY_CONFIGURE_OPTS=--with-jemalloc MAKE_OPTS=-j2 rbenv install -s 4.0.9'
        as_app '. "$NVM_DIR/nvm.sh"; nvm install 24.19.0; nvm alias default 24.19.0; corepack enable'
        ;;
    dependencies)
        test -f "$backup/COMPLETE"
        systemctl stop mastodon-maintenance.timer
        if systemctl is-active --quiet mastodon-maintenance.service; then
            echo 'Maintenance is running; wait for it to finish before upgrading' >&2
            exit 1
        fi
        # Keep the original DB backup and units available until the entire upgrade is verified.
        sudo -u mastodon git -C "$site" checkout "$target"
        as_app 'gem install bundler --no-document; bundle config set --local build.charlock_holmes --with-cxxflags=-std=c++17; bundle install --jobs 2 --retry 3; yarn install --immutable'
        ;;
    assets)
        rails 'bundle exec rails assets:precompile'
        ;;
    pre-migrate)
        rails 'SKIP_POST_DEPLOYMENT_MIGRATIONS=true bundle exec rails db:migrate'
        ;;
    restart)
        for unit in "${units[@]}" mastodon-maintenance; do
            sed -i -e "s|^Environment=RBENV_VERSION=.*|Environment=RBENV_VERSION=$ruby|" \
                -e "s|^Environment=PATH=.*|Environment=PATH=$runtime_path|" \
                "/etc/systemd/system/$unit.service"
        done
        sed -i -e "s|^export RBENV_VERSION=.*|export RBENV_VERSION=\"$ruby\"|" \
            -e "s|^export PATH=.*|export PATH=\"$runtime_path\"|" /usr/local/bin/mastodon-maintenance
        as_app 'rbenv global 4.0.9; rbenv rehash'
        systemctl daemon-reload
        systemctl restart "${units[@]}"
        ;;
    post-migrate)
        rails 'bundle exec rails db:migrate'
        ;;
    verify)
        systemctl is-active "${units[@]}" mastodon-nginx
        for unit in "${units[@]}" mastodon-maintenance; do
            effective_env=$(systemctl show "$unit" --property=Environment --value)
            case " $effective_env " in
                *" RBENV_VERSION=$ruby "*) ;;
                *) echo "$unit has an unexpected effective Ruby version" >&2; exit 1 ;;
            esac
            case " $effective_env " in
                *" PATH=$runtime_path "*) ;;
                *) echo "$unit has an unexpected effective PATH" >&2; exit 1 ;;
            esac
        done
        as_app 'ruby --version; node --version; bundle check'
        rails 'bundle exec rails db:abort_if_pending_migrations'
        curl --fail --silent --show-error --retry 30 --retry-delay 2 --retry-all-errors \
            -H "Host: $domain" -H 'X-Forwarded-Proto: https' http://127.0.0.1:10042/api/v2/instance \
            | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["domain"],d["version"]); assert d["version"] == "4.7.4"'
        curl --fail --silent --show-error http://127.0.0.1:10043/api/v1/streaming/health
        if grep -qx enabled "$backup/timer-state"; then
            systemctl start mastodon-maintenance.timer
        fi
        touch "$backup/UPGRADED"
        ;;
    *) echo "Unknown step: $step" >&2; exit 2 ;;
esac
