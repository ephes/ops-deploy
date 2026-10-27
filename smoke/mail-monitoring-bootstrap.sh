#!/bin/bash
# ONLY for an empty disposable Ubuntu mail fixture, never an inventory host.
# Creates synthetic schemas/accounts and replaces this VM's Dovecot config.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postgresql python3-psycopg2 dovecot-core dovecot-imapd dovecot-pgsql curl
getent group vmail >/dev/null || groupadd -g 5000 vmail
id vmail >/dev/null 2>&1 || useradd -u 5000 -g vmail -s /usr/sbin/nologin -M vmail
id nyxmon >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -M nyxmon
install -d -o vmail -g vmail -m0700 /var/lib/mail-fixture
runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<'SQL'
CREATE DATABASE mail;
CREATE ROLE mail_fixture LOGIN PASSWORD 'fixture-database-only';
SQL
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d mail <<'SQL'
CREATE TABLE domain(domain text PRIMARY KEY);
INSERT INTO domain VALUES ('example.test');
CREATE TABLE mailbox(username text PRIMARY KEY,password text NOT NULL,name text,maildir text,quota bigint,local_part text,domain text,active boolean,created timestamp,modified timestamp);
CREATE TABLE mail_domains(id serial PRIMARY KEY,name text);
INSERT INTO mail_domains(name) VALUES ('example.test');
CREATE TABLE mail_users(id serial PRIMARY KEY,domain_id integer,localpart text,password text,active boolean);
GRANT SELECT ON mailbox TO mail_fixture;
SQL
cat > /etc/dovecot/dovecot.conf <<'EOF'
protocols = imap
listen = 127.0.0.1
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain
mail_location = maildir:/var/lib/mail-fixture/%d/%n
first_valid_uid = 5000
passdb {
 driver = sql
 args = /etc/dovecot/fixture-sql.conf
}
userdb {
 driver = static
 args = uid=5000 gid=5000 home=/var/lib/mail-fixture/%d/%n
}
EOF
cat > /etc/dovecot/fixture-sql.conf <<'EOF'
driver = pgsql
connect = host=127.0.0.1 dbname=mail user=mail_fixture password=fixture-database-only
default_pass_scheme = SHA512-CRYPT
password_query = SELECT username AS user, password FROM mailbox WHERE username = '%u' AND active = true
EOF
chmod 0600 /etc/dovecot/fixture-sql.conf
systemctl restart dovecot
install -d -m0700 -o nyxmon -g nyxmon /home/nyxmon/site

touch /etc/ops-deploy-mail-fixture
