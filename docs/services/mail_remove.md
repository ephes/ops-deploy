# mail removal

`ops_deploy.services.mail_remove`: `remove_mail(MailRemoveConfig(...))` ports
the `mail_remove` role at ops-library `44a532ba` (recorded under
`tests/parity/mail/remove`). The defaults are the role's: no component
selected, packages purged, config and state directories removed, and the
Maildir/backups (`remove_data`), the vmail account (`remove_vmail_user`) and
the PostgreSQL database and role (`drop_database`, `drop_db_user`) kept.

Without `confirm` and at least one of `backend` (Postfix, Dovecot, OpenDKIM),
`relay` (Postfix, postgrey) and `spam` (rspamd) it fails before any host
probe. Service, package and path lists are the selected components' lists
joined in the role's order, each name once.

In the role's order:

1. with `backend` or `relay`: a warning when `postqueue -p` reports a
   non-empty queue (nothing is flushed);
2. stop and disable each selected service systemd knows (disable before stop,
   failures ignored; an unknown unit is skipped, as `service_facts` does);
3. `apt-get --purge remove` of the selected packages dpkg knows (installed or
   with config files left), in one call with the apt module's dpkg options;
   nothing when none is left (`purge_packages`);
4. remove the config directories (`remove_configs`), the state directories
   (`remove_state`) and, with `remove_data`, `/mnt/cryptdata/vmail` and
   `/mnt/cryptdata/backups/mail`;
5. with `remove_vmail_user`: `userdel` (`-r` with `remove_data`) and
   `groupdel` when the group still exists;
6. with `drop_database`: `DROP DATABASE "mail"` (`WITH (FORCE)` with
   `db_force_disconnect`) when it exists; with `drop_db_user`: `DROP USER
   "mail"` when it exists; both through `runuser -u postgres -- psql` (peer
   auth, as `become_user: postgres`). An unreadable database state or a
   failing drop fails the removal, as the modules do.

No mail data, credentials or database contents pass through the controller;
the PostgreSQL probes read only whether the database and role exist.
