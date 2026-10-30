# Certbot original lifecycle contract

Exact original public role/default/internal task and host-script snapshots from
ops-library 3627919. The installed archive validator and tree preserver remain
byte-exact originals; the public host orchestration reuses their functions.
Backup archive walking follows the existing community.general.archive provider
add_targets algorithm: walk directory entries without following directory links,
add each entry once relative to the source parent, and preserve tar links.

The backup tasks force generated/fetched/existing selected archives 0600; their
file-mode default is declared but unused. Restore supports original tar formats
and internal Certbot link graphs, retained prior trees, verified mount-point
copy+empty, and original failure cleanup. The original normal renewal command
has no config-dir option and is managed work; only explicit validation avoids
staging/publication/renewal. No policy-backed external mount registration is added.
