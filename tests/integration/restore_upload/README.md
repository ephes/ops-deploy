# Owned restore-upload primitive proof

Build this source-only fixture with the repository as context, then run it with
`--network none --cpus 1 --memory 512m --pids-limit 128`. It requires no privilege,
host mounts, host socket, host ports, inventory, credentials or archive input.
The build fetches ordinary Ubuntu packages; the test container has no network.
It uses synthetic files and disposable container paths only.

The test runs the actual public helper's root creation and move/chown/chmod
scripts with real Linux tools and real rsync. Only rsync's SSH destination is
replaced by a local owned staging path. Separate exact-argv tests bind all SSH
options to the same inventory target. This is not a real inventory restore,
native service qualification, or a claim that an interrupted remote writer has
stopped. Failed stages retain their unique temporary identity; they do not start
restore or delete staging on an unknown remote result.

The complete source test also executes the first-name classifier, checks all
archive selection, preserves existing backup-root ownership/mode, checks final
0600 archive permissions, and exercises actual child timeout cleanup. No archive
body is interpreted; all file contents in this fixture are synthetic.
