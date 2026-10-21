# Rust port of the Echoport remote command guard — implementation plan

Status: S0, S1, S2, S3a and S4 implemented (campaign "Rust-Ports Runde 2", stream
`rust-echoport-command-guard`; see `README.md`). Nothing in this directory is
released or deployed yet. This file is the contract for the implementers and
reviewers of every slice below; a slice that wants to deviate changes this
file first, in its own reviewed diff.

Source of truth for behaviour: the Python guard
`roles/echoport_remote_command_guard/files/echoport-remote-command-guard.py`
at ops-library `a6ed074e` (2.53.0, 721 lines, sha256 `ca74405e…`), cited below
as `guard.py:<line>`. The Python guard is the **oracle** for every decision:
the Rust guard must not accept anything the Python guard refuses, and must make
the same decision for everything the runners send. It is a **security
contract**, not a byte-parity target. Section 3 lists which observable
behaviours must stay the same, and section 4 lists the differences that are
allowed, which are all stricter refusals.

Precedents this plan follows: `mailgun-relay/rust/PLAN.md` and
`nyxmon/agent-rs/PLAN.md` (Python as oracle, fixtures generated from Python, a
parity harness, a pinned release on an old glibc baseline, an impl selector in
the role with Python as rollback, a shadow run, a cutover with a rollback
drill, and Python retirement as its own slice). The shared Rust foundation in
this repo is designed in `rust/PLAN-foundation.md` (stream
`rust-metrics-httpd`), and its slice ids are used here: **F1** (Cargo
workspace, toolchain, `rust.yml` CI), **F2** (`rust-release.yml` with
per-binary tags) and **F3** (the internal install/pin/prune role
`rust_release_binary`). F4 (the pyinfra helper in ops-deploy) is not needed:
this role is Ansible only. This plan does not design its own release
pipeline. Section 8.1 lists what it needs from the foundation.

Owner decisions of 2026-10-21 are recorded in section 9; they replace the
former owner questions.

---

## 1. Live facts (gathered read-only on 2026-10-21)

### 1.1 What runs where

The guard is **not a long-running process**. sshd runs it as the forced
command of one `authorized_keys` line (the deploy@macmini backup key, logging
in as root) for every SSH command an Echoport remote runner on macmini sends.
It checks the command and then `execvp`s it (the PID then belongs to the
target command), or it refuses and exits. No systemd unit or timer belongs to
it.

| Host (inventory) | Address | OS | glibc | Python | OpenSSH | rsync | Arch |
|---|---|---|---|---|---|---|---|
| `production` | `wersdoerfer.de` | Ubuntu 24.04.5 LTS | 2.39 | 3.12.3 | 9.6p1 | 3.2.7 | x86_64 |
| `staging` | `staging.wersdoerfer.de` | Debian 13 (trixie) | 2.41 | 3.13.5 | 10.0p2 | 3.5.0 | x86_64 |

These are the only two hosts with the guard. `root_ssh_deploy_backup_key_pinned:
true` is set only in ops-control `inventories/prod/host_vars/{production,staging}.yml`.
`heis` has the deploy key without the pin, so no guard runs there. macmini is
the runner host (the SSH client) and has no guard.

Installed on both hosts (2026-10-16):

- `/usr/local/sbin/echoport-remote-command-guard`, root:root `0755`, 715
  lines, sha256 `d1cc449d…` = ops-library `7b61eed6`. This is the version
  **before** `.timeout` support (`a6ed074e`, 2.53.0, is not deployed yet; see
  6.4).
- `/etc/echoport/remote-command-guard.json`, root:root `0644` (production
  850 bytes, staging 1100 bytes), rendered from host_vars
  `echoport_remote_command_guard_policy`.
- `/root/.ssh/authorized_keys`: the deploy key line carries
  `from="<macmini tailnet v4>,<macmini tailnet v6>",restrict,command="/usr/bin/python3 -I /usr/local/sbin/echoport-remote-command-guard /etc/echoport/remote-command-guard.json"`.
- sshd: `syslogfacility AUTH`, `loglevel INFO`. NSS on production is
  `passwd: compat systemd`, on staging `files`. The service users
  (`postgres`, `gotosocial`, `python-podcast`, `marina`, `villakunterbunt`)
  are all in `/etc/passwd`.

### 1.2 Load and memory

- Invocations, from `journalctl -t echoport-remote-command-guard`:
  production 23–46 per day (2026-10-16 to 10-21, 179 allowed, 1 refused
  `id`, 1 refused interactive probe). The staging journal holds only
  2026-10-21: 46 allowed, 0 refused. Every runner command seen in the last 24
  hours had an allowed shape (section 3.4 lists the shapes).
- Cost per invocation (the Python guard under `/usr/bin/time`, Ubuntu 24.04
  container with Python 3.12.3, **arm64**, measured locally; S7 re-measures
  on the x86_64 hosts): peak RSS 13.3–13.5 MiB, wall time 10–20 ms for
  `--check-policy`, for a refusal and for an allowed command up to `exec`.
  There is no resident memory and no RSS at rest.
- So the resource gain is small: about 11 MiB less peak and about 15 ms less
  for each of a few dozen SSH commands a day. The main value of the port is
  elsewhere (section 9, Q1). The root forced-command path no longer depends on
  the distribution's Python, which already differs between the hosts (3.12
  and 3.13) and behaves differently in places that matter here (realpath,
  section 3.3.6). The parser also becomes typed and fuzzed.

### 1.3 How it is deployed today

- Engine: **Ansible**. ops-control `docs/PYINFRA.md` ("Not registered"):
  `authorize-root-ssh.yml`, `authorize-opsgate-root-ssh.yml` and
  `remove-root-ssh-key.yml` stay on Ansible for every host, the
  pyinfra-deployed ones included. This plan does not move them.
- Entry point: `just pin-deploy-backup-key <hosts>`, where the argument is
  positional (`staging`, `production` or `production,staging`; the
  default is both). It lives in ops-control `justfiles/register.just` and
  runs
  `ansible-playbook -i inventories/prod/hosts.yml playbooks/authorize-root-ssh.yml --limit <hosts>`
  with `SOPS_AGE_KEY_FILE`.
- Inside `playbooks/authorize-root-ssh.yml` (ops-control main `93368405`), in
  this order:
  1. Assert ops-library ≥ 2.54.0.
  2. Write deploy's ssh_config route on macmini (`throttle: 1`).
  3. Probe over the route.
  4. `include_role: local.ops_library.echoport_remote_command_guard` (l.161).
  5. Build the key line with `command="<echoport_remote_command_guard_forced_command>"`
     (l.175–177).
  6. Run `ssh_authorized_keys_manage` with `exclusive: false` (l.207).
  7. Post-probe: `failed_when` stderr lacks
     `interactive sessions are not allowed` (l.221; the same string at
     l.157).
- Role `roles/echoport_remote_command_guard`:
  - copies the guard (root `0755`, `tasks/main.yml:52`);
  - writes the policy (`0644`) with
    `validate: <python> -I <guard> --check-policy %s` (l.71);
  - sets the fact `echoport_remote_command_guard_forced_command` (l.74).
- The collection gets to ops-control through `just install-local-library`.
- Production deploys take the shared controller deploy lock
  `/tmp/ops-control-deploy.lock` (ops coordination, 2026-10-21; see 6.1).

---

## 2. Scope

**In scope:** a Rust binary `echoport-command-guard` (crate
`rust/echoport-command-guard` in the shared workspace) that does what
`guard.py` does: forced-command mode, `--check-policy`, the same policy file,
the same allowlist, the same redirections and run-as rules, the same syslog
records and the same stderr messages and exit codes. It also gets three
modes that a client cannot reach (section 3.6), plus:

- the role switch;
- the ops-control wiring;
- the shadow run;
- the cutover with a rollback drill;
- Python retirement.

**Hosts:** production and staging (x86_64). No new hosts are pinned as part
of this stream.

---

## 3. The contract to preserve

Levels as in the precedents:

- **P1**: must be identical. A fixture or test enforces it.
- **P2**: must be equivalent. The text may differ, the meaning may not.
- **P3**: an intentional difference, listed exhaustively in section 4.

### 3.1 Invocation, arguments, exit codes (P1)

`guard.py:673-717`. The argument grammar is exact; no option parser library
is involved.

| argv | Behaviour | Exit |
|---|---|---|
| `<prog> --check-policy <file>` (exactly 3) | Load and validate the policy. On error print `echoport-remote-command-guard: invalid policy: <detail>` to stderr. | 0 / 1 |
| `<prog> <file>` (exactly 2) | Forced-command mode, below. | |
| anything else | `echoport-remote-command-guard: usage: echoport-remote-command-guard <policy.json> \| --check-policy <policy.json>` | 2 |

Forced-command mode, in this order:

1. `SSH_ORIGINAL_COMMAND` unset: log a warning `refused interactive session
   from <client>` and print `echoport-remote-command-guard: interactive
   sessions are not allowed` to stderr, exit 1. **This happens before the
   policy is read.** ops-control's probes depend on this exact stderr text.
2. Load the policy. On any error: log an error `policy error (<ExcType>):
   refusing <repr(command)>`, print `echoport-remote-command-guard: policy
   error`, exit 1.
3. `check()` (sections 3.3 and 3.4). Then the umask, then open the redirects
   (3.5). On `Refused` or an OS error: log a warning `refused from <client>:
   <reason>: <repr(command)>`, print `echoport-remote-command-guard: command
   not allowed`, exit 1.
4. Log info `allowed from <client>: <repr(command)>`. Set `PATH` to `SAFE_PATH`
   (`guard.py:33`). Run Python's `os.execvp(argv[0], argv)`; 3.5 describes
   its exact PATH search. If exec fails, print
   `echoport-remote-command-guard: cannot run <argv0>: <strerror>`, exit 127.

`<client>` is `SSH_CLIENT.split(" ")[0]`, or `-` when `SSH_CLIENT` is unset.
The program name in every message is `echoport-remote-command-guard`, whatever
the binary is called.

**The guard writes nothing to stdout and reads nothing from stdin, ever.**
stdout and stdin carry the scp/rsync protocols and the dump streams. A test
enforces this for every mode (3.5, S4).

### 3.2 Policy file (P1 for accepted policies, P3 for some refusals)

`guard.py:96-160, 662-670`; role `defaults/main.yml`; role assert
`tasks/main.yml:1-35`.

- JSON object, read as UTF-8. Top-level keys: `postgres` (object with
  `dump_databases`, `restore_databases` (name → owner role),
  `temp_file_prefixes`, `scratch_restore_prefixes`), `units`,
  `private_media_paths`, `path_roots` (`{path, owner}`), `temp_dirs`,
  `sqlite_snapshots` (`{database, owner, temp_dir}`), `read_files`,
  `ready_urls`. A missing key or `null` means empty. **Unknown keys are
  ignored** (P1: same as Python). The role assert already limits the
  top-level keys; refusing unknown keys could lock out a host whose policy
  carries an extra `postgres` sub-key.
- Validation, with each rule as in Python:
  - database and role names: `_SAFE_NAME_RE`;
  - temp file prefixes `[a-z0-9_]+`, scratch prefixes `[a-z][a-z0-9_]*`;
  - units: `_SAFE_NAME_RE`;
  - private media paths, path roots, sqlite databases and read files: safe
    path with at least 2 slashes;
  - owners: `_SAFE_OWNER_RE` and not `root:`; the sqlite user is not `root`;
  - temp templates: `_TEMP_TEMPLATE_RE`; ready URLs: `_READY_URL_RE`.
- Normalisation: private media paths and path roots are stripped of trailing
  `/` (`guard.py:119,121`).
- **Order matters.** `path_roots` and `sqlite_snapshots` are ordered lists
  and the first match wins (`guard.py:229-231`, `170-173`, `378-389`). The
  Rust policy keeps the list order. Sets (`units`, `read_files`, …) only
  answer membership questions.
- The policy is read on every invocation. The file's ownership and mode are
  not checked (P1: the same as today).

### 3.3 Parsing and helper semantics (P1 unless noted)

1. **Pre-checks** (`guard.py:454-455`): the command is non-empty and at most
   `MAX_COMMAND_LENGTH = 4096` *characters* (Python `len` on `str`), with no
   `\n`, `\r` or `\0`.
2. **Two regex shapes are matched before tokenising**: `_TAR_RE` and
   `_CAT_TO_FILE_RE` (`guard.py:44-45, 457-476`). Python's `\S` excludes
   `\x1c-\x1f`; Rust's Unicode `\S` does not. The prefilter in 4.1 removes
   the difference.
3. **Tokenising** is `shlex.split(command)`: POSIX mode, `comments=False`,
   whitespace `" \t\r\n"`, quotes `'` and `"`, and `\` escapes outside quotes
   and, inside `"`, only before `"` and `\`. `''` gives an empty token, and
   adjacent quoted parts concatenate. An unterminated quote or a trailing
   escape is refused (`guard.py:478-481`). Checked in the Ubuntu 24.04
   container (`a "b c"d` → `['a', 'b cd']`, `systemctl stop gotosocial #x` →
   four tokens). Implementation decision in 5.2.
4. **The trailing `< file`** is split off only for `runuser`
   (`guard.py:483-487`).
5. **Python's `$` quirk.** `re.match(r"^…$")` also matches before a final
   `\n`. That only matters for policy values, since commands cannot contain
   `\n`. A Python policy accepts e.g. a unit `"x.service\n"`, which can never
   match a command. Rust anchors at the real end. This is P3 (4.2).
6. **`os.path.realpath`** (non-strict) decides "inside a root"
   (`guard.py:224-238`). Behaviour to keep:
   - symlinks are resolved component by component, also when they dangle
     (their target text is followed);
   - missing components (`lstat` gives `ENOENT`, or `ENOTDIR` below a
     non-directory) are appended literally;
   - `..` in a link target is applied to the resolved path.
   Python 3.12 (production) and 3.13 (staging) implement it differently, and
   symlink loops are where they can diverge. Section 4.2 makes loops, and the
   lookup errors Python skips over, a refusal. The guard only ever resolves
   paths that `_is_safe_path` accepts (absolute, no `.`, `..` or empty
   component except trailing `/`), so the port resolves absolute paths only.
   S2 ports CPython 3.13's algorithm (`pyrealpath.rs`) and checks it against
   both versions (7.3, 7.5).
7. **`lstat`**: `ENOENT` means absent. Any other `OSError` refuses with
   `<what> not checkable` (`guard.py:241-247`).
8. **User and UID lookups.**
   - `_user_uids` resolves names with `getpwnam` (NSS). By default it also
     includes the guard's own euid; `include_self=False` leaves it out.
     `guard.py:622-629`.
   - Plain-file checks: a regular file with exactly one link; an `owner`,
     when given, must match its uid (`guard.py:250-262`).
   - A private directory is a directory owned by the euid with mode
     `& 0o077 == 0` (`guard.py:265-275`).
   - The Rust port uses the same NSS path (glibc `getpwnam_r`; see 8.2).
9. **`shlex.quote` of a private media path** (`guard.py:286-294`). The
   probe script the guard compares against is built with `shlex.quote`.
   Policy paths are safe paths and come back unchanged. The Rust port asserts
   this instead of re-implementing `quote`.

### 3.4 The allowlist (P1, decision for decision)

Every branch of `check()` (`guard.py:452-619`) and its helpers
`_check_postgres` (297-368), `_check_sqlite` (371-390), `_check_scp`
(393-420), `_check_rsync` (423-432) and `_check_chown` (435-449) is ported one
to one, **in the same order of checks** so that the refusal reasons match
(4.4). The output of a decision is the `Decision`:

- `argv`;
- `umask` (`None` or `0o077`);
- `stdin` and `stdout`, each a `Redirect` (`directory`, `name`, `owners`)
  or none.

Two families of decision:

- **Run-as wrappers** in `argv`:
  - `sudo` → `sudo -n -u postgres -- …` (`guard.py:492`);
  - uploads (`scp -t`, rsync receiver) and `mkdir -p` run as
    `runuser -u <owner> -- …` (`guard.py:512, 516, 603`);
  - restore dumps run as `postgres`.
- **Redirections**: `cat >` (create), the `pg_restore … <` file and the
  snapshot `cat` (read).

The shapes the runners send today (journal, last 24 hours) all appear in
the fixture corpus:

- `sudo -u postgres pg_dump/dropdb/createdb/pg_restore/psql`;
- `runuser -u postgres -- pg_dump/psql/createdb/pg_restore <`;
- `runuser -u gotosocial -- sqlite3 … '.backup …'` and `'PRAGMA integrity_check;'`;
- `systemctl show/start/stop`;
- `scp -f/-t`;
- the three rsync server forms;
- `test`, `readlink`, `mktemp -d`, `chown`, `cat`, `rm -f`, `rm -rf --`,
  `du -sb --`, `sh -c '<probe>'`, `umask 077 && tar …` and `umask 077 && cat >`.

The repo version adds the 4-argument `sqlite3 <db> ".timeout <ms>"
".backup '<snap>'"` (`guard.py:69, 374-377`, ops-library `6c7693e`/`a6ed074e`).
This is **mandatory** in the port, even though production does not run it
yet (6.4). Its tests are `tests/test_sqlite_backup_runners.py`, the
`.timeout` cases in `tests/test_echoport_remote_command_guard.py`
(GoToSocial) and the molecule scenario.

`RSYNC_SERVER_ARGS` (`guard.py:54-61`) is copied verbatim. An rsync version
that sends other strings must fail closed in both guards.

### 3.5 Execution side effects (P1)

Measured or read from `guard.py:632-651, 696-717`; the process-level probes in
S4/S5 enforce each item.

- Redirect open (`guard.py:632-651`):
  - open the directory with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`;
  - check its owner with `fstat`: the euid or one of the `owners` uids;
  - check that `mode & 0o077 == 0`;
  - open the file with `openat`. Create:
    `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600` (after the umask).
    Read: `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, then clear `O_NONBLOCK`;
  - `fstat` the file: it must be regular with `nlink == 1`;
  - `dup2` onto fd 0 or 1.
  All fds are close-on-exec (Python's default), so only 0/1/2 reach the
  command, plus whatever sshd passed. If the open returns the target number
  itself (sshd started the guard with fd 0 or 1 closed), the Rust guard
  only clears its close-on-exec flag; Python's `dup2(fd, fd)` plus `close`
  would leave it closed. sshd always passes 0/1/2, so this is not reached;
  besides, Rust std opens `/dev/null` on a closed fd 0, 1 or 2 at startup,
  where CPython leaves it closed (also unreachable under sshd).
  - The `OSError` text in the `refused from` line is Python's `str(exc)`:
    `[Errno <n>] <strerror>: <repr(filename)>` (the directory for its open,
    the name for the `openat`), with the C library's `strerror`.
- `umask(0o077)` is set before the redirects are opened for the
  `umask 077 && …` shapes. Otherwise the umask is inherited.
- Environment: inherited unchanged except `PATH = SAFE_PATH`.
  **Measured:** with no locale variables set, CPython's PEP 538 coercion
  exports `LC_CTYPE=C.UTF-8` into the exec'd command's environment (`env -i
  python3 -I … execvp env` prints `LC_CTYPE=C.UTF-8`). With `LANG=C.UTF-8`
  set it adds nothing. The Rust guard reproduces the coercion rule of the
  hosts' CPython (3.12/3.13 `_Py_CoerceLegacyLocale`: when `LC_ALL` is unset
  or empty and the `LC_CTYPE` locale is `C`/`POSIX`, set `LC_CTYPE` to the
  first of `C.UTF-8`, `C.utf8`, `UTF-8` that `setlocale` accepts and whose
  `nl_langinfo(CODESET)` is not empty). S4 checked this against
  `Python/pylifecycle.c` and `Python/preconfig.c` of 3.12 and 3.13 (the same
  code; `-I` ignores `PYTHONCOERCECLOCALE`), and `tests/flow.rs` compares
  the exported `LC_CTYPE` with CPython 3.12.3 (Ubuntu 24.04) and 3.13.5
  (Debian 13) for nine environments.
- Signal dispositions: CPython ignores **SIGPIPE and SIGXFSZ**, and
  `execvp` keeps them ignored. **Measured:** `SigIgn: 0000000001001000` in
  the exec'd command against `0` from a shell. So `cat`, `tar`, `pg_dump` and
  scp get `EPIPE` instead of being killed. The Rust guard adds exactly
  these two to the ignored set it inherited, as CPython does (S4 sets both
  explicitly; Rust std also ignores SIGPIPE). Found by S4: glibc 2.37+'s
  `posix_spawn` (which Rust's `Command` uses) leaves glibc's internal
  signals 32 and 33 ignored in the child; sshd forks and execs, so the hosts
  are not affected, and the S4 test compares with what the guard inherited.
- `exec` follows **CPython's `os.execvp`** (`os._execvpe`), which is **not**
  libc `execvp`:
  - When `argv[0]` contains `/`, it is a single `execv`.
  - Otherwise it calls `execv(<dir>/<argv0>, argv)` for each directory of
    `PATH`. By then `PATH` is `SAFE_PATH` in the process environment, which
    `execv` passes on.
  - `ENOENT`/`ENOTDIR` record the last error and move on. Any other error
    (`EACCES`, `ENOEXEC`, …) is remembered if it is the first such error,
    and the search moves on.
  - At the end it reports the first remembered error, else the last one.
  - **No `/bin/sh` fallback on `ENOEXEC`.** glibc's `execvp` runs an
    executable text file without a `#!` line through `/bin/sh`, and it also
    treats `EACCES` differently. So the port implements this loop itself
    over `nix::unistd::execv`; it never calls libc `execvp`/`execvpe`.
  - Tests (S4 and Layer 3), with expectations taken from CPython and the
    same for both guards:
    - A shebang-less executable that is the **only** candidate in
      `SAFE_PATH` exits 127 with the `ENOEXEC` message ("Exec format
      error") and is never run by a shell.
    - A shebang-less executable or a non-executable (`EACCES`) entry
      **followed by** a valid executable in a later `SAFE_PATH` directory:
      the later executable runs. The search goes on after those errors.
    - A directory named like the tool and nothing else: 127 with `EACCES`.
    - A missing tool: 127 with `ENOENT`.
    Exit 127 is reserved for searches that find no executable candidate.

### 3.6 Logging (P1 for identifier, facility, priorities and message prefixes; P2/P3 for the repr text)

- `openlog("echoport-remote-command-guard", LOG_PID, LOG_AUTH)`, then
  `syslog(priority, "%s", message[:1000])`. The priorities are WARNING for a
  refusal or an interactive session, ERR for a policy error and INFO for an
  allowed command. OS errors while logging are ignored (`guard.py:654-659`).
  The port calls libc `openlog`/`syslog` exactly like CPython's `syslog`
  module (glibc, `/dev/log`, journald). It does not use a syslog client
  crate, which would change the identifier and PID formatting.
- `<repr(command)>` and the `{path!r}` parts of the reasons are Python
  `repr`. This matters for operators (`journalctl -t
  echoport-remote-command-guard`) and as protection against log injection:
  control characters are escaped. P1 for printable ASCII and tab, which is
  everything the runners send. The rule for the rest is in 4.3.
- Consumers found: the ops-control docs (`FASTDEPLOY_PRIVILEGES.md`,
  `ROOT_SSH_KEY_ROLLOUT.md`, `marina-staging-backup.md`) and the playbook
  stderr probe. No alert or parser reads the log lines.

Modes a client cannot reach. They are additions: argv is fixed by the
`command=` option, so a client cannot select them.

- `--version`: prints `echoport-command-guard <ver> (<commit>)` and exits 0.
  The release smoke test and the role use it.
- `--decide <policy>`: reads `SSH_ORIGINAL_COMMAND` and prints the decision
  as JSON on stdout. It never opens redirects, never logs and never execs.
  It is used by the parity harness (Layer 2) and later by the runner-shape
  tests (S13). One JSON line; verdicts `allowed` (`argv`, `umask`,
  `stdin`, `stdout`, the fixtures' form), `refused` (`reason`),
  `interactive`, `policy-error` (`error_type`, `message`) and `panic`
  (`reason`). Exit 0 for `allowed`, else 1.
- `--shadow <policy> <python> -I <pyguard> <policy>`:
  - computes the Rust decision (`check()` only; no redirect open, no umask
    change, no exec of the target);
  - logs it under the identifier `echoport-remote-command-guard-shadow` as
    one JSON object (`verdict`, `argv`, `umask`, redirects, `reason`);
  - then **always** `execv`s the given Python guard with the original
    environment. A panic is caught (`catch_unwind`; the crate keeps
    `panic = "unwind"`), logged and the exec still happens.
  - The tail must be exactly an absolute interpreter, `-I`, an absolute
    guard path and the same policy path. Anything else exits 2 without exec.
  - The record is the `--decide` JSON at priority INFO, not cut at 1000
    characters (it must stay valid JSON). It covers `check()` only, so a
    redirect that fails to open later is `allowed` in the shadow line and
    refused in the Python line; the S8 compare script must allow for that.
  - If the `execv` of the Python guard fails: `cannot run <python>:
    <strerror>` and exit 127; nothing else runs.
  - Because the PID survives `execv`, the Rust shadow line and the Python
    line pair up by `_PID`.

---

## 4. Allowed differences (P3, exhaustive) and non-goals

Every allowed difference is a **stricter refusal** or affects only log
text. Nothing the Python guard refuses may be accepted. The differential
tests (7.3) enforce this invariant: *if Rust accepts, Python accepts with an
identical `Decision`*.

### 4.1 Command prefilter (decided, Q2)

Right after Python's own pre-checks (3.3.1, same order and reasons; the
length is counted in characters of the decoded string), the Rust guard
refuses a command that:

- is not valid UTF-8 (Python's check counts `surrogateescape` characters;
  Rust counts decoded characters, or bytes when the string is invalid);
- contains a character outside printable ASCII (0x20–0x7e) and tab;
- contains `\` or `#`.

The refusal reason is `non-ASCII or control characters in command` or
`unsupported character in command`.

Justification:

- Every command Python accepts consists of printable ASCII and tab, except
  for Python accepting commands with backslash escapes such as `systemctl
  start marina\.service`. Every accepted token ends up compared with an
  ASCII-validated policy value or an ASCII regex. S0 proves this with a
  property test against the Python guard.
- No runner sends `\` or `#`. The corpus check is in S0, and the runners use
  `shlex.join`/`shlex.quote` (single quotes, `'"'"'`).
- With the prefilter, the `shlex` crate and Python's `shlex.split` agree
  (5.2), and the `\S` difference (3.3.2) cannot arise.

### 4.2 Other stricter refusals (decided, Q2)

- **Policy types.** Values must have the JSON type the role writes: lists of
  strings, an object of strings, objects with string fields, or `null` for
  empty. Python accepts and coerces some other inputs:
  - a string where a list is expected (`set("abc")`);
  - numbers through `str()`;
  - `false`, `0` or `""` as empty;
  - a list of pairs as `restore_databases`;
  - duplicate keys (last one wins).
  Rust refuses these. Every policy the role produces (YAML → `to_nice_json`)
  is accepted by both. S9 runs the Rust `--check-policy` on both live
  policies before anything switches.
- **Trailing `\n` in policy values** is refused (3.3.5).
- **realpath errors.** While resolving, these refuse with `path not
  checkable: <path!r>: <strerror>`:
  - a symlink loop, where Python returns a partly resolved path (which
    differs between 3.12 and 3.13), and more than 40 symlink traversals
    (Linux's `MAXSYMLINKS`; the kernel itself refuses to open such a path),
    which Python resolves. They are counted as the kernel counts them: a
    link Python answers from its `seen` map costs every traversal of its
    first resolution again (`<dir>/a/a/…` with `a -> .` and 41 `a`s);
  - an `lstat` error other than `ENOENT`/`ENOTDIR`, for example
    `ENAMETOOLONG` or `EACCES`, where Python treats the component as "not a
    link" and appends it unchecked;
  - a `readlink` error (Python 3.12 raises it, 3.13 appends the link
    literally) and a link target that is not valid UTF-8 (Python carries the
    bytes as surrogates).
  None of these occur on the hosts' policy paths; S2's Layer-2 harness
  exercises each of them (7.5).
- **Invalid UTF-8 in `SSH_ORIGINAL_COMMAND`.** Python decodes it with
  `surrogateescape` and refuses later. Rust refuses right after Python's
  pre-checks (counted in bytes, 4.1) with the same `refused from` log line,
  using the reason `non-ASCII or control characters in command`.
- **Non-standard JSON in the policy** (found by S0, S1): Python's `json`
  accepts `NaN`, `Infinity`, lone surrogate escapes such as `"\ud800"` and
  numbers outside the double range such as `1e400` (as `inf`, or as an
  unbounded int) and documents nested deeper than 127 arrays and objects
  (top level included; `serde_json`'s recursion limit), also under unknown
  keys, and keeps the last of duplicate keys anywhere in the document. Rust
  refuses these (`serde_json` refuses all but the duplicates as malformed
  JSON, the strict tree of 5.2 the duplicates as a type error); the fixtures
  tag them `policy-type`.
- **Python crashes in `check()`** (found by S0). The `umask 077 && tar …`
  shape matches `_TAR_RE` on the raw string and then calls `shlex.split` on
  the group without a guard (`guard.py:459`), so an unbalanced quote or a
  trailing `\` in it raises `ValueError`. `main()` does not catch that: the
  Python guard exits 1 with a traceback on stderr, logs nothing and runs
  nothing. Rust refuses such a command like any other (`refused from` log
  line, `command not allowed`, exit 1). The fixtures record these cases with
  the verdict `error`.

### 4.3 Log text (P2)

- `repr` is reproduced exactly for printable ASCII and tab: the choice of
  quote character, `\\`, `\'` and `\t`.
- Other characters only appear in refused commands. Rust escapes all of them:
  - bytes 0x00–0x1f and 0x7f as `\xNN` (as Python does);
  - non-ASCII as `\xNN`/`\uNNNN`/`\UNNNNNNNN`, where Python prints printable
    non-ASCII literally;
  - undecodable bytes as `\udcNN` (as Python's `surrogateescape` repr).
  This is stricter against log injection.
- `<ExcType>` in `policy error (...)` uses Python's names where there is a
  counterpart: `FileNotFoundError`, `PermissionError`, `IsADirectoryError`,
  `JSONDecodeError`, `UnicodeDecodeError`, `KeyError`, `TypeError`,
  `Refused`. Otherwise `OSError`.
- The detail after `invalid policy:` and after `cannot run <argv0>:` may
  differ in wording. Ansible's `validate` only looks at the exit code.

### 4.4 Refusal reasons (P1 with listed exceptions)

The reason inside `refused from <client>: <reason>: …` must equal Python's
for every Layer-1 fixture, except:

- commands caught by the prefilter (4.1), and invalid UTF-8 (4.2);
- the policy-type, trailing-`\n` and realpath refusals (4.2);
- the `check()` crashes (4.2).

The generator tags every Layer-1 case that falls into one of these classes
with `p3` (`prefilter`, `invalid-utf8`, `python-error`, `policy-type`,
`policy-trailing-newline`). For a tagged case the Rust guard may refuse where
Python accepts and may give another reason or error type, but it must never
accept what Python refuses. Any other exception is listed by case id in
`parity/allowed_differences.json` (empty at S0). S5 reviews each tag class
and each entry.

### 4.5 Non-goals

- No new command shapes, no policy schema changes, no change to what any
  runner sends. A new runner shape goes into the Python guard first until S12,
  and from S13 into the Rust guard only.
- No change to `authorized_keys` options other than `command=`. `from=`,
  `restrict` and the key stay.
- No move of `authorize-root-ssh.yml` to pyinfra.
- No change to the opsgate keys, `authorize-opsgate-root-ssh.yml`, graphyard
  or the ingest tokens.
- The TOCTOU windows Python documents as accepted (downloads as root
  re-open their path after the check; README "Files the guard opens itself")
  stay as they are. The port neither widens nor narrows them.
- No musl build (8.2). No aarch64 build. No packaging for macmini.

---

## 5. Design

### 5.1 Crate layout

```
rust/echoport-command-guard/
  Cargo.toml            # [[bin]] echoport-command-guard; lib for tests
  PLAN.md  TESTMAP.md  README.md
  src/main.rs           # argv grammar (3.1), exit codes; the binary's GuardEnv until S2
  src/modes.rs          # forced-command flow, --decide, --shadow over an injectable Host (S4)
  src/policy.rs         # strict JSON tree, typed policy, validation (3.2, 4.2)
  src/prefilter.rs      # 4.1
  src/tokens.rs         # shlex crate wrapper + _TAR_RE/_CAT_TO_FILE_RE
  src/env.rs            # trait GuardEnv { euid, uid_of, lstat, realpath }; virtual impl (S1), real impl (S2)
  src/pyrealpath.rs     # non-strict realpath over trait ResolveFs { lstat, readlink } (3.3.6, S2)
  src/rules/{mod,postgres,sqlite,transfer,files}.rs   # check() port (3.4)
  src/rules/paths.rs    # realpath/lstat/uid helpers of check() (3.3.6-3.3.8, S2)
  src/decision.rs       # Decision/Redirect + JSON for --decide/--shadow
  src/redirect.rs       # openat/fstat/dup2 (3.5)
  src/exec.rs           # umask, PATH, locale coercion, signals, execvp
  src/repr.rs           # py_repr (4.3), used by refusal reasons and log lines
  src/syslog.rs         # openlog/syslog through nix's libc wrapper (3.6)
  parity/gen_fixtures.py  parity/oracle.py  parity/allowed_differences.json
  parity/e2e/           # Dockerfiles + scripts for Layers 2 and 3
  examples/env-probe.rs # the real GuardEnv as JSON lines, for Layer 2 (S2)
  fixtures/             # generated, committed (7.2)
  fuzz/                 # cargo-fuzz targets (not a workspace member)
```

The modes in `modes.rs` take a `Host` (the `GuardEnv`, a `Logger`, the
`check` function and the exec search path), so `tests/flow.rs` runs the
real flow in a child process with a stub `check()`, a test search path and
a log file (S4). `main.rs` passes the real ones (`SAFE_PATH`, syslog).

`check()` takes `&dyn GuardEnv`, so the Layer-1 fixtures run against a
virtual filesystem and user table, the way the Python tests inject `realpath`
and `lstat`: the virtual impl answers `realpath` from the case's recorded
map (default `normpath`). Production uses the real implementation
(`RealEnv`), whose `realpath` is `pyrealpath.rs` over `lstat`/`readlink`
(5.2: the crate was evaluated and rejected in S2).

### 5.2 Crate choices

| Need | Choice | Why |
|---|---|---|
| Tokenising | `shlex` (comex), behind the 4.1 prefilter | A maintained crate. With `\` and `#` refused and only printable ASCII and tab left, its POSIX splitting equals Python's `shlex.split` (no comments, no escapes, literal quotes). The differential test in S1 is the proof; any disagreement blocks S1. |
| Regexes | `regex-lite` | Only ASCII classes are needed after the prefilter. Smaller than `regex`. |
| JSON policy | `serde` + `serde_json` into a strict JSON tree (a `Deserialize` visitor that refuses duplicate keys anywhere), then a typed conversion in `Policy.from_dict`'s order | Strict types (4.2); a missing entry key is a `KeyError` and a wrong type a `TypeError` in Python's order, which typed `serde` structs cannot give. Unknown keys are ignored (3.2). |
| Syscalls (`openat`, `fstat`, `fcntl`, `dup2`, `umask`, `execvp`, `getpwnam_r`, `geteuid`, `sigaction`) | `nix` | Maintained. One crate covers everything. `lstat` and `readlink` are std's `symlink_metadata` and `read_link` (S2). |
| syslog | `nix::syslog` (`openlog`, `syslog(priority, "%s", msg)`) | Parity with CPython, which calls the same libc functions (3.6). nix's wrapper is exactly these two calls, so no `unsafe` of our own (S4). |
| `setlocale`, `nl_langinfo` | `libc` (thin `unsafe` calls in `exec.rs`) | PEP 538 parity (3.5); nix has no wrapper. |
| `strerror` texts | std's `io::Error` (glibc `strerror_r`) | `nix::Errno::desc` is nix's own table and differs from glibc for some codes (`EBADF`: "Bad file number"). |
| Non-strict realpath | own `pyrealpath.rs`, about 70 lines, a port of CPython 3.13's `posixpath.realpath` over `ResolveFs` (`lstat`, `readlink`) | `std::fs::canonicalize` is strict (it fails on missing paths and dangling links). **Decided in S2 (Q3):** `soft-canonicalize` 0.5.6 was run through the Layer-2 harness (7.5) on Ubuntu 24.04 against Python 3.12.3, on the same 1,531 safe-path probes (31 curated, 1,500 in 300 random trees). It differed on 265: it does not follow dangling links, it keeps a trailing `/` and resolves `..` in link targets differently, it resolves a loop through `..` and the `ENAMETOOLONG`, `EACCES` and non-UTF-8 cases instead of refusing them, and 49 of its results lie inside the probe's tree where Python's lie outside (acceptance drift). `pyrealpath.rs` matched Python 3.12.3 and 3.13.5 on every probe, apart from the 4.2 refusals. |
| Tests | `proptest`, `tempfile`, `serde_json` | |
| Fuzzing | `cargo-fuzz` (nightly, outside the workspace) | Section 7.4. |

No async runtime, no TLS, no CLI parser, no logging framework.

### 5.3 Fail-closed rules for implementers

- Unknown tools, and branches not yet ported, return `Refused("command not
  allowed: <tool>")`. The dispatcher stub of S1 refuses everything.
- No `unwrap()`/`expect()` on input-derived data, which clippy enforces with
  `#![deny(clippy::unwrap_used, clippy::expect_used)]` outside tests. Indexing
  into token slices happens only after the length checks that `guard.py`
  makes at the same point.
- In forced-command mode any internal error refuses (exit 1) and never execs.
  A panic never results in an exec.
- `unsafe` appears only in `exec.rs` (libc `setlocale`/`nl_langinfo`,
  `set_var` and `sigaction` right before the exec, in the single-threaded
  guard), each block with a `// SAFETY:` comment and an
  `#[allow(unsafe_code)]` on its function. The crate's `[lints]` copy the
  workspace lints with `unsafe_code = "deny"` instead of `forbid` (which
  no `allow` can lift); everything else stays as in `[workspace.lints]`.

---

## 6. Deployment and rollout

### 6.1 Rules for every production step

- Every production step goes through ops-control's existing entry point,
  `just pin-deploy-backup-key <host>` (positional: `staging` or
  `production`), or the playbook it wraps, run directly. The direct form is
  used for previews and for the rollback with `-e` (6.5). There is no new
  deploy mechanism. The direct form, from the ops-control checkout, with the
  same environment as the recipe:
  ```bash
  SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt \
    ansible-playbook -i inventories/prod/hosts.yml playbooks/authorize-root-ssh.yml \
    --limit <host> [--check --diff] [-e …]
  ```
  The recipe cannot pass `--check --diff` or `-e`. In check mode the
  playbook's `shell` probes are skipped, so a preview never touches the
  guard.
- **Deploy lock.** Before every production step:
  ```bash
  mkdir /tmp/ops-control-deploy.lock \
    && printf '%s %s %s\n' "<session>" "rust-echoport-command-guard <slice>" "$(date -Is)" \
       > /tmp/ops-control-deploy.lock/owner
  ```
  If `mkdir` fails, wait and retry. Never remove a lock you did not create.
  Release with `rm /tmp/ops-control-deploy.lock/owner && rmdir
  /tmp/ops-control-deploy.lock` right after the step.
- Before each real run, run the direct form above with `--check --diff`
  under the lock. Expected change: **only** the deploy key line's `command=` and
  the guard's files. `authorize-root-ssh.yml` also applies the current
  operator key declarations. If the diff shows anything else, stop and ask
  the coordinator.
- Each step needs `just install-local-library` with an ops-library at or
  after the release containing S6. The playbook's minimum version is raised
  in S8. Workers never bump `galaxy.yml`: the coordinator makes the
  collection release commit (`galaxy.yml` bump plus the CHANGELOG heading) on
  ops-library `main` right before the first production step that needs it
  (owner decision 2026-10-21, section 9).
- **Scheduling (Q1).** This stream is scheduled last in the campaign. Its
  production steps (S9, S10a, S10b, S11a, S11b, S12) never run alongside
  another production or staging change: each step starts only when the
  coordinator has confirmed in the go that no other change on production or
  staging is in flight or scheduled for the step and its acceptance, and the
  production chain starts only after the other streams' production and
  staging cutovers of this campaign are done or the coordinator releases it
  explicitly. During the shadow and soak windows, another change on
  production or staging needs the coordinator's explicit go and is noted in
  the deployment record, because it can confound the evidence. The
  non-production slices S0–S8 change nothing on a host and may run earlier
  when the coordinator has capacity.
- Secrets: the role handles none. Nothing sets `environment:` under
  `become_user` (ops-control `test-become-environment-secrets`, ops-library
  `tests/test_become_environment_secrets.py` ≥ 2.55.0).
- No cutover during an Echoport run on the host. The schedules are in
  Echoport, and the runs cluster between 00:00 and 05:00. Check the
  "running" list before switching. Each SSH command is its own session, so a
  run that sees both guards still works, but a quiet window keeps the
  evidence clean.
- Production cutover and production shadow need the coordinator's go: the
  Traefik ACME move on production runs until 2026-10-30, and MinIO work is
  announced separately.

### 6.2 Role changes (S6)

New defaults in `roles/echoport_remote_command_guard/defaults/main.yml`:

```yaml
# python | shadow | rust. python: today's forced command, byte for byte.
# shadow: the Rust guard logs its decision, then execs the Python guard,
# which decides. rust: the Rust guard decides.
echoport_remote_command_guard_impl: python
echoport_remote_command_guard_rust_version: ""        # e.g. "0.1.0"; a set version is installed even with impl python
echoport_remote_command_guard_rust_sha256: ""         # archive sha256 (64 hex)
echoport_remote_command_guard_rust_local_archive: ""  # dev/molecule only
echoport_remote_command_guard_rust_install_root: /usr/local/lib/echoport-command-guard
echoport_remote_command_guard_rust_keep_versions: 3
```

The tasks:

- **Assert** that `impl` is one of the three values, and that `shadow`/`rust`
  require a version with a sha256 or a local archive.
- **Python guard:** always installed as today (copy, `0755`, validate) until
  S12. It is the rollback target, and it is what `shadow` execs.
- **Rust binary:** installed through F3's role `rust_release_binary`
  (`tasks_from: install`, with `install_root` set to this role's
  `rust_install_root`, and `fail_hard` true only for impl `shadow`/`rust`,
  per the rollback-independence rule below). The binary goes to
  `<install_root>/<version>/echoport-command-guard`. The install root, the
  version directory and the binary are root:root, directories `0755` and the
  binary `0755`. No component of the path may be group- or world-writable;
  the role asserts this with `stat` on every component up to `/`, because
  sshd runs this file as root.
  - After installing, run `<bin> --version` (it must print the pinned
    version) and `<bin> --check-policy <rendered policy>`.
  - **No pin and no prune in the main tasks.** When the role's main tasks
    run, the playbook has not yet written the new `authorized_keys` line,
    so the forced command may still name an older version, and the play can
    still stop before the line is written. So the main tasks install and
    check the target version but never move a pin and never prune.
    Installing never deletes a version.
  - **Rollback independence.** With `impl: python`, every Rust step is
    best-effort: download, install, `--version`, `--check-policy`, and in
    `confirm_live.yml` the pin and prune steps run, but their failures only
    warn (`failed_when: false`, an explicit warning, and a registered result
    the slice evidence records).
    They are fatal only for `impl: shadow` and `impl: rust`, and then
    *before* the fact is set. So a broken, missing or unrunnable Rust binary
    or release can never block a switch back to Python. S6 has a molecule
    case for this: a broken archive or a binary that exits 1, with impl
    `python`, must converge and leave the Python forced command.
- **Policy `validate`:** the Python guard always validates (fatal, as
  today). If a Rust binary is installed, a separate `command` task also runs
  the Rust `--check-policy` on the rendered file. The copy task takes only
  one `validate`, so the Rust check is its own task. It is fatal under the
  same rule as above. This shows divergence on the hosts' own policy before
  any switch.
- **The fact `echoport_remote_command_guard_forced_command`:**
  - `python`: unchanged, `{{ python }} -I {{ path }} {{ policy_path }}`. It
    is byte-identical, so `ssh_authorized_keys_manage` reports no change.
  - `shadow`: `<bin> --shadow <policy> <python> -I <pyguard> <policy>`.
  - `rust`: `<bin> <policy>`.
  All parts are safe paths (asserted), so no quoting is needed inside
  `command="…"`.
- **Pin and prune after the line is verified live:** new
  `tasks_from: confirm_live.yml`, which the playbook includes after its
  fatal post-probe (6.3). The mechanism is F3's (`rust/PLAN-foundation.md`,
  F3, owner requirement of 2026-10-21, section 9): `prune` never deletes a
  version in its explicit `protect` list, which the consumer fills from the
  live state, and never deletes a version named by a pin, including the
  consumer's separate "previous" rollback pin, which moves only when the
  consumer pins a new version that it verified live. This role's duties as
  the consumer, in this order:
  1. **Verify live.** Read root's `authorized_keys`, the file the playbook
     has just written, and assert that the deploy key's line carries exactly
     the `command="…"` of the fact
     `echoport_remote_command_guard_forced_command`. Together with the
     playbook's fatal post-probe through that line, this is the "verified
     live" condition. For impl `shadow`/`rust`, `<bin> --version` must also
     print the target version. A mismatch in the line is fatal for every
     impl (it checks what the playbook wrote, not the Rust binary), and none
     of the steps below run.
  2. **Protect list from the live state.** Every version that any line of
     that `authorized_keys` names as
     `<install_root>/<version>/echoport-command-guard` (the deploy key line
     and any other line, for example a manual edit from the runbook), plus
     the configured `rust_version` (installed for a quick switch even with
     impl `python`). If a line mentions `<install_root>` in any other form,
     or the file cannot be read or parsed, the live state is unknown: the
     role skips prune with a warning and never deletes on doubt. The parsing
     is a small filter with its own unit test (S6).
  3. **Move the pins, only now.** impl `shadow`/`rust`: F3 `pin` for the
     consumer `echoport_remote_command_guard` with the target version; if
     the current pin named another version, F3 moves that version to the
     previous pin. impl `python`: F3 removes the current pin and keeps its
     version as the previous pin, so the last Rust version verified live
     stays on disk for a quick switch back. If F3's `pin` cannot keep a
     removed version as the previous pin, S6 leaves the current pin as it is
     for impl `python` instead (R9).
  4. **Prune** with F3's `prune`, `keep_versions` and the `protect` list of
     step 2.

  A play that stops anywhere before step 3 (the role, the write of the
  line, the post-probe, or step 1 or 2) moves no pin and prunes nothing, so
  the current pin keeps naming the last version verified live and the
  version the forced command names is never pruned. Example: the
  `authorized_keys` line names A and the current pin is A; deploys
  targeting B and then C stop after the role, before the line is written;
  the pins stay A and nothing is pruned. A deploy targeting D whose line is
  written and verified pins D, moves A to the previous pin, and prunes with
  `protect` [D]: A, D and the newest versions by mtime stay. If D's write
  or post-probe fails instead, nothing is pruned and A stays. In check mode
  `confirm_live.yml` only reports what it would do. Under the
  rollback-independence rule above, the `--version` check of step 1 and
  steps 3 and 4 only warn with impl `python`.
- **Molecule:** the existing scenario becomes impl × platform: `python`,
  `shadow` and `rust` on Ubuntu 24.04 and Debian 13 (new platform). The
  `rust` and `shadow` runs use `rust_local_archive` built from the branch.
  The existing verify (allowed and refused commands through a real sshd,
  classic scp, the three rsync forms, SFTP refused, interactive refused) runs
  unchanged for all three. The shadow run also checks that one journal line
  with each identifier carries the same `_PID`.
- **Pin and prune tests (S6)**, a molecule scenario `pins` on Ubuntu 24.04
  with a real sshd and impl `shadow`. Each version is a local stub archive:
  a script that answers `--version` and `--check-policy` and, called as
  `--shadow <policy> <argv…>`, execs the given Python guard command, so
  every guarded SSH command still goes through the real Python guard. The
  scenario runs the role's main tasks, the line write (as the playbook
  does) and `confirm_live.yml` separately, so a failed play can be cut at
  any point. Cases:
  - **Repeated failed deployments with different targets.** A is written
    and confirmed (current pin A). Then runs targeting B, C and D each stop
    after the role's main tasks (no write, no `confirm_live.yml`). After
    each run: A–D are on disk, the pins are unchanged (current A, no
    previous), the line still names A, and an allowed guarded command
    succeeds through sshd. Then a run targeting E is written and
    confirmed: current pin E, previous pin A, and with `keep_versions` 3
    the prune keeps E, D, C (newest by mtime) and A (previous pin) and
    removes only B; the allowed command succeeds through E.
  - **Stale line.** A run targeting F stops after the role, then
    `confirm_live.yml` runs with F's fact while the line still names E: it
    fails, no pin moves, nothing is pruned.
  - **Written but not verified.** F's line is written but the post-probe
    is made to fail (stub F refuses everything); the play stops before
    `confirm_live.yml`: no pin moves, nothing is pruned. The next run back
    to E is confirmed; F is not pinned.
  - **Protect from the live state alone.** The pin files are removed and a
    second, manual `authorized_keys` line names an unpinned version X,
    installed first in the scenario and so the oldest by mtime; a confirmed
    run keeps X. A line that
    mentions the install root in another form makes the role skip prune
    with a warning and delete nothing.
  - **Switch to Python verified.** impl `python` is written and confirmed:
    the current pin is removed, the previous pin names the last Rust
    version, and that version is still on disk after the prune.
  - **Check mode:** `confirm_live.yml` moves no pin and prunes nothing.
  The filter that parses the versions from `authorized_keys` has a unit
  test (Python, Rust and shadow lines, several lines with different
  versions, an install-root mention in another form, an unreadable file).
- **Docs:** role README (impl selector, switch, rollback, shadow),
  `docs/source/roles/infrastructure/echoport_remote_command_guard.md`, and a
  CHANGELOG entry under "Unreleased". `galaxy.yml` is not bumped.

### 6.3 ops-control changes (S8)

- `inventories/prod/group_vars/all.yml`:
  `echoport_remote_command_guard_rust_version` and `_sha256` (one pin for
  both hosts). host_vars `production.yml` and `staging.yml`:
  `echoport_remote_command_guard_impl: python` at first.
- `playbooks/authorize-root-ssh.yml`:
  - Raise the minimum ops-library version to the release containing S6.
  - The post-probe stays as it is: every impl prints the same
    interactive-session text.
  - After the post-probe, `include_role` of
    `local.ops_library.echoport_remote_command_guard` with
    `tasks_from: confirm_live.yml` (6.2): the only place where the guard's
    pins move and old Rust versions are pruned. A test pins its position
    (after the post-probe, nothing between that could prune) and that it
    runs for every impl, the rollback included.
  - One change for rollback. Today's **pre**-probe (the route check before
    the guard role, `failed_when` at l.155–157) goes through the *currently
    installed* forced command. If that is a broken Rust binary, the probe
    fails and the playbook stops before it can write the Python command
    back.
  - S8 adds a variable `deploy_backup_route_probe_fatal`, default `true`.
    The rollback passes `-e deploy_backup_route_probe_fatal=false`. The
    probe then still runs and its output is printed, but a failure no
    longer stops the play.
  - The **post**-probe, after `authorized_keys` is written, stays fatal, so
    the rollback is still verified against the Python guard.
  - A test in `tests/test_echoport_remote_command_guard_policy.py` (or the
    root-key tests) pins this: the default stays fatal, and only the
    pre-probe honours the variable.
- `tests/test_echoport_remote_command_guard_policy.py`:
  - `impl` is valid on the pinned hosts, and `shadow`/`rust` require the pins;
  - the existing `test_guard_accepts_the_policies` keeps using the Python
    parser;
  - a new test runs the Rust `--check-policy` on both policies when a built
    binary is available (`ECHOPORT_GUARD_RUST_BIN`), otherwise it is skipped
    with a message.
- `scripts/echoport_guard_shadow_compare.py` (stdlib, with a unit test):
  - read-only; runs `ssh root@<host> journalctl -o json -t
    echoport-remote-command-guard -t echoport-remote-command-guard-shadow
    --since <ts>`;
  - pairs the lines by `_PID` and reports: pairs, matches, verdict
    mismatches, unpaired lines on either side, malformed records and Rust
    shadow panics.
  - With `--strict` it exits non-zero on any of these:
    - an `ssh` or `journalctl` failure, or output that is not JSON lines;
    - zero records, or fewer pairs than `--min-pairs` (the default is 1; the
      S10 gates set it from the expected run count);
    - a Python guard line without a shadow line, or a shadow line without a
      Python line;
    - a shadow record that does not parse;
    - a verdict mismatch;
    - a panic;
    - when `--require-shapes` is given (the S10 gates pass it), any missing
      shape family, i.e. a tool family such as `scp -t` or `sqlite3`
      `.timeout` with no pair in the window.
    Silence is never a pass.
  - Its unit tests cover:
    - empty output;
    - an `ssh` failure;
    - only Python lines;
    - only shadow lines;
    - a malformed shadow JSON;
    - a reused PID with two pairs at different times (pairing is by
      `_PID` *and* the closest timestamp within 5 s);
    - a mismatch;
    - a clean window.
  - It compares verdicts. Argv parity is covered by Layers 1–3.
- Docs: `docs/FASTDEPLOY_PRIVILEGES.md` and `docs/ROOT_SSH_KEY_ROLLOUT.md`
  (impl selector, shadow compare, switch, rollback, emergency rollback) and a
  deployment record per production step under `docs/deployments/`.
- ops-control main CI is currently red at `test-software-inventory`, which
  is unrelated. S8 runs `just test-echoport-remote-command-guard-policy` and
  the touched tests locally and does not fix the inventory test.

### 6.4 Ordering with the `.timeout` rollout (item `sqlite-backup-runners-timeout`)

The hosts run the guard **without** `.timeout`. The first S9 deploy to
production installs the current Python guard, which has `.timeout`, and that
is the pending step `just pin-deploy-backup-key production` of that item.
`just register-gotosocial-backup` must follow it.

**S9 production waits until that item is done**, or the coordinator assigns
that step to S9 explicitly, and then S9 runs `register-gotosocial-backup`
right after. Staging is not affected: the GoToSocial runner targets
production.

### 6.5 Rollout phases

1. **Install only** (S9). Steps:
   - `impl: python` with the version pinned: first the direct `--check
     --diff` preview, then `just pin-deploy-backup-key staging`, then the
     same two steps for `production`;
   - check that the `authorized_keys` line is unchanged (the
     `ssh-keygen -lf` listing plus a `grep command=` of the line, compared
     before and after);
   - `<bin> --version` and the Rust `--check-policy` on the live policy pass.
   Lean measurement on the hosts: `/usr/bin/time -f '%M %e' <bin>
   --check-policy /etc/echoport/remote-command-guard.json`, read-only, on both
   hosts and for both guards.
2. **Shadow, staging** (S10a). Set `impl: shadow` on staging and deploy, for
   at least 72 hours. The window must include:
   - three nightly runs;
   - the 02:20 production → staging restores;
   - manual triggers of the marina and villakunterbunt staging targets
     (Echoport UI);
   - `just backup-django-chat-staging-db` and
     `just restore-django-chat-staging-db <run>` (a scratch restore), then
     `drop-django-chat-staging-db-restore`;
   - one refused probe (`ssh … id` from macmini as deploy).
   Gate: `echoport_guard_shadow_compare.py --strict --min-pairs <n>
   --require-shapes staging` is clean. That means every guard line has its
   shadow pair, there are zero mismatches, zero panics, zero malformed
   records and at least `<n>` pairs. `<n>` is the number of guard lines the
   journal shows for the window, which must be at least the count of a
   normal staging night (about 40). Every staging shape family must be
   present. All Echoport targets on the host succeed in the window.
3. **Shadow, production** (S10b). Starts after at least 24 hours of clean
   staging shadow and needs the coordinator's go (6.1). At least 72 hours,
   including:
   - `just backup-homepage-production-db`;
   - `just backup-python-podcast-production-db`;
   - `just backup-gotosocial`, which covers `.timeout`, the snapshot `cat`
     and `chown`;
   - the python-podcast private media archive (`tar`, `du`, `sh -c`, `rm -rf`).
   Same gate, with `--require-shapes production` and `<n>` at least the
   count of a normal production day (about 25).
4. **Cutover, staging = canary** (S11a). Set `impl: rust` and deploy.
   Acceptance:
   - the post-probe of the playbook;
   - every staging target triggered manually and successful;
   - the Django Chat scratch restore;
   - the next morning's nightly runs and the 02:20 restore successful;
   - `journalctl -t echoport-remote-command-guard` shows no refusal of a
     runner command.
   **Rollback drills**, timed, outside Echoport run windows:
   - (a) **Healthy binary.** Run the emergency rollback command below under
     the lock. The forced command is Python again, the post-probe passes and
     one manual staging backup succeeds. Then switch back to `rust` with
     `just pin-deploy-backup-key staging`.
   - (b) **Broken binary**, the case rollback exists for:
     - with impl `rust` active, an operator root session sets the active
       Rust binary to `chmod 000`, which is reversible;
     - check that the deploy key now fails: as `deploy` on macmini,
       `ssh … test -d /home/marina/site` fails;
     - run the emergency rollback command. The pre-probe failure is
       reported but does not stop the play, the role converges with impl
       `python` despite the unrunnable binary, the post-probe passes, and
       one manual staging backup succeeds;
     - restore the binary with `chmod 0755` (the next role run also sets it)
       and switch back to `rust`.
   - (c) **Manual path, no controller.** The authorized_keys edit from the
     runbook below is rehearsed on staging once, with `ssh-keygen -lf`
     before and after.
   Target: (a) and (b) each ≤ 3 minutes including the lock. The deployment
   record notes the times. Then soak at least 72 hours.
5. **Cutover, production** (S11b). Needs the coordinator's go. The same
   acceptance with the production targets, plus a refused `id` probe.
   Rollback criteria during soak: any refusal of a runner command, any
   failed Echoport run attributable to the guard, or any Nyxmon Echoport
   freshness alert that the guard causes. On any of these, roll back first
   and investigate afterwards.
6. **Retirement on the hosts** (S12): at least 14 days after S11b with no
   incident.
7. **Retirement in the repo** (S13, Q5): 30 days after S11b with no
   incident, or at the first runner change after that.

**Emergency rollback** for both hosts, about 1 minute, while the Python guard
is still installed (until S12):

```bash
SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt \
  ansible-playbook -i inventories/prod/hosts.yml playbooks/authorize-root-ssh.yml \
  --limit <host> -e echoport_remote_command_guard_impl=python \
  -e deploy_backup_route_probe_fatal=false
```

This command depends on neither the Rust binary nor its release. With impl
`python` the role's Rust steps are non-fatal (6.2), and the pre-probe through
the current, possibly broken, forced command is non-fatal (6.3). The
post-probe still verifies the Python guard. The Python guard file is always
installed before S12.

Afterwards, record `impl: python` in host_vars. If the controller is
unavailable: log in as root with an operator key (it is unrestricted), copy
`/root/.ssh/authorized_keys`, and replace only the deploy key line's
`command="…"` with the Python string from 1.1. Compare `ssh-keygen -lf`
before and after. The runbook in S8 spells this out.

---

## 7. Test strategy

### 7.1 TESTMAP (Python tests → Rust tests)

S0 creates `TESTMAP.md` with one row per Python test method. Every later
slice fills in its rows, and S5 requires every row filled. Mapping by class
(`tests/test_echoport_remote_command_guard.py`, 33 methods):

| Python | Rust |
|---|---|
| `GuardAllowsRunnerShapes` (7) | `rules::*` unit tests and the Layer-1 fixtures with source `unit` |
| `GuardRefusals` (9) | `rules::*` unit tests and the Layer-1 fixtures. `test_scp_against_a_real_tree` → Layer 2 |
| `GuardRedirects` (5) | `redirect.rs` tests on real temp dirs (Linux CI; macOS dev skips with a reason) |
| `GuardMain` (5) | process tests: the binary (`tests/cli.rs`) for refusals, `--decide` and `--shadow`; the flow with a stub `check()` and a probe as the exec target on a test search path (`tests/flow.rs`, Linux; S4). The real `SAFE_PATH` with stub tools is Layer 3 |
| `RunnerCommandsAreAllowlisted` (6) and `RecordingHosts` | Layer-1 corpus source `runner`: every command each runner sends for backup and restore, recorded by the existing harness and replayed against both guards |
| `RunnersUseClassicScp` (1) | stays Python (it tests runner templates, not the guard) |
| `tests/test_sqlite_backup_runners.py` (`.timeout`) | Layer-1 cases `.timeout` 1, 30000, 999999 accepted; 0, 1000000, `01`, `-1`, extra space and missing `.backup` refused |
| ops-control `test_echoport_remote_command_guard_policy.py` | Layer-1 policy fixtures plus the S8 Rust `--check-policy` test |
| role molecule verify | runs unchanged for impl `rust` and `shadow` (6.2) |

### 7.2 Layer 1: generated decision fixtures (Python oracle, committed)

`parity/gen_fixtures.py` imports `guard.py` from the role path, as the tests
do. It writes `fixtures/*.jsonl` (with `fixtures/mutation/*.jsonl`, every
file under the repository's 1000 KB limit and listed in
`fixtures/manifest.json`) and records the sha256 of the guard file it used
in `fixtures/GUARD_SHA256`. The crate's `README.md` documents the format.

**One case:**
- `id` (stable) and `source`;
- `policy` (a reference into `fixtures/policies/`);
- `env`, every lookup the Python guard made for the case:
  - `euid` (0);
  - `users` (name → uid, `null` for none);
  - `lstat` (path → kind, mode, uid, nlink; or `absent`, or an errno with
    glibc's `strerror`);
  - `realpath` (path → resolved).
  A path missing from `lstat` is absent, a path missing from `realpath`
  resolves to `normpath` (the tests' `identity`), and a missing user does
  not exist.
- `command`, or `command_hex` for bytes that are not valid UTF-8;
- `expected`: `{verdict: "allowed", argv, umask, stdin, stdout}`,
  `{verdict: "refused", reason}` or `{verdict: "error", error_type,
  message}` (4.2, `check()` crashes);
- `p3`, when the case falls into a 4.4 class.

**How it is generated:** in two steps. `gen_fixtures.py record` runs in the
repo venv (ansible-core, jinja2): it imports
`tests/test_echoport_remote_command_guard.py`, writes its policies to
`fixtures/policies/`, records the runner corpus (below) and every `check()`
and `Policy.from_dict()` call of the guard's unit tests, with the lookups
each call made, to `fixtures/corpus/`. `gen_fixtures.py generate` is stdlib
only: it points the guard module's `os.geteuid` and `pwd.getpwnam` at a
recorder and passes `realpath`/`lstat` callables, so each case's `env` is
exactly what that call asked; every case is replayed from its `env` and must
give the same decision. It runs with `PYTHONHASHSEED=0`.

**Python versions:** it runs under the hosts' Pythons, 3.12 and 3.13
(`uv run --python 3.12/3.13 --no-project`, stdlib only), and the outputs must
be equal. A case where they differ is a generator error unless it is listed
in `parity/allowed_differences.json` (expected: none at Layer 1, because
`realpath` is injected there).

**Sources of cases:**

1. `runner`: every command of every runner's backup and restore, recorded
   with the existing `RecordingHosts` harness. This runs once under the repo
   venv (ansible-core and jinja2) and is written to `fixtures/corpus/runner.jsonl`.
   Policies: the production and staging policies from the tests. Clock
   stamps are replaced by synthetic ones.
2. `journal`: the shapes seen live (3.4), with real paths and synthetic
   stamps.
3. `unit`: every case from the Python unit tests (`GuardAllowsRunnerShapes`
   and `GuardRefusals` except `test_scp_against_a_real_tree`, which is
   Layer 2; `Policy.from_dict()` calls and `GuardMain`'s documents go to the
   `policy` source).
4. `mutation`: a systematic mutation of every accepted command:
   - drop, duplicate or swap each token;
   - replace a value with its counterpart from the other host's policy or
     with an unlisted one;
   - append `; id`, `&& id`, `| id`, `$(id)`, `` `id` ``, `#x`, `\`;
   - requote a token (`'x'`, `"x"`, `x''`), which must give the same
     decision;
   - change whitespace (tab, double space, leading or trailing);
   - control and Unicode characters (`\x1b`, `\x1c`, U+00A0, U+200B,
     look-alikes);
   - length 4095/4096/4097;
   - path forms `.`, `..`, `//`, trailing `/`;
   - per tool: rsync tuples with one option more or fewer, `scp -r/-p/-d`,
     psql SQL variants including `SELECT 1; DROP …`, the `.timeout` and
     `.backup` variants.
5. `fs`: for each path-taking shape, every relevant `lstat`/`realpath` state:
   - regular file, dir, symlink, fifo, socket, device, `nlink` 2;
   - owners root, other, postgres or the service user;
   - dir modes `0700`/`0750`/`0777`;
   - resolved inside or outside a root;
   - absent;
   - an `ENOTDIR`/`EACCES`/`ELOOP` errno.
6. `policy`: `--check-policy` cases. Each validator passes and fails. The
   types and `null` cases are included, plus the trailing-`\n` quirk (a P3
   entry).

**Expected size:** about 10–20k cases, generated rather than hand-written
(S0: about 13.4k cases, 5 MB). The JSONL is committed, and reviewers spot-check
it.

**Drift check:** a step in F1's `rust.yml` regenerates the fixtures and
fails on any diff. `fixtures/GUARD_SHA256` must equal the sha256 of
`guard.py`, so any change to the Python guard before S13 forces a
regeneration and a Rust update in the same change. `rust.yml` only runs on
changes under `rust/` (owner decision 2026-10-21), so a change to `guard.py`
or a runner template alone does not trigger it. S0 therefore also adds
`tests/test_echoport_command_guard_fixtures.py` (no Rust toolchain) to `just
test-echoport-remote-command-guard`, which `just test` runs: the
`GUARD_SHA256` comparison and the full drift check (`gen_fixtures.py check
--record`, which re-records the runners), plus the 4.1 property tests. `just
echoport-command-guard-fixtures` regenerates (record in the venv, generate
under 3.12, `check` under 3.13 and the venv).

### 7.3 Differential and property tests (CI, stable toolchain)

**The oracle server:** `parity/oracle.py` is a long-running Python process
speaking JSON lines (`check`, `split`, `check_policy`, `realpath` over a
virtual tree, and `os_realpath` on the real filesystem, S2) with injected
env.

**proptest suites** call the oracle server:

- **tokeniser:** random strings over an alphabet weighted towards
  quote, space and tab characters, and towards `\`, `#`, `$` and control
  characters. Property: if the prefilter passes, Rust tokens equal
  `shlex.split` (including errors).
- **realpath** (S2, `tests/realpath.rs`): random trees of directories,
  files, links with random relative and absolute targets (`.`, `..`, empty
  parts) and `lstat` errors, probed with random safe paths: virtual trees
  through the oracle's `realpath`, real trees in a temp directory through
  `os_realpath` with the real `GuardEnv`. Property: when Rust resolves,
  Python resolves to the same string; Rust may refuse only as 4.2 allows, and
  a loop refusal must be confirmed by an independent resolver without
  Python's `seen` map.
- **decisions:** grammar-aware commands built from the policy vocabulary
  and the mutation operators, with random virtual fs states. Property:
  `rust_accepts ⇒ python_accepts ∧ decision_equal`; for refusals, reasons are
  equal unless the case is in the 4.4 list.
- **invariants**, Rust only, also used as fuzz assertions:
  - an accepted `argv[0]` is in the fixed tool set;
  - an upload or `mkdir` is never `runuser -u root`;
  - every accepted path token matches `_SAFE_PATH_RE` with no `.`/`..`
    component;
  - a `sudo` decision always starts `sudo -n -u postgres --`.

CI runs a fixed number of cases (default 2,000 per suite, seeded). Local
runs with `PROPTEST_CASES=100000` are documented.

The oracle runs under Python 3.12 in CI. S5 also runs it under 3.13 locally.

### 7.4 Fuzzing

`fuzz/` holds cargo-fuzz targets for `prefilter+tokens`, `check` (with
arbitrary command and env), `policy` (arbitrary JSON) and `py_repr`.
Assertions: no panic, and the 7.3 invariants hold.

S5 runs each target for at least 1 hour on nightly. The crashes it finds
become Layer-1 fixtures, and the corpus is committed. It is not a CI gate,
because CI uses the pinned stable toolchain. S5 records how to re-run it.

### 7.5 Layer 2: live differential on real filesystems (Linux containers, root)

`parity/e2e/` has Dockerfiles for Ubuntu 24.04 (Python 3.12) and Debian 13
(Python 3.13), each with real users (`postgres`, `gotosocial`, `marina`). A
script materialises fs scenarios as real trees, as root, under the real
policy paths:

- symlink in or out of a root;
- dangling symlink;
- loop;
- `..` in a link target;
- replaced directories;
- foreign owner;
- hard link;
- fifo.

It then runs each command through Python `check()` with the real
`realpath`/`lstat`/`pwd` and through Rust `--decide`, and compares. This
covers `test_scp_against_a_real_tree` and validates `pyrealpath.rs` against
both CPython versions.

**S2 delivers the filesystem part** (`parity/e2e/Dockerfile`,
`layer2_realpath.py`, `run-layer2.sh`; `just echoport-command-guard-layer2`,
local, needs Docker). The probe `examples/env-probe.rs` answers the real
`GuardEnv`'s lookups as JSON lines; the script builds the scenarios above
under the policies' path roots (plus 40/41-link chains, an `ENAMETOOLONG`
component, a non-UTF-8 link target, an `EACCES` case run as `nobody`, and
300 seeded random trees) and compares `realpath` with `os.path.realpath`,
`lstat` with `os.lstat` (kind, mode, uid, link count, or errno and
`strerror`), `uid_of` with `pwd.getpwnam` and the euid. An `ELOOP` refusal
must be confirmed by an independent resolver without Python's `seen` map
(no end, or more than 40 traversals), and a resolved path must need at most
40. S5 adds
the `check()`/`--decide` comparison on top.

### 7.6 Layer 3: end to end through sshd

The same containers, extended with sshd and a pinned client key, with
`command="<impl forced command>"` for the Python, Rust and shadow impls.
For a curated list:

- every runner shape, with stub `systemctl`/`sudo`/`pg_*`/`sqlite3`/`curl`
  in `/usr/local/sbin` that record their argv, environment, fds, `SigIgn`
  and umask;
- real `scp -O` upload and download;
- the three rsync forms;
- `cat >` and the snapshot `cat`;
- `tar` with umask;
- `mkdir -p` as owner;
- refused commands;
- interactive;
- SFTP.

Compared between Python and Rust: exit code, stdout, stderr text and the
resulting files (content, owner, mode). From the stub probes: argv, the
environment (including `LC_CTYPE` with and without a client `LANG`), the
open fds, `SigIgn` and the umask. The journal lines are compared too
(identifier, priority, message with the PID removed).

This is the gate for 3.5 and 3.6. The role's molecule scenario (6.2) is the
Ansible-level counterpart.

---

## 8. Build, release, lean goals

### 8.1 What this stream needs from the foundation (`rust/PLAN-foundation.md`)

1. F1: the workspace (S1 appends the member `echoport-command-guard`), the
   pinned stable toolchain, `cargo-deny`, and `--locked` everywhere.
2. F1 CI (`rust.yml`): fmt, clippy (`-D warnings`), test, deny. S1 adds
   steps for this crate (the foundation allows crate steps, not new suites):
   Python 3.12 available (via `uv`) for the oracle tests, a Linux runner
   where tests may use real temp dirs, and a step that runs the fixture
   drift check (7.2). The drift check needs the repo venv for the `runner`
   corpus.
3. F2 release workflow (`rust-release.yml`) with the tag prefix
   **`echoport-command-guard-v<semver>`** in its trigger list (the
   foundation lists it; if it is missing when S7 runs, S7 adds it):
   - target `x86_64-unknown-linux-gnu`;
   - glibc floor: F2 checks **2.35**, below what this crate needs
     (production 2.39). `NEEDED` libraries are glibc/libgcc only, enforced by
     the floor check;
   - `--version` smoke with the full commit;
   - a deterministic `tar.gz` holding only the binary and `LICENSE`, plus
     its `.sha256`;
   - the tag must equal the crate version.
4. F3 role `rust_release_binary`, with these properties:
   - `install` puts a pinned archive (URL from the tag, sha256 required) or
     a local archive into `<install_root>/<version>/`, with `install_root`
     set by this role (6.2);
   - it sets owner root:root and modes `0755`, and never leaves a group- or
     world-writable path component (6.2);
   - `prune` never deletes a version in its explicit `protect` list (the
     consumer fills it from the live state) or a version named by a pin,
     including the consumer's separate "previous" rollback pin, which moves
     only when the consumer pins a new version it verified live (owner
     requirement for F3 of 2026-10-21, section 9); `pin` with
     `state: absent` keeps the removed version as the previous pin. This
     role's side of it (when to pin, what to protect) is in 6.2;
   - it reports the installed binary path as a fact
     (`rust_release_binary_path`) and, without `fail_hard`, a failure as
     `rust_release_binary_failed` instead of stopping the play.
   If F3 cannot guarantee the permission properties, S6 adds the asserts on
   top and does not fork the role.
5. Nothing else. No container image, no service unit, no secrets.

### 8.2 Target and linking (decision)

The binary is glibc and dynamic, like the precedents: `getpwnam` through NSS
must equal Python's, and production uses `compat systemd`. musl's static
`getpwnam` does not load NSS modules. It would work today, because all the
users are in `/etc/passwd`, but it is a silent difference. Only x86_64 is
built.

### 8.3 Lean goals (measured like nyxmon 4.4)

| Metric | Python today | Budget |
|---|---|---|
| Stripped release binary | (interpreter) | ≤ 2 MiB |
| Peak RSS per invocation (`/usr/bin/time %M`, `--check-policy` and a refusal) | 13.5 MiB (arm64 container) | ≤ 4 MiB |
| Wall time from start to `exec` or refusal | 10–20 ms | ≤ 5 ms |
| Memory at rest | 0 | 0 |

How they are measured:

- in S7, in both Layer-3 containers (x86_64 CI runner), as the median of
  20 runs;
- in S9 on both hosts with `--check-policy` only, read-only, for both
  guards.

The numbers go into the S7 and S9 reports and the README. Exceeding the
binary budget means checking the dependencies (`regex-lite`, `serde_json`
features) before relaxing it.

---

## 9. Owner decisions (2026-10-21)

The owner accepted every recommended answer of the former owner questions on
2026-10-21 (given in chat to the campaign coordinator). They are decided:

- **Q1 Port at all:** **yes**, scheduled **last in the campaign** and
  **never alongside other production or staging changes** (6.1,
  "Scheduling"). The guard is not a resident process (about 13.5 MiB for
  about 15 ms, a few dozen times a day); the value is getting the
  distribution's Python (3.12 vs 3.13 already) off the root forced-command
  path and a typed, differential-tested and fuzzed parser. The risk, a
  security regression that locks out backups, is handled by 6.5 and R1.
- **Q2 Stricter refusals (4.1, 4.2):** **accepted**: the command prefilter
  (valid UTF-8, printable ASCII and tab only, no `\`, no `#`), strict policy
  JSON types, refusing trailing `\n` in policy values, and refusing realpath
  loops. No runner command and no generated policy is affected; S0 and S9
  prove that.
- **Q3 Python-compatibility ports:** **allowed**: a non-strict `realpath`
  (unless `soft-canonicalize` matches the oracle, S2; it does not, 5.2),
  `repr` for log lines,
  and PEP 538 locale coercion. Each is differential-tested against CPython
  3.12 and 3.13 (7.3–7.5).
- **Q4 Live acceptance:** **only non-destructive restores**: the nightly
  production → staging DB restores and the Django Chat scratch restore. The
  in-place restores of marina, villakunterbunt and GoToSocial are not run
  live; the fixtures, Layer 3 and molecule cover their commands (6.5).
- **Q5 Python guard removal from the repo (S13):** **30 days after S11b
  with no incident, or at the first runner change after that.** Until then,
  every runner change needs the Python rule, the fixture regeneration and the
  Rust rule. After S13 the runner-shape tests and ops-control's policy test
  use the Rust binary (`--decide`, `--check-policy`). The removal from the
  hosts (S12, 14 days after S11b) is unchanged.

Campaign-wide decisions of the same day that this plan follows:

- **Foundation CI and releases:** ops-library gets its first GitHub Actions
  workflows from the foundation: `rust.yml` (CI for `rust/` only, F1) and
  `rust-release.yml` (F2; `contents: write` only in the publish job, binary
  releases on the public repository). See 7.2 and 8.1.
- **Collection releases:** the coordinator makes the collection release
  commit (`galaxy.yml` bump plus the CHANGELOG heading) on ops-library
  `main` right before the production steps that need it; workers never bump
  `galaxy.yml` (6.1, S8).
- **Review rounds:** a slice, and a plan, may get a **third** review round
  over the repair delta of round 2. If round 3 is not clean, the worker
  stops and reports to the coordinator (section 11). For this plan the
  owner allowed exactly one more round (round 4) over the fix of the
  round-3 finding on the pin rotation.
- **Version protection in F3:** F3's `prune` never deletes a version in an
  explicit `protect` list that the consuming role fills from the live state,
  nor the consumer's separate "previous" rollback pin, which moves only
  after a new version is verified live. The mechanism is F3's; this plan
  keeps the consumer's duties and their S6 tests (6.2, 8.1).

**Approvals to bundle** (not questions): the production steps S9 (install
only), S10b (shadow), S11b (cutover) and S12 (retirement), each at a time
the coordinator clears with the other production work (6.1).

## 10. Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | **Backups are locked out silently**: the Rust binary does not start, or it refuses a runner command. | Role-level `--version`/`--check-policy` on the host before any switch; staging canary first; shadow gate with zero mismatches; the playbook's post-probe; manual acceptance runs; Nyxmon Echoport freshness alerts; rollback by one playbook run that needs neither the Rust binary nor the pre-probe (6.5; about 1 minute, drilled in S11a with a healthy and a deliberately broken binary); Python stays installed until S12. |
| R2 | **The Rust guard accepts something Python refuses** (a security hole). | The invariant `rust_accepts ⇒ python_accepts ∧ same decision` in Layer 1, the proptests, Layer 2 and fuzzing; the prefilter; fail-closed stubs; a dedicated security review in S7 (gpt-6.1-sol high, prompt focused on acceptance drift, path handling and fd/exec hygiene). |
| R3 | The Python guard changes during the port (new runner shapes). | The `GUARD_SHA256` drift check; TESTMAP; until S13 every guard change updates both. |
| R4 | The CPython versions on the hosts differ (3.12/3.13). | The oracle runs on both; loops are refused (4.2). |
| R5 | Side effects on the exec'd tools (environment, locale, signals, fds, umask). | Measured contract (3.5); Layer-3 probes. |
| R6 | A shadow-mode bug breaks backups (the Rust binary runs first). | `catch_unwind` plus an unconditional `execv` of Python; the shadow forced command is validated by the role; staging first. |
| R7 | `authorize-root-ssh.yml` also applies pending operator-key changes. | `--check --diff` under the lock before each run; stop on any unexpected line. |
| R8 | Collisions with other production work: Traefik ACME (production, until 2026-10-30), the `.timeout` rollout (6.4), opsgate key rotation (macmini only, different playbook). | Coordinator's go for the production steps; the shared deploy lock; 6.4 ordering. |
| R9 | The foundation (F1–F3) is late or differs from what 8.1 assumes. | S0 needs no foundation slice; S1 adapts to F1's actual layout, S6 to F3's, S7 to F2's; any gap goes back to the foundation stream (`rust-metrics-httpd`), without a parallel pipeline here. |
| R10 | Public repo: fixtures could leak private data. | Fixtures use only the policies that are already public in the tests, and synthetic stamps; no tailnet addresses (the `SSH_CLIENT` in tests uses a documentation address). |
| R11 | ops-library has no CI today (no `.github/workflows`), and F1's `rust.yml` covers only `rust/`. | `rust.yml` comes with F1 (owner decision 2026-10-21); until then the slices run `cargo test` and `just test-echoport-remote-command-guard` locally and record this in the review. The Ansible/Python suite stays local (`just test`), including the `GUARD_SHA256` comparison (7.2). |

---

## 11. Slices

Rules, as in the precedents:

- **Branch:** one per slice, `rust-echoport-command-guard-<id>` (e.g.
  `rust-echoport-command-guard-s1`), in its own worktree.
- **Review:** `gpt-6.1-sol` at high reasoning through the codex review loop.
  A slice may get up to three rounds; round 3 covers only the repair delta
  of round 2, and if round 3 is not clean the worker stops and reports to
  the coordinator (owner decision 2026-10-21). After a clean review: merge
  into `main`, push, and deploy where the slice says so.
- **Collection version:** never bump `galaxy.yml`; CHANGELOG entries go under
  "Unreleased". The coordinator cuts collection releases (6.1).
- **Merging is safe at any time:** nothing on a host changes until the
  role's `impl` and version change in ops-control.
- **Every slice:** keeps `cargo fmt/clippy/test/deny` and
  `just test-echoport-remote-command-guard` green, updates `TESTMAP.md`, and
  lists the `guard.py` lines it ports in the review context.
- **Size:** at most about 2k lines including tests; generated fixtures are
  excluded but spot-checked.
- **Production slices:** use the deploy lock and `--check --diff` (6.1).

| ID | Slice | Scope | Depends on | Parallel | Prod | Est. h |
|---|---|---|---|---|---|---|
| S0 | Contract freeze and fixture generator | `parity/gen_fixtures.py`, `parity/oracle.py`, all Layer-1 sources (7.2), `fixtures/` + `GUARD_SHA256`, `allowed_differences.json` (empty), property test "Python accepts only printable ASCII and tab", runner-corpus check (no `\`/`#`), the `GUARD_SHA256` comparison in `just test-echoport-remote-command-guard` (7.2), `TESTMAP.md` skeleton. Python only. | — | yes (with F1–F3) | no | 4 |
| S1 | Crate skeleton, policy, tokeniser | Crate in the F1 workspace (member added), this crate's `rust.yml` steps (8.1 item 2: Python 3.12 via `uv`, fixture drift check), `main.rs` argv grammar and `--version`, `policy.rs` + `--check-policy` (policy fixtures green), `prefilter.rs`, `tokens.rs` + tokeniser differential proptest, `Decision` types, fail-closed dispatcher stub, `GuardEnv` trait with the virtual impl, Layer-1 test runner (cases from unported branches are expected-refused). | F1, S0 | no | no | 4 |
| S2 | Filesystem layer | Real `GuardEnv` (`lstat`, `readlink`, `getpwnam_r`, `geteuid`), `pyrealpath.rs` or `soft-canonicalize` (decision with evidence), plain-file and private-dir helpers, Layer-2 container harness for realpath against 3.12 and 3.13. | S1 | with S3a, S4, S6 | no | 3 |
| S3a | Rules without filesystem | `sudo`/`runuser` postgres (all branches), `sqlite3` including `.timeout`, `systemctl`, `curl`, `sh -c` probe, `du`, `mktemp`, `rm -f` dumps and `rm -rf --` temp dirs; their Layer-1 cases green. | S1 | with S2, S4, S6 | no | 3 |
| S3b | Rules with filesystem | `scp -f/-t`, rsync, `mv`, `mkdir`, `chmod`, `chown`, `rm` wal/shm, `test`, `readlink`, snapshot `cat`, `cat >`, `sha256sum`, `tar`; redirect decisions; their Layer-1 cases green (with S3a: all of Layer 1). | S1, S2 | with S3a, S4, S6 | no | 4 |
| S4 | Runtime and exec | Forced-command flow (3.1), syslog and `py_repr` (3.6, 4.3), `redirect.rs` (3.5), umask, `PATH`, locale coercion, SIGPIPE/SIGXFSZ, fd hygiene, exit codes, `--decide`, `--shadow`; process tests (`tests/cli.rs`, `tests/flow.rs`; on Linux CI directly, in a container on macOS). | S1 | with S2, S3a, S3b, S6 | no | 4 |
| S5 | Parity gate | All of Layer 1 green, the 4.4 list reviewed, decision proptests (7.3), Layer 2 complete, Layer 3 sshd e2e on both distros, fuzz targets with at least 1 hour each and the corpus committed, TESTMAP complete. | S2, S3a, S3b, S4 | with S6 | no | 4 |
| S6 | Role switch | 6.2: the impl selector, Rust install through F3's role with the permission asserts, dual validate, forced command per impl, `confirm_live.yml` (verify the written line, protect list from the live `authorized_keys`, F3 pin and previous pin, F3 prune with `protect`) with its parse filter and unit test, molecule impl × {Ubuntu 24.04, Debian 13} with a local archive, the rollback-independence case (a broken Rust binary with impl `python` converges), the `pins` scenario (repeated failed deployments with different targets and the other 6.2 cases), README/docs/CHANGELOG (Unreleased). | F3 (install role with `protect` and the previous pin), S4 (CLI surface) | with S2–S5 | no | 5 |
| S7 | Release 0.1.0 | Lean measurements (8.3), README, security-focused review of the whole crate, tag `echoport-command-guard-v0.1.0` through F2's workflow, archive sha256 recorded. | S5, S6, F2 (release workflow) | with S8 prep | no | 2 |
| S8 | ops-control wiring | 6.3: pins (filled after S7), impl `python`, tests, playbook minimum version, `confirm_live.yml` after the post-probe with its position test, the `deploy_backup_route_probe_fatal` rollback switch with its test, the strict shadow-compare script and its tests, runbooks. | S6 merged plus a collection release commit by the coordinator, S7 (pin values) | prep with S7 | no | 3 |
| S9 | Install only | 6.5 step 1, staging then production, read-only lean measurement on the hosts. | S7, S8, 6.4 (`.timeout` item), coordinator go (6.1 scheduling: last in the campaign, no other production/staging change in flight) | no | **yes** | 1.5 |
| S10a | Shadow, staging | 6.5 step 2, compare report in ops-control `docs/deployments/`. | S9 | no | **yes** | 1.5 + 72 h soak |
| S10b | Shadow, production | 6.5 step 3. | S10a (≥ 24 h clean), coordinator go | overlaps S10a's soak | **yes** | 1.5 + 72 h soak |
| S11a | Cutover, staging, and rollback drills | 6.5 step 4, drills (a)–(c). | S10a (gate), S10b running | no | **yes** | 2 + 72 h soak |
| S11b | Cutover, production | 6.5 step 5. | S11a (soak clean), S10b (gate), coordinator go | no | **yes** | 1.5 |
| S12 | Retire Python on the hosts | Role: with impl `rust` the Python guard file is removed from the host and the `shadow` impl is removed; the default stays `python` for other consumers until S13. ops-control: host_vars cleanup, runbooks (rollback then means re-installing Python by a role run with `impl: python`, still one command). Deploy both hosts. | S11b + 14 days | no | **yes** | 2 |
| S13 | Retire Python in the repo | Q5 (30 days after S11b with no incident, or the first runner change after that): delete `guard.py`, make the Rust binary the source for the runner-shape tests (`--decide`) and for ops-control's policy test (`--check-policy`), make the role default `rust`, remove the impl selector's Python branch. | S12, S11b + 30 days (Q5) | no | no | 3 |

**Parallel waves:**

1. F1 ∥ S0 (F2 and F3 follow F1 in the foundation stream).
2. S1.
3. S2 ∥ S3a ∥ S4 ∥ S6.
4. S3b (after S2) ∥ the rest of wave 3.
5. S5 ∥ S6.
6. S7 ∥ S8 prep.
7. The production chain S9 → S10a → (S10b overlapping) → S11a → S11b → S12
   → S13.

Up to four implementation workers can run at the same time (wave 3).

**Total:** about 50 worker-hours, plus at least 7 days of soak before S11b,
14 days before S12 and 30 days before S13. The production chain waits for the
coordinator's go under 6.1 "Scheduling".

**Review focus per slice** (in addition to correctness):

- S1/S3/S4/S5: acceptance drift, check order (reasons), panics on input,
  `unsafe`.
- S6: the permissions of the root-executed path, that the forced
  command for impl `python` is byte-identical, and that no path moves a pin
  or prunes before the written line is verified live, or prunes a version
  that any `authorized_keys` line names.
- S9–S12: the evidence (lock, diff, probes, compare report, journal) in the
  deployment record.
