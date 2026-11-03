# vibe_coding

Port of the `vibe_coding_deploy` Ansible role (ops-library `6777cbb1`,
2.75.5; the role's last change is `6777cbb1`): a dedicated interactive
coding user on a Linux host with a locked password, SSH key login, fish,
chezmoi dotfiles, the GitHub CLI login, Node.js, Neovim, lazygit, rustup,
per-user npm coding tools, zellij and an sshd `Match User` block.

```python
from pathlib import Path
from ops_deploy.services.vibe_coding import VibeCodingConfig, deploy_vibe_coding, prepare_dotfiles

dotfiles = prepare_dotfiles("git@github.com:example/dotfiles.git", Path(workdir))  # on the controller
cfg = VibeCodingConfig(
    ssh_authorized_keys=("ssh-ed25519 AAAA... me@laptop",),
    dotfiles=dotfiles,
    secrets="secrets/prod/vibe-coding.yml",
)
deploy_vibe_coding(cfg, secrets)  # secrets: github_username, github_token (both optional)
```

ops-control registers it as `vibe_coding` (its `docs/PYINFRA_VIBE_CODING.md`).

## Configuration (`VibeCodingConfig`)

The role's variables without the `vibe_coding_` prefix, with its defaults.

| Field | Default | Notes |
|---|---|---|
| `user`, `group` | `vibe` | the group must be named like the user (shell_basics uses the user's own group, as its role does) |
| `site_path` | `/mnt/cryptdata/vibe` | the home (`user_home`); letters, digits and `. _ / + -` only |
| `shell` | `/usr/bin/fish` | also shell_basics' `shell_path` |
| `projects_dir` | `<home>/projects` | |
| `ssh_authorized_keys` | required | one line each; empty is refused (the role's assert) |
| `dotfiles` | `None` | `prepare_dotfiles(repo, workdir)`; `None` skips the chezmoi tasks (empty `dotfiles_repo`) |
| `shell_basics_extra_packages` | `gh`, `zoxide` | |
| `shell_basics` | `ShellBasicsConfig()` | shell_basics' own settings (host vars); the include's five variables are applied on top |
| `install_node`, `node_major_version` | `True`, `22` | NodeSource |
| `neovim_version`, `lazygit_version` | `0.12.5`, `0.65.1` | with the role's checksums per architecture |
| `install_rust`, `rustup_version` | `True`, `1.29.2` | |
| `npm_prefix` | `<home>/.npm-global` | |
| `npm_tools` | the role's four tools | package names only; non-empty needs `install_node` (the role's assert) |
| `zellij_install`, `zellij_version` | `True`, `0.45.1` | archive and binary checksums |
| `sshd_hardening` | `True` | |
| `secrets` | `None` | file with `github_username` and `github_token` |

The GitHub CLI login is managed when `github_token` is non-empty (the
playbook's `vibe_coding_github_cli_auth_enabled`); a token without a user
name fails planning (the role's assert). Without a token, `hosts.yml` is
removed, as the role does when the login is off. The token reaches the host
only through `secret_file` (stdin), never a command line or log.

## Parity with the role, task by task

Planning probes the host first; a step runs only when the probe shows the
role's task would change something. "Same" means the same command or the
same resulting bytes, owner and mode.

| Role task (file) | Here | |
|---|---|---|
| main: validate required variables | config validators; GitHub pair checked when the deploy starts | same refusals, before any connection or change |
| user: group | `groupadd vibe` when missing | same |
| user: user (`groups: []`, `password: "!"`, `password_lock`, `create_home`) | `useradd -g -d -s -p '!!' -m`, or `usermod` with exactly the options Ansible's user module adds (`-g`, `-G ''`, `-d`, `-s`, `-L`/`-p '!!'`) | same commands; the shadow field is read only as "starts with !" / "is only !", never printed |
| ssh: `.ssh` 0700, `authorized_keys` 0600, `rc` 0700 | `files.directory` / `files.put` with the role's templates | byte-identical |
| ssh: fish `conf.d` 0755, `ssh-agent-forward.fish` 0644 | same; missing parents get the user and mode, like the `file` module | byte-identical |
| ssh: find and remove `~/.ssh/id_*` (not `*.pub`) | `find -maxdepth 1 -type f`, one removal per key | same selection |
| shell: `include_role shell_basics_deploy` | nested `deploy_shell_basics` with user, home, extra packages, no fish config, shell switch | the include's variables over the host's shell_basics settings |
| chezmoi: GitHub key in root's and the user's `known_hosts` | `ssh-keygen -F` and the module's decision (keep, replace the same-type line, append) | same content; an existing file keeps its owner and mode |
| chezmoi: stat `.git`, `git remote get-url origin` | one read-only probe | see differences |
| chezmoi: remove source without correct origin | fresh clone into a removed directory | same |
| chezmoi: `safe.directory` for root | `git config --global --add` when missing | same |
| chezmoi: `git` clone/update (via the forwarded agent) | controller fetch + `git bundle`; clone, or fetch, `checkout --force <branch>`, `reset --hard origin/<branch>` | see differences |
| chezmoi: recursive ownership | `files/own_tree.py` when anything is not the user's, before the update | see differences |
| chezmoi: rsync legacy flow | not ported | the playbook uses the git flow |
| chezmoi: `init --force`, `status`, `apply --force` (as the user; status and apply with `--exclude=externals`) | the same three commands in one step | runs when planning finds a change (see differences) |
| chezmoi: remove legacy `z.fish` | `files.file(present=False)` | same |
| secrets: `conf.d/secrets.fish` from `fish_env` | not ported | the playbook sets no `fish_env` |
| github_cli: `~/.config/gh` 0700, `hosts.yml` 0600 (no_log) / remove | `secret_file` / `files.file(present=False)` | byte-identical; never logged |
| directories: projects 0755 | `files.directory` | same |
| nodejs: dependencies, keyring, `nodesource.list`, apt update, `nodejs` | the same files and packages; the key is fetched into a private temp directory and dearmored once | same files (see differences) |
| neovim: arch assert, version check, remove apt `neovim`, verified download, unpack to `/opt`, link | same order and checks | same |
| lazygit: version check, verified download, `lazygit` into `/usr/local/bin` | `release_install_script` (staged, renamed into place) | same file, owner and mode |
| rust: rustup-init as the user when `~/.cargo/bin/rustup` is missing | same, pinned and checked | same |
| rust: `rustup component add rust-analyzer` | only when `component list --installed` lacks it | see differences |
| coding_tools: npm prefix dir, `npm config set prefix` | the setting only when `npm config get prefix` differs | see differences |
| coding_tools: `npm-paths.fish` | `files.put` | byte-identical |
| coding_tools: system-wide listing, uninstall conflicts, user listing, outdated, install | one host script (`files/npm_tools.py`) with the role's order and rules | see differences |
| zellij: `which zellij`, verified archive, binary checksum, install | same checks, staged and renamed into place | same |
| sshd: `blockinfile` with `validate: sshd -t -f %s`, handler `reload sshd` | the same block and markers; checked, then installed and reloaded in one step with rollback | byte-identical; see differences |

Commands the role runs as `become_user` run through `sudo -H -n -u <user>`,
so they get sudo's environment and PAM session exactly as Ansible's become
does (HOME, `secure_path`, the locale, and pam_umask's `0002` for a user
with its own group, which decides the modes chezmoi and npm give new files).
They start in `/`: sudo keeps root's working directory (`/root`, which the
user cannot read, so chezmoi failed with `stat .: permission denied`), while
Ansible runs its modules from a temporary directory the user can read.

## Differences from the role

- **Dotfiles transport.** The role clones on the host as root through a
  forwarded SSH agent (`ForwardAgent=yes` in the playbook). pyinfra opens no
  agent channel for its commands and the hosts get no GitHub credentials,
  so the controller clones the repository with the operator's own git and
  SSH setup (`prepare_dotfiles`, bare and complete) and the deploy ships a
  `git bundle` of every branch and tag to `/var/lib/ops-deploy/vibe-coding`
  (root, `0700`; the bundle `0600`, removed after use) only when the checkout
  is not at the default branch's tip. The host then does what the `git`
  module does with the remote; `origin` keeps the repository URL, so the
  user's own `git pull` through an agent works as before. Repositories with
  submodules are refused (the module would fetch them on the host).
- **git runs as the user.** The role runs every git command as root in the
  user's checkout, whose `.git/config` the user controls (`core.fsmonitor`,
  hooks): root would run the user's commands. Here the probe, the removal of
  a checkout with another origin, the clone and the update run as the user
  (`sudo -H -n -u`), reading the bundle from root on stdin; root only stages
  the bundle. The root `safe.directory` entry is still added, as the role
  does. Before a clone, the checkout's parent (`~/.local/share`, which the
  role's root clone leaves root's) is given to the user, that directory
  only. A checkout the user cannot read while planning (its owner is being
  repaired) is cloned or updated as the state after the repair says.
- **No accidental re-clone.** The role reads `origin` before it adds the
  `safe.directory` entry, so on a host without that entry it removes and
  re-clones the checkout. Here every read passes `-c safe.directory` for
  that one command, and the update re-checks the planned state first: a
  checkout that matches `origin` is never removed. `git status` runs with
  `--no-optional-locks`, so the read leaves no root-owned index behind.
- **Ownership.** The `file` module's recursive ownership follows symlinks
  (`follow: true`) and would change the owner of their targets, also outside
  the checkout. Here `files/own_tree.py` opens the path from `/` without
  following any symlink (a symlinked parent fails the step) and changes the
  owner through directory descriptors, links themselves only. It runs when
  something below the checkout is not the user's, before the update (whose
  git, running as the user, then writes only the user's files).
- **Shell.** The role's include leaves shell_basics' `shell_path` at its
  default (fish) whatever `vibe_coding_shell` is, so another shell would be
  switched back and forth on every run; here shell_basics gets `shell`.
- **Always-run steps.** The role runs `chezmoi init --force`, `chezmoi
  apply --force`, `npm config set prefix` and `rustup component add
  rust-analyzer` on every run (reported unchanged or changed by output).
  Here each runs when planning shows it would change something:
  `execute-template --init` of the config template differs from the config
  file (or there is none), `chezmoi status` lists anything (always-run
  `run_` scripts included, so dotfiles with such a script get this step on
  every run, as the role reports a change on every run), the checkout was
  updated or chezmoi is replaced in the same run; the npm prefix differs;
  rust-analyzer is not installed. A failing probe runs the step.
- **npm on a first run.** npm 10 fails `npm list -g` on an empty per-user
  prefix (no `lib` directory, exit 254), which stops the role on a fresh
  host. Here such a prefix counts as having no packages.
- **sshd.** The role writes the validated file and reloads at the end of
  the play. Here one step, last as in the role: the planned file is
  installed only if `/etc/ssh/sshd_config` is still what planning read, the
  candidate passes `sshd -t -f`, and `sshd -T -C user=root,...` prints the
  same effective settings for root before and after (root's login cannot be
  changed by it); then the old file is kept as a backup, the new one moved
  in, checked again with `sshd -t` and ssh reloaded (started if stopped, as
  `state: reloaded`). If that check or the reload fails, the old file is put
  back and ssh reloaded again, and the step fails.
- **NodeSource key.** Fetched into a private `mktemp -d` directory instead
  of `/tmp/nodesource-repo.gpg.key`, and only when the keyring is missing
  (the role downloads it whenever the list or keyring is missing and lets
  `creates:` skip the dearmor).
- **Missing home parent.** For a new user whose home's parent is missing
  the module copies `/etc/skel` itself; here the parent is created and
  `useradd -m` does it.
- **chezmoi externals.** Both tools run `chezmoi status` and `chezmoi apply
  --force` with `--exclude=externals`, so the probe's `status` leaves them out
  too: entries from the dotfiles' `.chezmoiexternal.*` (the `projects/agent-stuff`
  git-repo external, cloned over SSH) are not fetched by a deploy. The user has
  no GitHub key and no forwarded agent then; the next interactive `chezmoi
  update` as the user, with the owner's forwarded agent, fetches them.
- **Not ported.** The rsync flow (`chezmoi_source_dir`) and `fish_env`
  (`secrets.fish`): the playbook uses neither, and the config has no field
  for them.

## Converged runs

A second run plans no operation: only probes run. On a host the role
converged, the first run changes nothing either
(`tests/test_vibe_coding_docker.py`, below), apart from steps the role
itself repeats: real dotfiles with an always-run script make the chezmoi
step run every time with both tools.

## Tests

- `tests/test_vibe_coding.py` (fake connector): config validation, the
  rendered files, `blockinfile` and `known_hosts` against the modules'
  rules, the user module's commands, the controller bundle with real git,
  a converged host (no command, no upload, the token in no log), the plan of
  a fresh arm64 host in the role's order, drift, refusals. With
  `OPS_LIBRARY_PATH`, the shipped templates must equal the role's. With
  `chezmoi` and `bash` on PATH (skipped otherwise), the real chezmoi runs the
  probe and the apply step against a temporary home with a git-repo external
  nobody can fetch: the apply succeeds and the probe then reports `current`.
- `tests/test_vibe_coding_docker.py` (skipped unless
  `VIBE_CODING_DOCKER_IMAGE` names an image built from
  `tests/integration/vibe_coding/Dockerfile`): real Ubuntu 24.04 containers
  with systemd and sshd, network access and a synthetic dotfiles repository
  (with a git-repo external nobody can fetch, which the deploys skip).
  A fresh host converges (user, files, chezmoi, gh, Node.js 22, Neovim,
  lazygit, rustup with rust-analyzer, an npm tool, zellij, the sshd block)
  and the repeat changes nothing; SSH logins as the user and as root work
  after the reload, root's effective sshd settings are unchanged. Drift: a
  new upstream commit, a changed chezmoi config, local modifications
  (refused), another origin (re-cloned), ownership, the GitHub login off,
  private keys, a candidate `sshd -t` rejects (nothing changed) and a failing
  reload (old file restored, ssh active). With `OPS_LIBRARY_PATH`, the role
  runs first with Ansible in the container and the deploy then changes
  nothing (the file tree's owners, modes and sizes are identical).

```bash
docker build -t ops-deploy-vibe-coding-port:local tests/integration/vibe_coding
VIBE_CODING_DOCKER_IMAGE=ops-deploy-vibe-coding-port:local OPS_LIBRARY_PATH=/abs/ops-library \
  uv run --locked pytest tests/test_vibe_coding_docker.py
```

The containers are named `ops-deploy-vibe-coding-<random>`, labelled
`ops-deploy.fixture=vibe-coding` and removed at the end.
