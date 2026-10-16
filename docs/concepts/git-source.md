# Git source

A service's code can come from its git remote at a given ref instead of a
developer checkout. ops-deploy fetches it **on the controller**, with the
operator's own git and SSH setup, and the deploy syncs the fetched tree like
any local checkout. Hosts never talk to the git remote and need no deploy keys
or other credentials.

```python
from pathlib import Path
from ops_deploy.core.git_source import GitSource, fetch_source

tree = fetch_source(GitSource(repo="git@github.com:owner/app.git", ref="main"), workdir / "tree")
source = SourceSpec(path=tree.path, commit=tree.commit, ...)  # django_site
```

## `fetch_source`

`fetch_source(source, dest)` creates `dest` (it must not exist), runs
`git init` there, resolves the ref on the remote (`git ls-remote`) and makes a
shallow fetch of that one full ref name (`git fetch --depth=1 --no-tags`),
then checks out the fetched commit detached and returns a
`SourceTree(path, commit)`. The caller owns `dest` and removes it after the
run.

- **Ref.** `GitSource.ref` is a branch, a tag (annotated tags resolve to their
  commit) or a full 40-character commit id; `None` fetches the remote's `HEAD`,
  its default branch. Abbreviated ids, revision syntax (`HEAD~1`, `main@{1}`),
  refspecs (`a:b`, `+a`) and option-like names are refused when the config is
  built.
- **Fails closed.** A ref the remote does not have, a name that is both a
  branch and a tag (give the commit instead), a fetched commit other than the
  full id asked for, a checkout `git status` does not report clean, or a file
  whose bytes or executable bit differ from its committed blob raises
  `GitSourceError` before any connection to a host.
- **Files exactly as committed.** `.git/info/attributes` (which overrides the
  tree's `.gitattributes`) switches off filters, line-ending conversion,
  `ident` and `working-tree-encoding`, and every file is then hashed and
  compared with its blob. Git LFS pointers and submodules are refused: the
  deploy would ship a pointer or an empty directory.
- **No credentials.** `GitSource.repo` is `user@host:path` or an `ssh://`,
  `https://` or `file://` URL; a URL with a password or (for `https`) any user
  part is refused, so no message or log line can show a token. Validation
  errors never echo the value. Authentication is whatever the operator's git
  uses: the SSH agent and `~/.ssh/config`, or a credential helper for `https`.
  git runs with `GIT_TERMINAL_PROMPT=0`, so a missing credential fails instead
  of prompting.
- **Nothing from the operator's setup runs.** The repository is created
  without a template and git runs with `core.hooksPath=/dev/null` and
  `core.autocrlf=false`, so no hook runs and line endings are the committed
  ones.
- The runner is injectable (`GitRunner`, default `subprocess_git_runner`), like
  `sync_tree`'s rsync runner.

## Recording the deployed commit

A service that supports a git source has a `source_commit` field (a full
commit id, or `None` for a local working tree). Its deploy ends, after the
health checks, with `record_source(site_path, commit, user=..., group=...)`
from `ops_deploy.helpers`:

- with a commit, `<site_path>/.ops-deploy-source` holds that id (one line,
  `0644`, owned by the service user). Writing the same id again is no change,
  so a re-run of the same ref is a no-op from the first operation to the last;
- with `None`, the file is removed: a local working tree has no commit, and a
  stale record would name code that is no longer deployed.

`sync_tree` never transfers or deletes `.ops-deploy-*`, so the file survives
every sync. An Ansible deploy (rsync from a checkout) does not know about it
and leaves it in place: after one, the record names the last git-source deploy,
not necessarily the running code.

Because `sync_tree` compares content, not times, the fetched tree (all files
new) changes nothing on a host that already runs the same code, whichever way
that code got there.

Services with a git source: [django_site](../services/django_site.md)
(`SourceSpec.commit`; marina, heis), [heis](../services/heis.md) and
[graphyard](../services/graphyard.md).

## Why not clone on the host

The Ansible roles' `git` deploy method (`nyxmon_deploy`, `fastdeploy_deploy`
and others) clones on the host, which needs read access to the repository
from every host: a deploy key per repository (GitHub allows a key on one
repository only) installed on the host and kept out of backups, or a
credential with access to several repositories, plus a known_hosts entry for
the git server. A private repository owned by someone else (heis) needs that
owner to add the key. Rotating or revoking them is per host and per
repository.

The controller-side fetch needs none of that: it uses the access the operator
already has, the host only receives files over the SSH connection the deploy
uses anyway, and the deploy cannot leave credentials behind. A host-side clone
becomes relevant only when something other than an operator's machine deploys
(FastDeploy running pyinfra, Phase 9 of the port). Even then the controller
fetch still works if FastDeploy's host holds the read credential; a clone on
every target host would only be needed if targets must pull on their own.
