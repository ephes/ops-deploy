"""Custom pyinfra operations shared by service deploys."""

from ops_deploy.ops.secret_file import secret_file, secret_stdin
from ops_deploy.ops.sync_tree import sync_tree

__all__ = ["secret_file", "secret_stdin", "sync_tree"]
