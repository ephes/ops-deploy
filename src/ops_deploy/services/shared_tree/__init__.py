"""shared_tree: a directory tree that every member of one group may write (a shared media library).

Root owns the tree, the group can write, and setgid directories keep new
entries in the group; daemons that write there run with the group as their
(P)GID and ``UMASK=002``. Port of ops-control's ``playbooks/media/storage.yml``.
"""

from ops_deploy.services.shared_tree.deploy import SharedTreeConfig, deploy_shared_tree

__all__ = ["SharedTreeConfig", "deploy_shared_tree"]
