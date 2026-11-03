"""Pinned RustFS (single node, single disk) with declarative buckets and IAM."""

from .config import (
    RUSTFS_ARTIFACTS,
    RUSTFS_VERSION,
    RustfsBucket,
    RustfsConfig,
    RustfsCredentials,
    RustfsIdentity,
    RustfsPolicy,
    RustfsUserCredentials,
)
from .deploy import deploy_rustfs

__all__ = [
    "RUSTFS_ARTIFACTS",
    "RUSTFS_VERSION",
    "RustfsBucket",
    "RustfsConfig",
    "RustfsCredentials",
    "RustfsIdentity",
    "RustfsPolicy",
    "RustfsUserCredentials",
    "deploy_rustfs",
]
