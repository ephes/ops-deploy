"""Pinned MinIO deployment with explicit, bounded IAM ownership."""

from .config import (
    MinioBucket,
    MinioConfig,
    MinioCredentials,
    MinioIdentity,
    MinioPolicy,
    MinioSupersededPolicy,
    MinioUserCredentials,
)
from .deploy import deploy_minio

__all__ = [
    "MinioBucket",
    "MinioConfig",
    "MinioCredentials",
    "MinioIdentity",
    "MinioPolicy",
    "MinioSupersededPolicy",
    "MinioUserCredentials",
    "deploy_minio",
]
