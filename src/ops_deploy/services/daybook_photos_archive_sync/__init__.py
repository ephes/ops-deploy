"""Original single-writer archive component declarations."""

from .config import DaybookPhotosArchiveSyncConfig
from .deploy import install_daybook_photos_archive_sync

__all__ = ["DaybookPhotosArchiveSyncConfig", "install_daybook_photos_archive_sync"]
