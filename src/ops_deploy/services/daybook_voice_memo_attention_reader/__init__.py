"""The original dedicated read-only Obsidian attention-reader identity."""

from .config import DaybookVoiceMemoAttentionReaderConfig, DaybookVoiceMemoAttentionReaderCredentials
from .deploy import install_daybook_voice_memo_attention_reader

__all__ = [
    "DaybookVoiceMemoAttentionReaderConfig",
    "DaybookVoiceMemoAttentionReaderCredentials",
    "install_daybook_voice_memo_attention_reader",
]
