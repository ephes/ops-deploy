"""Original Studio capable-work LaunchAgent: disabled and retired state only."""

from .config import VoiceMemoWorkConfig
from .deploy import apply_voice_memo_work_state

__all__ = ["VoiceMemoWorkConfig", "apply_voice_memo_work_state"]
