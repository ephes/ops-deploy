"""Native macOS Ollama Homebrew and launchd deployment and the role's removal."""

from .config import OllamaConfig
from .deploy import deploy_ollama
from .remove import OllamaRemoveConfig, remove_ollama

__all__ = ["OllamaConfig", "OllamaRemoveConfig", "deploy_ollama", "remove_ollama"]
