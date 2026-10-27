"""Native macOS Ollama Homebrew and launchd deployment."""

from .config import OllamaConfig
from .deploy import deploy_ollama

__all__ = ["OllamaConfig", "deploy_ollama"]
