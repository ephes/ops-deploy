"""Loopback proxy that gives Home Assistant's voice bridge one warm OpenClaw session per day."""

from ops_deploy.services.voice_session_proxy.deploy import VoiceSessionProxyConfig, deploy_voice_session_proxy

__all__ = ["VoiceSessionProxyConfig", "deploy_voice_session_proxy"]
