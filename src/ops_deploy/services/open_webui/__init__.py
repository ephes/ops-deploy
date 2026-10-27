"""open_webui: Open WebUI in a uv virtualenv behind Traefik (port of the open_webui_venv_deploy role, deploy only)."""

from ops_deploy.services.open_webui.deploy import OpenWebUIConfig, deploy_open_webui

__all__ = ["OpenWebUIConfig", "deploy_open_webui"]
