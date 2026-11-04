"""open_webui: Open WebUI in a uv virtualenv behind Traefik (ports of open_webui_venv_deploy and _remove)."""

from ops_deploy.services.open_webui.deploy import OpenWebUIConfig, deploy_open_webui
from ops_deploy.services.open_webui.remove import OpenWebUIRemoveConfig, deploy_open_webui_remove

__all__ = ["OpenWebUIConfig", "OpenWebUIRemoveConfig", "deploy_open_webui", "deploy_open_webui_remove"]
