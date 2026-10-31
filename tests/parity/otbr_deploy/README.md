# OTBR Deploy Role

Deploy OpenThread Border Router (OTBR) from source on Ubuntu with systemd wiring and optional ZBT-2 udev rules. The role uses the upstream `ot-br-posix` scripts (`script/bootstrap`, `script/setup`) to install dependencies and build OTBR.

## Features

- Clones `openthread/ot-br-posix` and runs the upstream bootstrap/setup scripts.
- Manages `/etc/default/otbr-agent` with RCP + REST API settings.
- Enables and starts the `otbr-agent` systemd service (optionally `otbr-web`).
- Installs a ZBT-2 udev rule for consistent `dialout` permissions.

## Requirements

- Ubuntu 24.04 (or compatible) with `systemd` and `sudo`.
- ZBT-2 flashed with the OpenThread RCP firmware.
- Network access to fetch OTBR sources and build dependencies.

## Key Variables

| Variable | Default | Description |
| --- | --- | --- |
| `otbr_rcp_device` | `CHANGEME` | **Required.** Serial device path for the RCP (e.g. `/dev/serial/by-id/...`). |
| `otbr_infra_interface` | `""` | Backbone interface name (defaults to primary IPv4 interface when facts are available). |
| `otbr_rest_api_enabled` | `true` | Build and expose the REST API. |
| `otbr_rest_listen_address` | `127.0.0.1` | REST listen address (`0.0.0.0` for off-host Home Assistant). |
| `otbr_rest_listen_port` | `8081` | REST API port. |
| `otbr_web_enabled` | `false` | Build and run the `otbr-web` UI service. |
| `otbr_mdns` | `openthread` | mDNS provider (`openthread`, `avahi`, `mDNSResponder`). |
| `otbr_dhcp6_pd_client` | `none` | DHCPv6-PD client (`none`, `dhcpcd`, `openthread`). |
| `otbr_remove_bind` | `true` | Remove the `bind9` package installed by `script/bootstrap` to avoid DNS conflicts. |
| `otbr_manage_udev` | `true` | Install the ZBT-2 udev rule. |
| `otbr_force_rebuild` | `false` | Force a rebuild even if sources/config did not change. |

See `defaults/main.yml` for the full list of tunables.

## Example Usage

```yaml
- hosts: otbr_hosts
  become: true
  vars:
    otbr_rcp_device: "/dev/serial/by-id/usb-Espressif_..."
    otbr_infra_interface: "eno1"
    otbr_rest_listen_address: "0.0.0.0"
  roles:
    - role: local.ops_library.otbr_deploy
```

## Notes

- Changing build-related variables (REST/web enablement, mDNS backend, etc.) triggers a rebuild because the role records the build settings.
- Set `otbr_rest_listen_address` to a non-loopback address if Home Assistant runs on a different host.
- Use `otbr_force_rebuild: true` if you need to rebuild without changing config or source revision.
- `script/bootstrap` installs `bind9` by default; set `otbr_remove_bind: false` if you rely on BIND on the host, otherwise the role removes it.

## Testing

```bash
cd /path/to/ops-library
just test-role otbr_deploy
```

## Restart behavior

Build changes notify the existing restart handlers after deployment.
A rebuild (source checkout or build settings changed, or a forced rebuild) restarts otbr-agent and, when enabled, otbr-web. Runs without a rebuild do not request a restart.
The `otbr_restart_on_change` setting (default `true`) controls these handlers.
