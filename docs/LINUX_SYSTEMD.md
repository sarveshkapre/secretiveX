# Linux systemd User Service

This project includes a Linux `systemd --user` unit template and install scripts for `secretive-agent`.

## Files

- `packaging/systemd/secretivex-agent.service.tmpl`
- `scripts/install_systemd_user_service.sh`
- `scripts/uninstall_systemd_user_service.sh`

## Install

Prerequisites:
- Linux with `systemd` user manager.
- `secretive-agent` binary available in `PATH` or explicit `--binary` path.

Install and start service:

```bash
./scripts/install_systemd_user_service.sh
```

Install with explicit binary/config:

```bash
./scripts/install_systemd_user_service.sh \
  --binary /usr/local/bin/secretive-agent \
  --config "$HOME/.config/secretive/agent.json"
```

Install only (do not start yet):

```bash
./scripts/install_systemd_user_service.sh --no-start
```

## What the install script does

1. Creates `~/.config/systemd/user` and `~/.config/secretive` if needed.
2. Creates a default config if missing.
3. Runs `secretive-agent --check-config` before installation.
4. Renders and installs a user unit.
5. Runs `systemctl --user daemon-reload`.
6. Enables and starts the service unless `--no-start` is set.

## Shell setup

Set `SSH_AUTH_SOCK` in shell startup files:

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/secretive/agent.sock"
```

## Operations

Status:

```bash
systemctl --user status secretivex-agent.service
```

Logs:

```bash
journalctl --user -u secretivex-agent.service -f
```

Restart:

```bash
systemctl --user restart secretivex-agent.service
```

## Uninstall

```bash
./scripts/uninstall_systemd_user_service.sh
```

Optional custom service name:

```bash
./scripts/uninstall_systemd_user_service.sh --service-name my-secretivex.service
```
