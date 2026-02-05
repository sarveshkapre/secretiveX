# Windows Service Packaging

Use PowerShell scripts in `scripts/` to install/uninstall the SecretiveX agent as a Windows service:

- `scripts/install_windows_service.ps1`
- `scripts/uninstall_windows_service.ps1`

The service runs `secretive-agent` with explicit `--config` and `--socket` arguments and is configured for automatic restart on failure.
