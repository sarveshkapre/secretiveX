# Windows Service Setup

SecretiveX can run as a Windows service using the provided PowerShell scripts.

## Prerequisites

- Run PowerShell as Administrator.
- Build or install `secretive-agent.exe`.
- Prepare an agent config JSON file.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_windows_service.ps1 `
  -BinaryPath "C:\secretivex\secretive-agent.exe" `
  -ConfigPath "C:\secretivex\agent.json" `
  -ServiceName "SecretiveXAgent" `
  -PipeName "\\.\pipe\secretive-agent"
```

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall_windows_service.ps1 `
  -ServiceName "SecretiveXAgent"
```

## Pipe hardening notes

- Agent named pipes reject remote clients (`reject_remote_clients=true`).
- Agent attempts to claim the first pipe instance on startup to reduce pipe-precreation attacks.
- Keep the pipe name stable and run only one service instance per pipe.
