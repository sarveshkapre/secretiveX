# Self-Hosted GitHub Actions Runners

This repository is configured to run CI jobs on self-hosted runners only.
No GitHub-hosted billing changes are required.

## 1. Register A Runner (Repository Scope)

1. Open `https://github.com/sarveshkapre/secretiveX/settings/actions/runners`.
2. Click **New self-hosted runner**.
3. Pick your OS (`Linux`, `macOS`, or `Windows`).
4. Copy and run the generated commands on your machine:
   - create runner directory
   - download runner package
   - `./config.sh --url https://github.com/sarveshkapre/secretiveX --token <TOKEN>`
   - `./run.sh` (or install service mode)

Service mode is recommended for reliability:
- Linux: `sudo ./svc.sh install && sudo ./svc.sh start`
- macOS: `./svc.sh install && ./svc.sh start`
- Windows: `.\svc install` then `.\svc start`

## 2. Required Tooling By Platform

## Common (all self-hosted runners)

- `git`
- Rust toolchain (`cargo`, `rustfmt`, `clippy`)
- `ssh-keygen`
- POSIX shell tools (`sh`, `awk`, `sed`)

## macOS runner (Swift + release/nightly workflows)

- Xcode + command line tools (`xcodebuild`, `xcrun`)
- Optional release tooling: `notarytool`, `gh`
- Default Xcode path expected: `/Applications/Xcode_26.2.app`
  - override with `XCODE_PATH` environment variable if different

## Linux runner (Rust + PKCS#11 smoke)

- `softhsm2` (`softhsm2-util`)
- `opensc` (`pkcs11-tool`)

The CI helper script installs Linux/macOS PKCS#11 deps when possible:
- `.github/scripts/install_pkcs11_deps.sh`

## Windows runner (named-pipe smoke workflow)

- PowerShell (`pwsh`)
- OpenSSH client tools (`ssh-keygen`)
- Rust toolchain

## 3. Preflight Checks

Run preflight locally:

```bash
./scripts/self_hosted_runner_preflight.sh all
```

Profile-specific checks:

```bash
./scripts/self_hosted_runner_preflight.sh macos
./scripts/self_hosted_runner_preflight.sh linux
./scripts/self_hosted_runner_preflight.sh windows
```

## 4. End-To-End Local CI Validation

Run the local self-hosted CI validation script:

```bash
./scripts/self_hosted_ci_validate.sh
```

What it covers:
- shell/repo sanity
- Rust lint/tests
- OpenSSH smoke + fan-out gates (scaled for local execution)
- PKCS#11 smoke (when tools are present)
- macOS Swift tests (when running on macOS)

## 5. Workflow Behavior Notes

- All jobs now use `runs-on: self-hosted`.
- macOS-only workflows (`test`, `nightly`, `oneoff`, release jobs) skip cleanly on non-macOS runners.
- Windows named-pipe smoke skips cleanly on non-Windows runners.
- PKCS#11 smoke uses an explicit dependency installer script for self-hosted machines.
