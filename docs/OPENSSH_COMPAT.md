# OpenSSH Compatibility Smoke

This project includes a smoke test for OpenSSH agent compatibility.

Script:
- `scripts/openssh_compat_smoke.sh`

CI workflow:
- `.github/workflows/openssh-compat-smoke.yml`
- Matrix: `ed25519`, `rsa`, `ecdsa` on Linux and macOS.
- Sign/verify checks run for `ed25519` and `ecdsa` by default (`OPENSSH_SIGN_KEY_TYPES`).

The smoke test validates three OpenSSH client flows against `secretive-agent`:

1. List identities via `ssh-add -L`
2. Sign/verify via `ssh-add -T <public-key>`
3. Error behavior via unsupported remove request `ssh-add -d <private-key>`

Run locally:

```bash
./scripts/openssh_compat_smoke.sh
```

Run a single key type:

```bash
OPENSSH_KEY_TYPES=rsa ./scripts/openssh_compat_smoke.sh
```

Control which key types must pass sign/verify:

```bash
OPENSSH_KEY_TYPES='ed25519,rsa,ecdsa' OPENSSH_SIGN_KEY_TYPES='ed25519,ecdsa' ./scripts/openssh_compat_smoke.sh
```
