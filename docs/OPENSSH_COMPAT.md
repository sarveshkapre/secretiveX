# OpenSSH Compatibility Smoke

This project includes a smoke test for OpenSSH agent compatibility.

Script:
- `scripts/openssh_compat_smoke.sh`

CI workflow:
- `.github/workflows/openssh-compat-smoke.yml`

The smoke test validates three OpenSSH client flows against `secretive-agent`:

1. List identities via `ssh-add -L`
2. Sign/verify via `ssh-add -T <public-key>`
3. Error behavior via unsupported remove request `ssh-add -d <private-key>`

Run locally:

```bash
./scripts/openssh_compat_smoke.sh
```
