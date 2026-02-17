# SecretiveX World-State Notes (2026-02-17)

This note tracks external ecosystem changes that affect SecretiveX roadmap decisions.

## External Signals

- OpenSSH 10.0 shipped in April 2025 and continued the move toward stronger default cryptography.
  - Source: [OpenSSH release notes](https://www.openssh.com/releasenotes.html)
- NIST finalized post-quantum standards in August 2024 (including ML-KEM / FIPS 203), driving upstream crypto migrations.
  - Source: [NIST PQC standards announcement](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- The Python `parallel-ssh` ecosystem remains active and commonly used for large fan-out automation.
  - Source: [parallel-ssh package page](https://pypi.org/project/parallel-ssh/)
- Windows OpenSSH guidance continues to focus on agent service hardening and strict ACL behavior.
  - Source: [Microsoft OpenSSH docs](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)

## Impact On SecretiveX

1. Keep fan-out defaults tuned for modern OpenSSH:
   - Keep `secretive-client --pssh-hints` aligned with hybrid post-quantum KEX guidance.
2. Expand compatibility gating:
   - Add OpenSSH 10.x matrix checks in CI alongside current list/sign smoke.
3. Prioritize token realism in PKCS#11:
   - Extend churn/latency validation on real HSMs/YubiKeys beyond SoftHSM smoke.
4. Tighten Windows hardening evidence:
   - Add host-level ACL validation artifacts for named-pipe service modes.
5. Raise stress targets:
   - Add repeatable 2k+ session stress profiles once 1k SLOs stay consistently green.

## Proposed Near-Term Additions

- OpenSSH 10.x compatibility gate lane.
- PKCS#11 real-token contention suite with queue-wait SLO assertions.
- Windows named-pipe ACL verification script + CI evidence upload.
- 2k-session staged fan-out soak profile (nightly, non-blocking at first).
