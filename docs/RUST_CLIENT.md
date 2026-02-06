# Rust Client CLI

`secretive-client` is a debug and diagnostics CLI for the Rust agent.

## Common usage

- List identities:
  - `secretive-client --list`
  - `secretive-client --list --json`
  - `secretive-client --list --json-compact`
- List with OpenSSH key strings:
  - `secretive-client --list --openssh`
- List with substring/fingerprint filtering:
  - `secretive-client --list --filter prod`
  - `secretive-client --list --filter SHA256:...`
- Sign data using a key blob:
  - `secretive-client --sign <key_blob_hex> --data ./payload.bin`
- Sign using comment/fingerprint selector:
  - `secretive-client --comment my-key --data ./payload.bin`
  - `secretive-client --fingerprint SHA256:... --data ./payload.bin`
- Health diagnostics:
  - `secretive-client --health`
  - `secretive-client --health --json`
  - `secretive-client --health --filter prod`
- Metrics snapshot inspection (from agent `metrics_output_path`):
  - `secretive-client --metrics-file /path/to/metrics.json`
  - `secretive-client --metrics-file /path/to/metrics.json --json`

## Health report fields

- `total_identities`: number of identities returned by agent.
- `valid_identities`: identities whose key blobs parsed as valid SSH public keys.
- `invalid_key_blobs`: identities with unparsable key blobs.
- `unique_key_blobs`: unique raw key blobs.
- `duplicate_key_blobs`: repeated key blob entries.
- `unique_fingerprints`: unique SHA256 key fingerprints among valid keys.
- `duplicate_fingerprints`: repeated fingerprints among valid keys.
- `duplicate_comments`: repeated comment entries.
- `algorithms`: per-algorithm identity counts.

## Socket and timeout controls

- `--socket <path>` overrides socket/pipe path.
- `--response-timeout-ms <n>` sets per-request timeout.
- `--response-timeout-ms 0` disables timeout.
