# Rust Agent Config

The Rust agent supports a JSON configuration file. You can point to it via `SECRETIVE_CONFIG` or `--config`.

## Top-level fields

- `socket_path` (string): override the Unix socket path or Windows named pipe.
- `stores` (array): ordered list of key stores to load.
- `max_signers` (number): optional cap for concurrent sign operations.

Legacy fields (used only when `stores` is not provided):
- `key_paths` (array of strings): explicit private key paths.
- `scan_default_dir` (bool): whether to scan `~/.ssh` for private keys.

## Store definitions

### File store

```json
{
  "type": "file",
  "paths": ["/Users/me/.ssh/id_ed25519"],
  "scan_default_dir": true
}
```

### Secure Enclave store (macOS, planned)

```json
{
  "type": "secure_enclave"
}
```

### PKCS#11 store (planned)

```json
{
  "type": "pkcs11",
  "module_path": "/usr/local/lib/your-pkcs11.so",
  "slot": 0,
  "pin_env": "PKCS11_PIN"
}
```

Note: PKCS#11 support is behind the `pkcs11` feature in `secretive-core`.
