# Rust Benchmarking

`secretive-bench` is a lightweight load generator for the Rust agent.

## Basic usage

```bash
cargo run -p secretive-bench -- --concurrency 64 --requests 200
```

## JSON output

```bash
cargo run -p secretive-bench -- --concurrency 100 --requests 50 --json
```

## High fan-out simulation

```bash
cargo run -p secretive-bench -- \
  --concurrency 1000 \
  --requests 10 \
  --warmup 5 \
  --payload-size 128
```

## Reconnect per request

Use `--reconnect` to open a fresh connection for every sign request (closer to pssh fan-out).

```bash
cargo run -p secretive-bench -- \
  --concurrency 500 \
  --requests 5 \
  --reconnect
```

## Duration-based run

```bash
cargo run -p secretive-bench -- --concurrency 200 --duration 30
```

## Identity list benchmark

```bash
cargo run -p secretive-bench -- --concurrency 200 --requests 50 --list
```

## Reuse a key blob

Fetch a key once via `secretive-client --list --json` and pass the hex blob:

```bash
cargo run -p secretive-bench -- --concurrency 200 --requests 50 --key <hex_blob>
```

## RSA hash flags

Use `--flags` to exercise RSA SHA-256/512 flags (2 or 4 respectively).
