# WebMon

Lightweight, dependency-free system monitor written in C for Linux servers and embedded boards. Reads `/proc` for CPU, memory, disk, and network stats and serves a tiny web UI with a `/metrics` JSON endpoint.

## Requirements
- Linux with `/proc` available.
- POSIX C toolchain (`cc`/`gcc`/`clang`).

## Build and run (web-only)
- Build: `make build-c` (outputs `./webmon`).
- Run web UI + JSON: `make run` (alias for `make run-c`), then open `http://<host>:61080` (default host `127.0.0.1`).

CLI flags:
- `-i <seconds>`: sampling period (default `1.0`, minimum `0.1`).
- `-d <path>`: filesystem to report (default `/`).
- `-n <iface1,iface2>`: comma-separated interfaces to include; defaults to all non-loopback.
- `-H`, `-p`, `-r`: host (default `127.0.0.1`), port (default `61080`), and browser refresh interval (default `2.0` seconds).
- `-w <count>`: HTTP worker threads (default `2`, max `8`).
- `-t <token>`: shared token for HTTP auth (optional).

Auth notes:
- Start with `-t <token>` and open `http://<host>:61080/?token=<token>` in a browser.
- `/metrics` accepts `X-WebMon-Token: <token>` or the `?token=` query.

Displayed fields (auto-updated in-page with inline bars, no full refresh):
- Uptime and connected user count.
- CPU percent plus 1/5/15 minute load averages.
- Memory and swap usage with byte totals.
- Disk usage for the requested path.
- Per-interface network throughput (bytes/sec).

UI notes:
- Mobile-friendly layout with smaller typography on narrow screens.
- Dark/light themes auto-follow system preference (no manual toggle in UI).
