# Changelog

All notable changes to this project are documented in this file.

## [1.7] - 2026-06-26
- Added: server `GET /proxy_health` endpoint — honest bulk throughput test of the active proxy via the real path (downloads 512 KB from Ubuntu through the proxy over SOCKS5+TLS). Detects "dead" proxies that accept connections and small requests but stall after ~17 KB on bulk transfer.
- Added: "Bulk test" (⚡) button in the client banner — runs the server-side health test and reports CLEAN/STALLED with downloaded KB, time and KB/s. Catches proxies the client-side speed test misses (client tests a different network path).

## [1.6] - 2026-06-26
- Changed: Redesigned client UI — modern card-based dark layout (Catppuccin), custom rounded Canvas buttons with hover states, accent strips, segmented RU/EN language toggle, section cards (Server / Proxy / Log), refined typography and spacing. No new dependencies.

## [1.5] - 2026-06-26
- Added: "Broadcasting" banner in the client showing the exit IP currently served to the router's devices and its geo (country / city / ISP), with a ⟳ refresh button and auto-refresh after Route / Check server.
- Added: server `GET /current_ip` endpoint — resolves the exit IP/geo by querying ip-api.com through the active proxy (using the credentials from config.json). Client falls back to local resolution if the endpoint is absent.

## [1.4] - 2026-06-25
- Added: Check cleanliness button in the Windows client — checks exit IP reputation via open sources (ip-api.com `proxy` / `hosting` / `mobile` flags) with a CLEAN / Datacenter / DIRTY verdict.
- Added: Speed & latency measurement (Cloudflare speed endpoint) reported on cleanliness check; last speed is stored in proxy history.

## [1.3] - 2026-06-25
- Added: Proxy history tab in the Windows client — stores used proxies with geo info (country, city, ISP, flag), colored status icons (✓/⚠/✗), and actions: Load, Check, Delete.
- Added: Auto-save to history on Route apply and on proxy check (with geo data).
- Added: Double-click on a history row loads the proxy into the main field.

## [1.2] - 2026-06-24
- Added: Check UDP button in the Windows client — tests SOCKS5 UDP ASSOCIATE support before routing.
- Added: UDP TProxy — QUIC/HTTP3 traffic is now proxied through SOCKS5 UDP ASSOCIATE instead of being dropped. Reduces fraud score on antidetect systems.
- Added: FakeIP mode via sing-box — DNS queries return fake IPs (198.18.0.0/15), hostname is sent to the proxy directly (no IP leaks through DNS).
- Added: DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) blocking — forces devices to use plain UDP DNS, which FakeIP intercepts.
- Added: MSS clamp 1280 and GRO/GSO/TSO offload disable on LAN interface.

## [1.1] - 2026-06-24
- Added: Support for UDP traffic when the upstream proxy supports UDP forwarding. If the configured proxy supports UDP relay, UDP traffic will be proxied; otherwise the project continues to handle TCP only.
