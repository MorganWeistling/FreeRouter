# Changelog

All notable changes to this project are documented in this file.

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
