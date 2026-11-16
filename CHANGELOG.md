# Changelog

## 0.1.0 - 2026-11-16

First release.

- macOS local baseline: firewall / stealth mode, FileVault, SIP, Gatekeeper, OS version, automatic updates, screen lock, automatic login, guest user, sharing services and listening ports.
- LAN asset discovery (TCP probes + ARP table) with 30 weak-service rules (Telnet, ADB, Docker API, databases, RTSP cameras, ...) and SSH version risk detection.
- Dependency vulnerability check for requirements, Pipfile.lock, poetry.lock, uv.lock, package-lock.json, Cargo.lock and go.mod via OSV, with a built-in CVSS v3 calculator.
- Markdown / HTML / JSON reports with a fix-first list and an authorization record.
- Ownership confirmation before scanning; targets limited to private ranges with a size cap.
