# Security policy

## Scope of use

homeguard is a **defensive** self-audit tool. Use it only on devices and networks you own, or that you have explicit authorization from the owner to test.

By design it does not include the following, and contributions adding them will not be accepted:

- exploitation, attack payloads, password brute-forcing or default-credential login attempts;
- scanning techniques that evade firewalls / IDS / EDR (fragmentation, spoofed sources, slow stealth scans);
- scanning public addresses or third-party assets (targets are restricted in code to private/local ranges).

## Reporting a vulnerability

If you find a security issue in homeguard itself (for example HTML injection in reports, or a way around the target range validation), please report it privately through GitHub Security Advisories on this repository instead of opening a public issue.
