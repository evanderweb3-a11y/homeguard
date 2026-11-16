# homeguard

A **defensive** security self-audit tool for individuals and households. Use it to check your own Mac, the devices on your home network (TVs, tablets, NAS boxes, cameras, routers, ...) and the dependencies of your own projects. It produces HTML / Markdown / JSON reports with concrete remediation steps.

> ⚖️ **Authorized use only**
> Use homeguard only on devices, networks and code that **you own** or that you have **explicit written permission** from the owner to test.
> Scanning networks or devices without authorization is illegal in many jurisdictions.
> The tool enforces this in code: it only scans private/local address ranges, requires you to confirm ownership before scanning, and writes that confirmation into the report.
> You are responsible for how you use it; the authors accept no liability for misuse.

## What it checks

| Module | Command | Coverage |
|---|---|---|
| Local security baseline (macOS) | `homeguard local` | Application firewall and stealth mode, FileVault, SIP, Gatekeeper, macOS version, automatic updates (including security responses), App Store auto-update, screen lock password, automatic login, guest user, sharing services (SSH / File Sharing / Screen Sharing / Remote Management ...), externally listening ports, pending updates (optional) |
| LAN assets and weak services | `homeguard lan <range>` | Finds live devices via TCP probes plus the ARP table; 30 rules flag risky services such as Telnet, Android ADB debugging (common on TVs and set-top boxes), unauthenticated Docker API, Redis / MySQL / MongoDB and other databases, RTSP cameras, MQTT, SMB / NetBIOS, VNC / RDP, and plain-HTTP admin pages; reads SSH banners to flag versions affected by regreSSHion (CVE-2024-6387) |
| Known vulnerabilities in dependencies | `homeguard deps <path>` | Recursively finds `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `package-lock.json`, `Cargo.lock`, `go.mod`; batch-queries the [OSV](https://osv.dev) database; reports severity (built-in CVSS v3 calculator) and fixed versions |
| Reports | every command | Markdown / HTML (single file, dark-mode aware) / JSON, with a summary, a **fix-first list**, the authorization record, and per-finding evidence and fixes |

### What it deliberately does **not** do

- No exploitation, no attack payloads, no login, brute-force or default-password attempts;
- No stealth scanning or firewall / IDS evasion tricks;
- No scanning of public addresses or third-party assets (anything outside 10/8, 172.16/12, 192.168/16, 169.254/16 and 127/8 is refused; at most 1024 addresses per scan, hard maximum 4096);
- Local checks are read-only: they never change a system setting and never need sudo.

## Why a Python CLI rather than a pure Claude Code skill

Vulnerability checks need **repeatable, testable logic that runs in CI**: parsing system command output, concurrent port probing, calling OSV, computing CVSS scores. As code, all of that is covered by unit tests and does not depend on an AI improvising each time. So the core is a Python CLI with no third-party runtime dependencies (Python < 3.11 additionally needs `tomli`).

The repository also ships a Claude Code skill ([.claude/skills/homeguard/SKILL.md](.claude/skills/homeguard/SKILL.md)). Open Claude Code in this repository and ask for a security self-audit: Claude confirms target ownership first, then runs the CLI, explains the report and walks you through fixes in priority order. The two ways of using homeguard are independent.

## Installation

Requires macOS (for the local baseline) or Linux (LAN and dependency checks work), and Python 3.9+.

```bash
git clone https://github.com/<you>/homeguard.git
cd homeguard
/usr/bin/python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
```

> 💡 **Create the virtualenv with the system `/usr/bin/python3`.**
> On macOS, when homeguard runs under a Python that is not Apple-signed (for example one installed by uv or pyenv), privacy rules stop `netstat` from seeing other processes' sockets, so root services such as SSH or File Sharing go undetected. homeguard detects this and marks the result as "could not be fully verified", but the system Python gives complete results.

After installing, run `.venv/bin/homeguard`, or `source .venv/bin/activate` and use `homeguard` directly.

## Usage

```bash
# 1. Local security baseline
homeguard local

# 2. LAN (asks you to type "I confirm" to state the range is yours)
homeguard lan 192.168.1.0/24

#    Check specific ports on one device, e.g. the TV
homeguard lan 192.168.1.50 --ports 5555,8008,8080

#    Non-interactive use (cron etc.) needs an explicit declaration
homeguard lan 192.168.1.0/24 --i-own-these-targets

# 3. Dependencies (sends package name + version + ecosystem to api.osv.dev)
homeguard deps ~/code/my-project
homeguard deps ~/code/my-project --offline     # identify only, no network

# 4. Run everything from a config file
cp config.example.toml homeguard.toml          # edit ranges and paths
homeguard all

# Other
homeguard list-checks                          # list all checks and port rules
homeguard local -f md,html,json -o ~/Desktop/report
```

Common options:

| Option | Meaning |
|---|---|
| `-c, --config` | Config file (default: `./homeguard.toml`, then `~/.config/homeguard/config.toml`) |
| `-o, --output-dir` | Report directory, default `reports/` |
| `-f, --format` | Any combination of `md,html,json`, default `md,html` |
| `--fail-on` | Exit with code 1 if a problem at or above this severity exists (default `high`, `none` disables) - handy in scripts and CI |
| `--i-own-these-targets` | Declare that the targets are yours (skips the interactive prompt; recorded in the report) |
| `--ports` / `--timeout` / `--no-resolve` | Port list, per-port timeout, and disabling reverse DNS for LAN scans |
| `--offline` | Dependency check without network access |

Exit codes: `0` OK; `1` problems at or above `--fail-on`; `2` usage, authorization or configuration error.

### How authorization works

Before a LAN scan starts, homeguard checks, in order:

1. The target range is fully covered by `network.authorized_networks` in the config file - you declared it in advance;
2. `--i-own-these-targets` is on the command line - you declare it for this run;
3. In an interactive terminal it shows the authorization statement and asks you to type `I confirm` or `yes`;
4. Otherwise the scan is refused (exit code 2).

The confirmation method and time for every target are written to the "Scan authorization" section of the report.

## Example output

Terminal (excerpt; local results depend on the machine):

```text
$ homeguard all --deps examples --lan 127.0.0.1 --i-own-these-targets
> Local security baseline...
> LAN check: 127.0.0.1/32 (1 addresses)...
> Dependency check: examples (querying OSV)

Done: critical 1 · high 12 · medium 19 · low 2 · passed 12 · errors 0
  [Critical] minimist 1.2.5 has known vulnerability GHSA-xvch-5gv4-984h - examples/package-lock.json
  [High] Application firewall is enabled - this Mac
  [High] lodash 4.17.20 has known vulnerability GHSA-35jh-r3h4-6jhm - examples/package-lock.json
  [Medium] Sharing service open to the LAN: Remote Login (SSH) - this Mac
  ...
reports/homeguard-report-20261116-104537.md
reports/homeguard-report-20261116-104537.html
reports/homeguard-report-20261116-104537.json
```

Markdown report excerpt (item 3 illustrates a LAN finding; for a full example see [examples/sample-report.md](examples/sample-report.md), generated by `homeguard deps examples`):

```markdown
## Fix first

1. **[Critical] minimist 1.2.5 has known vulnerability GHSA-xvch-5gv4-984h** - examples/package-lock.json
   - Fix: Upgrade minimist from 1.2.5 to a fixed version: 1.2.6, 0.2.4
2. **[High] Application firewall is enabled** - this Mac
   - Fix: System Settings > Network > Firewall > turn on. Command line: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
3. **[High] Android ADB debugging service open (port 5555)** - 192.168.1.50 (tv.lan)
   - Fix: Turn it off after debugging: device Settings > Developer options > disable network/USB debugging
```

Check titles describe the **expected** state (for example "Application firewall is enabled"); a status of "Fail" means the machine does not currently meet it.

> 🔒 Reports contain your devices' IPs, MACs, host names and security posture. `reports/` is in `.gitignore`; do not commit reports to a public repository.

## Configuration

See [config.example.toml](config.example.toml); every key is commented. Copy it to `homeguard.toml` (ignored by git) and edit.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest            # unit tests (no network, no real scanning)
.venv/bin/ruff check .      # lint
.venv/bin/ruff format .     # format
```

Layout:

```text
src/homeguard/
├── cli.py              # entry point and orchestration (validate and authorize first, then scan)
├── consent.py          # scan authorization
├── config.py           # TOML config loading
├── models.py           # Finding / ScanResult, severities and statuses
├── runner.py           # read-only system command runner (replaceable in tests)
├── osv.py              # OSV API client, CVSS v3 calculator
├── report.py           # Markdown / HTML / JSON reports
└── checks/
    ├── macos.py        # local baseline checks
    ├── network.py      # target validation, discovery, port probes, banners
    ├── services.py     # port risk rules and SSH version assessment
    └── deps.py         # lock file parsing and dependency vulnerability check
tests/                  # pytest; system commands and network are simulated
examples/               # intentionally vulnerable demo dependencies and a sample report
.claude/skills/homeguard/SKILL.md   # Claude Code skill
.github/workflows/ci.yml            # CI: ruff + macOS/Ubuntu x Python 3.9/3.11/3.13 + CLI smoke test
```

To add a port rule, append a `ServiceRule` to `_RULE_LIST` in `checks/services.py`. To add a local check, write `check_xxx(runner, opts)` in `checks/macos.py`, add it to `CHECKS`, and cover both the passing and failing output with `FakeRunner` in `tests/test_macos.py`.

## Known limitations

- TCP only; UDP services (UPnP SSDP 1900, mDNS, ...) are not covered;
- Weak-service findings are based on "port open + banner the service sends"; homeguard never logs in, so there can be false positives (for example an open port that already has a strong password);
- Linux distributions often backport security fixes without changing the version number, so treat SSH version warnings with your distribution's advisories in mind;
- The dependency check only covers pinned dependencies in lock files; entries like `flask>=2` are listed separately as a reminder;
- The local baseline currently supports macOS only.

## License

[MIT](LICENSE)
