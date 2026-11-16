---
name: homeguard
description: Run a defensive security self-audit of the user's own Mac, home LAN and project dependencies with the homeguard CLI, then explain the report and give prioritized fixes. Use when the user asks for a security self-check, whether their computer or home network has vulnerabilities, or whether their dependencies have known vulnerabilities. Only for assets the user owns or is authorized to test.
---

# homeguard security self-audit

## Rules (mandatory)

1. **Only audit the user's own assets.** Before any LAN scan, ask the user in one sentence to confirm that the range or devices belong to them or that they are authorized. Until the user confirms explicitly, do not run `homeguard lan` or `homeguard all` with `--lan`, and do not add `--i-own-these-targets` on their behalf.
2. Never scan public addresses, workplace networks, or devices on a neighbor's or public Wi-Fi. The tool refuses non-private ranges; do not try to work around that.
3. Never use the report to attempt exploitation, logins or password tests; only give remediation advice.
4. Changing system settings (turning on the firewall, disabling sharing) is the user's decision: give the steps and let the user perform them. Show commands that need sudo; do not run them.
5. The dependency check sends package name + version + ecosystem to api.osv.dev. If the user cares, use `--offline`.

## Steps

1. Check the install: the project root should contain `.venv/bin/homeguard`. If not, run
   `/usr/bin/python3 -m venv .venv && .venv/bin/pip install -U pip && .venv/bin/pip install -e .`
   (the system Python lets netstat see every listening port).
2. Pick the command for the request (always add `-f md,json --fail-on none` so the results are easy to read):
   - Local: `.venv/bin/homeguard local -f md,json --fail-on none`
   - LAN (after the user confirms ownership): use `ipconfig getifaddr en0` to help identify the range, then
     `.venv/bin/homeguard lan 192.168.x.0/24 --i-own-these-targets -f md,json --fail-on none`
     (add this flag only after the user has confirmed in the conversation)
   - Dependencies: `.venv/bin/homeguard deps <path> -f md,json --fail-on none`
3. Read the JSON report path printed at the end of the output and explain `summary` and `findings`:
   - Start with critical and high items in the fix-first list: what the risk is, what it means for this household, how to fix it;
   - Summarize medium and low items together; tell the user which `status = error` checks need manual verification;
   - Group LAN results by device (for example "the TV at 192.168.1.50 has ADB debugging enabled").
4. Give the user the HTML report path to open in a browser, and remind them the report contains home network details and should not be shared publicly.
