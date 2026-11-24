---
title: "Sigma & Chainsaw in a Local WSL2 Lab: Fast Hunting Across Windows Enterprise EVTX Logs"
description: "Practical guide to run Sigma rules and Chainsaw locally via Docker on WSL2 to hunt across Windows Enterprise EVTX files without a full SIEM."
date: 2026-11-24
categoria: SOC
tags: [sigma, chainsaw, evtx, detection-as-code, docker, wsl2, open-source, soc]
nivel: Intermediário
draft: false
---

> **TL;DR:** During endpoint incident response, complete Windows logs may not always have been forwarded to your SIEM before the attack occurred. This guide shows how to combine open **Sigma** rules with **Chainsaw** locally on WSL2 (Windows Enterprise) to scan `.evtx` files in seconds for persistence, lateral movement, and defense *bypass*.

---

## 1. Why combine Sigma and Chainsaw in your SOC lab?

**Sigma** is the open standard for *Detection as Code*, describing vendor-agnostic detection logic in YAML. **Chainsaw** (built in Rust by WithSecure Labs) lets analysts run hundreds of Sigma rules directly against native Windows Event Log (`.evtx`) files on disk without standing up a full SIEM first.

Running this workflow locally in **WSL2** (or inside an offline Docker container) provides:
- High-speed forensic triage across `Security.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`, and `Sysmon.evtx`.
- Rule portability across production stacks (Wazuh, Elastic, or conversions to Microsoft Sentinel KQL).
- Complete local custody: incident logs never leave your workstation.

---

## 2. Prerequisites and Lab Architecture

| Component | Minimum Requirement | Notes |
|---|---|---|
| **Host OS** | Windows 10/11 Enterprise with WSL2 | Updated Ubuntu 22.04/24.04 distro in WSL2. |
| **Analysis Engine** | Chainsaw (Linux binary or Docker container) | Written in Rust; low memory footprint. |
| **Rule Set** | Official `SigmaHQ/sigma` repository | Open YAML rules mapped to MITRE ATT&CK. |

---

## 3. Setting Up an Isolated Environment in WSL2 & Docker

Create a dedicated directory in WSL2 for Sigma rules and exported `.evtx` files from test hosts:

```bash
mkdir -p ~/dfir-labs/chainsaw/evtx ~/dfir-labs/chainsaw/rules
cd ~/dfir-labs/chainsaw
```

Clone the official Sigma rule repository (or mount an already vetted offline copy):

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git rules/sigma
```

If you prefer running Chainsaw in a clean ephemeral container without installing Rust on the host, create a minimal `Dockerfile`:

```dockerfile
FROM rust:1.82-slim AS builder
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN cargo install chainsaw

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/chainsaw /usr/local/bin/chainsaw
WORKDIR /workspace
ENTRYPOINT ["chainsaw"]
```

Build the image locally:

```bash
docker build -t local/chainsaw:latest .
```

---

## 4. Copying Test EVTX Logs and Running a Hunt

On a Windows Enterprise test machine, copy event logs into your WSL2 workspace (from an elevated PowerShell prompt in your lab):

```powershell
Copy-Item "C:\Windows\System32\Winevt\Logs\Security.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
Copy-Item "C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" "\\wsl$\Ubuntu\home\$env:USERNAME\dfir-labs\chainsaw\evtx\"
```

Run the scan completely offline (`--network none`) using Windows Sigma rules:

```bash
docker run --rm --network none \
  -v ~/dfir-labs/chainsaw/evtx:/evtx:ro \
  -v ~/dfir-labs/chainsaw/rules/sigma:/sigma:ro \
  local/chainsaw:latest hunt /evtx \
  -s /sigma/rules/windows \
  --mapping /sigma/tools/config/generic/windows-audit.yml \
  --json --output /evtx/findings.json
```

> **Operational tip:** For quick terminal inspection instead of JSON output, omit `--json --output ...` and Chainsaw will print a structured ASCII table showing timestamps, Event IDs, triggered rules, and `CommandLine` / `TargetUserName`.

---

## 5. Custom Sigma Rule Example (Suspicious Scheduled Task)

You can author custom YAML rules under `~/dfir-labs/chainsaw/rules/custom/` to detect persistence via `schtasks.exe` (`MITRE ATT&CK T1053.005`):

```yaml
title: Scheduled Task Creation Pointing to Temp Directory
id: 7b4e1a20-8f12-4c9a-9c2e-11a2b3c4d5e6
status: experimental
description: Detects schtasks creating tasks that execute binaries inside AppData or Temp.
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\schtasks.exe'
  selection_cmd:
    CommandLine|contains|all:
      - '/create'
    CommandLine|contains:
      - '\AppData\'
      - '\Users\Public\'
      - '\Temp\'
  condition: selection_img and selection_cmd
level: high
tags:
  - attack.persistence
  - attack.t1053.005
```

The exact same YAML rule can later be converted to Wazuh or Microsoft Sentinel KQL using `sigma-cli`.

---

## 6. Control Mapping and Best Practices

| Framework | Reference | Practical Application |
|---|---|---|
| **MITRE ATT&CK** | `T1053.005` / `T1059.001` | Standardized detection of scheduled tasks and obfuscated PowerShell execution. |
| **NIST SP 800-86** | *Guide to Integrating Forensic Techniques into Incident Response* | Structured inspection of OS event logs during DFIR triage. |
| **CIS Controls v8** | `8.2` / `8.5` | Collecting and auditing detailed Windows process and security logs. |

---

## References

- [Microsoft Learn — Install WSL 2 on Windows Enterprise](https://learn.microsoft.com/en-us/windows/wsl/install)
- [Microsoft Learn — Advanced security auditing in Windows](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq)
- [SigmaHQ — Sigma Generic Signature Format](https://sigmahq.io/)
- [WithSecure Labs — Chainsaw EVTX Hunting Tool](https://github.com/WithSecureLabs/chainsaw)

