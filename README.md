# Threat Hunt Report: The Broker

**Participant:** [REDACTED]  
**Date:** [REDACTED]

---

## Platforms and Languages Leveraged
- Log Analytics Workspaces (Microsoft Azure)
- Kusto Query Language (KQL)

## Scenario

October is known to be spooky, and this year is no different. In the first half of the month, an unfamiliar script surfaced in a user's Downloads directory. Not long after, multiple machines were found to start spawning processes originating from the Downloads folder as well. The machines were found to share the same types of files, naming patterns, and similar executables. The goal is to identify what the actor has compromised and to eradicate any persistence they may have established.

### High-Level IoC Discovery Plan
- Check `DeviceProcessEvents` to identify the suspicious machine, recon attempts in network and privileges.
- Check `DeviceFileEvents` to identify any security posture changes, consolidation of artifacts, and any planted narratives.
- Check `DeviceNetworkEvents` for any signs of outgoing connections and transfer attempts.

---

## Starting Point

We need to first find our starting point. Knowing that this issue started in the first half of October, we can establish a timeframe. Also, we can use `DeviceProcessEvents` to investigate what happened in the Downloads folder. In order to catch everything, we need to use `matches regex @"(?i)(..|..|..).*\.exe"` to see all regular expressions as a string, ignoring case sensitivity and ending in an `.exe`.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where ProcessCommandLine contains "Download"
| where ProcessCommandLine matches regex @"(?i)(desk|help|support|tool).*\.exe"
