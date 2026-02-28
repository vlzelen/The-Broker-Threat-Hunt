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
```

[IMAGE_PLACEHOLDER_STARTING_POINT]

**Question:** Identify the most suspicious machine based on the given conditions

<details>
<summary>Click to see answer</summary>

Answer: `gab-intern-vm`

</details>

---

## 1. Initial Execution Detection

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_INITIAL_EXECUTION]

**Question:** What was the first CLI parameter name used during the execution of the suspicious program?

<details>
<summary>Click to see answer</summary>

Answer: `-ExecutionPolicy`

</details>

---

## 2. Defense Disabling

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName matches regex @"(?i)(tamper)"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_DEFENSE_DISABLING]

**Question:** What was the name of the file related to this exploit?

<details>
<summary>Click to see answer</summary>

Answer: `DefenderTamperArtifact.lnk`

</details>

---

## 3. Quick Data Probe

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "powershell"
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_CLIPBOARD]

**Question:** Provide the command value tied to this particular exploit.

<details>
<summary>Click to see answer</summary>

Answer: `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

</details>

---

## 4. Host Context Recon

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_RECON]

**Question:** Point out when the last recon attempt was.

<details>
<summary>Click to see answer</summary>

Answer: `2025-10-09T12:51:44.3425653Z`

</details>

---

## 5. Storage Surface Mapping

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where tolower(ProcessCommandLine) has_any ("net share", "net view", "dir /s", "Get-Volume", "Get-SmbShare", "wmic", "fsutil fsinfo drives", "Get-CimInstance -ClassName Win32_LogicalDisk")
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_STORAGE]

**Question:** Provide the 2nd command tied to this activity.

<details>
<summary>Click to see answer</summary>

Answer: `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

</details>

---

## 6. Connectivity and Name Resolution Check

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "curl", "Test-NetConnection", "tracert")
| where FileName contains "powershell" or FileName contains "cmd"
| where ProcessCommandLine has_any ("ping", "tracert", "nslookup")
| where IsProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessParentFileName, IsProcessRemoteSession
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_CONNECTIVITY]

**Question:** Provide the File Name of the initiating parent process.

<details>
<summary>Click to see answer</summary>

Answer: `RuntimeBroker.exe`

</details>

---

## 7. Interactive Session Discovery

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains ("qwi")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessUniqueId
```

[IMAGE_PLACEHOLDER_SESSION_DISCOVERY]

**Question:** What is the unique ID of the initiating process?

<details>
<summary>Click to see answer</summary>

Answer: `2533274790397065`

</details>

---

## 8. Runtime Application Inventory

**Question:** Provide the file name of the process that best demonstrates a runtime process enumeration event on the target host.

<details>
<summary>Click to see answer</summary>

Answer: `tasklist.exe`

</details>

---

## 9. Privilege Surface Check

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
| take 1
```

[IMAGE_PLACEHOLDER_PRIVILEGE]

**Question:** Identify the timestamp of the very first attempt.

<details>
<summary>Click to see answer</summary>

Answer: `2025-10-09T12:52:14.3135459Z`

</details>

---

## 10. Proof of Access and Egress Validation

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessFileName, RemoteUrl
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_EGRESS]

**Question:** Which outbound destination was contacted first?

<details>
<summary>Click to see answer</summary>

Answer: `www.msftconnecttest.com`

</details>

---

## 11. Bundling and Staging Artifacts

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| where FileName has_any ("zip")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_STAGING]

**Question:** Provide the full folder path value where the artifact was first dropped into.

<details>
<summary>Click to see answer</summary>

Answer: `C:\Users\Public\ReconArtifacts.zip`

</details>

---

## 12. Outbound Transfer Attempt

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-16))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessParentFileName
| order by TimeGenerated desc
```

[IMAGE_PLACEHOLDER_OUTBOUND]

**Question:** Provide the IP of the last unusual outbound connection.

<details>
<summary>Click to see answer</summary>

Answer: `100.29.147.161`

</details>

---

## 13. Scheduled Re-Execution Persistence

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated desc
```

[IMAGE_PLACEHOLDER_SCHEDULER]

**Question:** Provide the value of the task name down below.

<details>
<summary>Click to see answer</summary>

Answer: `SupportToolUpdater`

</details>

---

## 14. Autorun Fallback Persistence

[IMAGE_PLACEHOLDER_REGISTRY]

**Question:** What was the name of the registry value?

<details>
<summary>Click to see answer</summary>

Answer: `RemoteAssistUpdater`

</details>

---

## 15. Planted Narrative / Cover Artifact

```kql
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
```

[IMAGE_PLACEHOLDER_COVER_ARTIFACT]

**Question:** Identify the file name of the artifact left behind.

<details>
<summary>Click to see answer</summary>

Answer: `SupportChat_log.lnk`

</details>

---

## Summary Table

| Flag | Description | Value |
|------|-------------|-------|
| Start | Suspicious Machine | gab-intern-vm |
| 1 | 1st CLI parameter used in execution | -ExecutionPolicy |
| 2 | File related to exploit | DefenderTamperArtifact.lnk |
| 3 | Exploit command value | "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" |
| 4 | Last recon attempt | 2025-10-09T12:51:44.3425653Z |
| 5 | 2nd command tied to mapping | "cmd.exe" /c wmic logicaldisk get name,freespace,size |
| 6 | Initiating parent process file name | RuntimeBroker.exe |
| 7 | Initiating process unique ID | 2533274790397065 |
| 8 | Process inventory | tasklist.exe |
| 9 | 1st attempt timestamp | 2025-10-09T12:52:14.3135459Z |
| 10 | 1st outbound destination | www.msftconnecttest.com |
| 11 | Artifact 1st full folder path | C:\Users\Public\ReconArtifacts.zip |
| 12 | Unusual outbound IP | 100.29.147.161 |
| 13 | Task name value | SupportToolUpdater |
| 14 | Registry value name | RemoteAssistUpdater |
| 15 | Artifact left behind | SupportChat_log.lnk |

---

**Report Completed By:** [REDACTED]  
**Status:** All 15 flags investigated and confirmed
