# Threat Hunt Report: The Broker
<img width="1244" height="311" alt="image" src="https://github.com/user-attachments/assets/6482ac03-0a09-47f0-9993-d4bc5a471178" />


**Participant:** Vlad Zelenskiy  
**Date:** February 2026

---

## Platforms and Languages Leveraged
- EDR Platform: Microsoft Defender for Endpoint
- Log Analytics Workspaces (Microsoft Azure)
- Kusto Query Language (KQL)
- [SancLogic Ops](https://sanclogic.com/sanclogic-ops)
- [MITRE ATT&CK](https://attack.mitre.org/)

## Scenario
<img width="740" height="493" alt="image" src="https://github.com/user-attachments/assets/f06500c0-f2c1-4d8e-8f99-17edade0fabd" />
<br>
SancLogics Labs has received a high-severity alert from Microsoft Defender for Endpoint indicating that a compromised user account is conducting hands-on-keyboard activity on device AS-PC1. The alert suggests that valid credentials may have been obtained and are now being used to manually execute commands, potentially enabling lateral movement within the environment. As a Security Analyst at SancLogics Labs, I am responsible for investigating this incident, determining the scope of the compromise, identifying affected systems and accounts, and assessing whether the attacker established persistence or accessed sensitive resources.




### High-Level IoC Discovery Plan
- Check `DeviceProcessEvents` to identify interactive logon activity, suspicious command execution, credential abuse, and evidence of lateral movement originating from AS-PC1.
- Check `DeviceNetworkEvents` to detect outbound connections, internal reconnaissance, SMB/RDP activity, or potential command-and-control communication.
- Check `DeviceFileEvents` for injected tools, staging artifacts, privilege escalation utilities, or evidence of persistence mechanisms.

---

## Starting Point

We need to establish the initial access vector that led to the hands-on-keyboard activity on **AS-PC1**. Based on the alert details, the compromise occurred between January 14 and January 16, 2026. This timeframe will anchor our investigation.
The Microsoft Defender alert identifies AS-PC1 as the affected device and indicates that the compromised account is Sophie.Turner.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-14 00:00:00) .. datetime(2026-01-16 00:00:00))
| where InitiatingProcessAccountName == "sophie.turner"
| where DeviceName =~ "as-pc1"
```
---

# SECTION 1: INITIAL ACCESS
The attacker needed a way in. Something landed on an endpoint - whether it was clicked, downloaded, or delivered - and kicked off the entire compromise. Trace the infection back to its origin. Identify what arrived, how it executed, and what it spawned.
## 🚩1. Initial Vector
To begin the investigation, I needed to determine what originally triggered the compromise on AS-PC1. Since the alert indicated hands-on-keyboard activity tied to Sophie.Turner on January 14, 2026, I reviewed the Microsoft Defender for Endpoint timeline to establish a chronological sequence of events.
<br>
<img width="572" height="807" alt="image" src="https://github.com/user-attachments/assets/e7abf1a1-5710-42b0-ae86-80c3fdbf6668" />
<br>
I identified a suspicious process execution event occurring immediately before the PowerShell activity. The event showed that a PowerShell interpreter was launched by a file named **Daniel_Richardson_CV.pdf.exe**. The file immediately stood out because it used a double extension **(.pdf.exe)**, a common technique to disguise an executable as a document, and it directly spawned **powershell.exe**, which means it acted as the initial execution vector.

**Task:** Identify the file that started the infection chain.
<br>
**Question:** What is the filename?

<details>
<summary>Click to see answer</summary>

Answer: `Daniel_Richardson_CV.pdf.exe`

</details>

---

##🚩2. Payload Hash
After identifying **Daniel_Richardson_CV.pdf.exe** as the initial execution vector, the next step was to uniquely fingerprint the payload. Establishing a cryptographic hash allows us to track the file consistently across telemetry. Using the Microsoft Defender for Endpoint timeline, I navigated to the file’s Object details and collect the payload SHA256 hash.
<br>
<img width="606" height="712" alt="image" src="https://github.com/user-attachments/assets/20fb9870-1173-44ab-b7a7-9f4baa4b0dd3" />
<br>

**Task:** Identify the SHA256 hash of the initial payload.
<br>
**Question:** What is the file hash?

<details>
<summary>Click to see answer</summary>

Answer: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

</details>

---

## 🚩3. User Interaction
After identifying the malicious payload, the next step was to determine how it was actually executed. Using the Microsoft Defender timeline, I examined the process event entities event which revealed the full parent-child relationship with **explorer.exe**.
<br>
<img width="513" height="761" alt="image" src="https://github.com/user-attachments/assets/baec6e2f-5758-4f00-a809-886067cdbe0f" />
<br>

**Task:** Determine how the payload was initially launched.
<br>
**Question:** What parent process indicates the method of execution?

<details>
<summary>Click to see answer</summary>

Answer: `explorer.exe`

</details>

---

## 🚩4. Suspicious Child Process
The MDE timeline showed the payload spawning processes, but it was not detailed enough to isolate a single legitimate Windows child process. I pivoted to Advanced Hunting and queried **DeviceProcessEvents** on AS-PC1, filtering where the initiating process was Daniel_Richardson_CV.pdf.exe. The results were mostly cmd.exe and powershell.exe, but one legitimate Windows process was **"spawned"**.

```kql
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where TimeGenerated between (datetime(2026-01-15 03:50:00) .. datetime(2026-01-15 05:15:00))
| where InitiatingProcessFileName =~ "Daniel_Richardson_CV.pdf.exe"
| project TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine
```
<br>
<img width="1306" height="335" alt="image" src="https://github.com/user-attachments/assets/406051f0-8276-4f80-ac14-2e99db6aba24" />
<br>
**Task:** The payload created a child process for further activity.
<br>
**Question:** What legitimate Windows process was spawned?

<details>
<summary>Click to see answer</summary>

Answer: `notepad.exe`

</details>

---

## 🚩5. Process Arguments
After confirming the payload spawned `notepad.exe`, I used the same Advanced Hunting query results and focused on the **ProcessCommandLine** field to capture exactly how it was executed. Projecting ProcessCommandLine shows the full argument string as recorded in telemetry.
```kql
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where TimeGenerated between (datetime(2026-01-15 03:50:00) .. datetime(2026-01-15 05:15:00))
| where InitiatingProcessFileName =~ "Daniel_Richardson_CV.pdf.exe"
| project TimeGenerated, InitiatingProcessFileName, FileName, ProcessCommandLine
```
<br>
<img width="1304" height="333" alt="image" src="https://github.com/user-attachments/assets/6378403c-e815-4d8a-860d-9734af53638b" />
<br>

**Task:** The spawned process executed with unusual arguments.
<br>
**Question:** What was the full command line?

<details>
<summary>Click to see answer</summary>

Answer: `notepad.exe ""`

</details>

---

# SECTION 2:  COMMAND & CONTROL
With a foothold established, the attacker needed to talk back to their infrastructure. Outbound connections were made to adversary-controlled domains. Identify how the attacker maintained communication and where their infrastructure lives.
## 🚩6. C2 Domain
After confirming execution activity, the next step was to determine whether the payload established outbound communication. I pivoted to DeviceNetworkEvents on AS-PC1 and filtered for connections initiated by Daniel_Richardson_CV.pdf.exe and related processes within the compromise timeframe.

Reviewing the RemoteUrl field revealed repeated outbound connections to a consistent external domain over ports 80 and 443, indicating command and control activity.

```kql
DeviceNetworkEvents
| where DeviceName =~ "as-pc1"
| where TimeGenerated between (datetime(2026-01-14 00:00:00) .. datetime(2026-01-16 00:00:00))
| where ActionType in ("ConnectionSuccess","ConnectSuccess","HttpConnectionInspected")
| where InitiatingProcessFileName in~ ("Daniel_Richardson_CV.pdf.exe","notepad. exe","powershell.exe","cmd. exe","AnyDesk. exe")
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine,
RemoteUrl, RemoteIP, RemotePort, Protocol
| order by TimeGenerated asc
```
<img width="1305" height="684" alt="image" src="https://github.com/user-attachments/assets/15d36c68-4e46-4489-86e3-59b0e4e872e5" />


[IMAGE_PLACEHOLDER_CONNECTIVITY]

**Task:** The payload established outbound connections.
<br>
**Question:** What domain was used for command and control?

<details>
<summary>Click to see answer</summary>

Answer: `cdn.cloud-endpoint.net`

</details>

---

## 🚩7. Staging Infrastructure

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
