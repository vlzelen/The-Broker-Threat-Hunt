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

## 🚩2. Payload Hash
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
With a foothold established, the attacker needed to talk back to their infrastructure. Outbound connections were made to a command and control server. Identify how the attacker maintained communication and where their infrastructure lives.
## 🚩6. C2 Domain
After confirming execution activity, the next step was to determine whether the payload established outbound communication. I pivoted to DeviceNetworkEvents on AS-PC1 and filtered for connections initiated by Daniel_Richardson_CV.pdf.exe and related processes within the compromise timeframe. Reviewing the RemoteUrl field revealed repeated outbound connections to a consistent external domain over ports 80 and 443, indicating command and control activity.

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

**Task:** The payload established outbound connections.
<br>
**Question:** What domain was used for command and control?

<details>
<summary>Click to see answer</summary>

Answer: `cdn.cloud-endpoint.net`

</details>

---

## 🚩7. C2 Process
After identifying the C2 domain, the next step was to determine which process initiated the outbound communication. Using the same DeviceNetworkEvents query, I projected the `InitiatingProcessCommandLine` field to isolate the originating process.
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
<img width="1618" height="542" alt="image" src="https://github.com/user-attachments/assets/9ea02c5c-c032-43bf-814d-8edb4fdb2176" />

**Task:** Identify the process responsible for C2 traffic.
<br>
**Question:** What process initiated the outbound connections?

<details>
<summary>Click to see answer</summary>

Answer: `"Daniel_Richardson_CV.pdf.exe"`

</details>

---

## 🚩8. Staging Infrastructure
Since the incident involved lateral movement, I widened scope beyond AS-PC1 to see where the same payload name appeared across other devices. Using **DeviceProcessEvents** for the January 14 to January 16 window and filtering on command lines containing “Daniel,” I found `certutil` downloads pointing to an external host, indicating payload staging.
<img width="1624" height="574" alt="image" src="https://github.com/user-attachments/assets/386b8725-215a-484f-a3aa-2037b42b9ade" />


**Task:** Additional payloads were hosted externally.
<br>
**Question:** What domain was used for payload staging?

<details>
<summary>Click to see answer</summary>

Answer: `sync.cloud-endpoint.net`

</details>

---

# SECTION 3: CREDENTIAL ACCESS
Credentials are the keys to the kingdom. The attacker went after stored secrets on the compromised host - targeting local credential stores and using in-memory techniques to extract authentication material. Determine what was targeted, how it was stolen, and who was doing it.
## 🚩9. Registry Targets
With credential access suspected, I searched **DeviceProcessEvents** for `reg.exe` executions during the compromise window. Filtering on command lines containing `save` revealed registry export activity initiated by powershell.exe on AS-PC1.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName =~ "as-pc1"
| where FileName =~ "reg.exe"
| where ProcessCommandLine has " save "
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1622" height="406" alt="image" src="https://github.com/user-attachments/assets/485256ff-fc2b-4acc-8e5c-68a411844ddf" />

**Task:** The attacker targeted local credential stores.
<br>
**Question:** What two registry hives were targeted? 

<details>
<summary>Click to see answer</summary>

Answer: `SAM, SYSTEM`

</details>

---

## 🚩10. Local Staging
After identifying the registry hive exports, I reviewed the same `reg.exe save` command lines to determine where the data was saved. The **ProcessCommandLine** field clearly shows both SAM and SYSTEM hives being saved to a local directory.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName =~ "as-pc1"
| where FileName =~ "reg.exe"
| where ProcessCommandLine has " save "
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1622" height="406" alt="image" src="https://github.com/user-attachments/assets/1413b578-381c-4ec0-a270-64eab4b51105" />

**Task:** Extracted data was saved locally before exfiltration.
<br>
**Question:** Where were the credential files saved?

<details>
<summary>Click to see answer</summary>

Answer: `C:\Users\Public\`

</details>

---

## 🚩11. Execution Identity
To determine the security context of the credential extraction, I projected `InitiatingProcessAccountName` and `AccountName` in the same `reg.exe save` query. The results show that both registry hive exports were executed under the compromised user session on AS-PC1.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName =~ "as-pc1"
| where FileName =~ "reg.exe"
| where ProcessCommandLine has " save "
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, AccountName
```
<img width="1621" height="409" alt="image" src="https://github.com/user-attachments/assets/f961afa5-0172-4bce-8d34-50ba37fc8fd5" />


**Task:** Credential extraction was performed under a specific user context.
<br>
**Question:** What user performed this action? 

<details>
<summary>Click to see answer</summary>

Answer: `sophie.turner`

</details>

---
# SECTION 4: DISCOVERY
Before moving deeper, the attacker needed to understand the environment. They ran
commands to figure out who they were, what was around them, and what they could reach.
Identify the reconnaissance activity and what intelligence the attacker gathered.

## 🚩12. User Context
After establishing access, the attacker began reconnaissance to confirm their execution context. Reviewing the MDE process timeline shows `whoami.exe` executed early in the sequence of commands.
<br>
<img width="879" height="865" alt="image" src="https://github.com/user-attachments/assets/684edf14-08fe-43fd-abe4-02b652744470" />
<br>
**Task:** The attacker confirmed their identity after initial access.
<br>
**Question:** What command was used?

<details>
<summary>Click to see answer</summary>

Answer: `whoami.exe`

</details>

---

## 🚩13. Network Enumeration
After confirming identity with `whoami.exe`, the attacker moved into network reconnaissance. Reviewing the MDE process timeline shows `net.exe view` executed shortly after other enumeration commands, indicating an attempt to discover available computer domains and shared resources.
<br>
<img width="1278" height="855" alt="image" src="https://github.com/user-attachments/assets/5f24b07f-9382-4604-b835-2095f19f1fd9" />
<br>

**Task:** The attacker enumerated network resources.
<br>
**Question:** What command was used to view available shares?

<details>
<summary>Click to see answer</summary>

Answer: `net.exe view`

</details>

---

## 🚩14. Local Admins
Continuing through the MDE process timeline, I observed `net.exe localgroup administrators` executed shortly after other enumeration commands. This indicates the attacker was checking membership of the local privileged group to assess escalation or lateral movement opportunities.
<img width="900" height="846" alt="image" src="https://github.com/user-attachments/assets/a04e935d-e071-4ce2-bec5-85b99f1583bf" />

**Task:** The attacker enumerated privileged local group membership.
<br>
**Question:** What group was queried?

<details>
<summary>Click to see answer</summary>

Answer: `administrators`

</details>

---
# SECTION 5: PERSISTENCE - REMOTE TOOL
The attacker wasn't planning a short visit. Multiple mechanisms were deployed to ensure
continued access - legitimate tools repurposed, tasks scheduled, accounts created. Map out
every backdoor they left behind.
## 🚩15. Planted Narrative / Cover Artifact

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
