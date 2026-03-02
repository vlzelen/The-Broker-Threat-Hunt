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
<br>
<img width="900" height="846" alt="image" src="https://github.com/user-attachments/assets/a04e935d-e071-4ce2-bec5-85b99f1583bf" />
<br>
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
## 🚩15. Remote Tool
Reviewing the MDE process timeline shows execution of `AnyDesk.exe` shortly after reconnaissance activity. Defender also flags it as uncommon remote access software, indicating deployment of a legitimate remote administration tool for persistence and continued access.

<br>
<img width="896" height="845" alt="image" src="https://github.com/user-attachments/assets/7b552acf-3ab5-4a71-ab03-0a068bd79f32" />
<br>

**Task:** A legitimate remote administration tool was deployed for ongoing access.
**Question:** What software was installed?

<details>
<summary>Click to see answer</summary>

Answer: `AnyDesk`

</details>

---
## 🚩16. Remote Tool Hash
After confirming AnyDesk was deployed, I opened the file details within the Defender alert to fingerprint the binary. In the object details, the SHA256 hash is listed, which provides a unique identifier for the remote access tool used during the compromise.
<br>
<img width="392" height="718" alt="image" src="https://github.com/user-attachments/assets/92edb98a-2675-4637-952f-9b8064bfa467" />
<br>
**Task:** Identify the SHA256 hash of the remote access tool.
<br>
**Question:** What is the file hash?

<details>
<summary>Click to see answer</summary>

Answer: `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

</details>

---
## 🚩17. Download Method
To determine how AnyDesk was introduced, I reviewed the earliest execution events tied to its appearance in the process tree. The command line shows `cmd.exe /c certutil -urlcache -split -f https://download.anydesk.com/...`, indicating the use of a native Windows utility to retrieve the binary.
<br>
<img width="886" height="841" alt="image" src="https://github.com/user-attachments/assets/71cec2ee-e216-4e72-b44d-fd4d5a23c9f0" />
<br>
**Task:** The tool was downloaded using a native Windows binary.
<br>
**Question:** What binary/executable was used?

<details>
<summary>Click to see answer</summary>

Answer: `certutil.exe`

</details>

---
## 🚩18. Configuration Access
After AnyDesk execution, I continued reviewing the process timeline to see what files were accessed next. A `cmd.exe /c type` command shows the attacker reading a configuration file shortly after installation.
<br>
<img width="935" height="831" alt="image" src="https://github.com/user-attachments/assets/7169062b-2ebc-466f-ac80-25ec2bb3a8fd" />
<br>
**Task:** After installation, a configuration file was accessed.
<br>
**Question:** What is the full path of this file?

<details>
<summary>Click to see answer</summary>

Answer: `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

</details>

---
## 🚩19. Access Credentials
To determine whether unattended access was configured, I reviewed the command lines associated with AnyDesk.exe. A `cmd.exe /c` command shows the `--set-password` flag being used, indicating the attacker configured remote access credentials.
<br>
<img width="949" height="855" alt="image" src="https://github.com/user-attachments/assets/93ce0bf0-0c2f-472a-aef4-2d82c276b51e" />
<br>
**Task:** Unattended access was configured for the remote tool.
<br>
**Question:** What password was set?

<details>
<summary>Click to see answer</summary>

Answer: `intrud3r!`

</details>

---
## 🚩20. Deployment Footprint
Since AnyDesk was downloaded using certutil, I pivoted back to DeviceProcessEvents and queried for command lines containing both certutil and download.anydesk.com. This allowed me to identify all devices where the same download technique was used.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where ProcessCommandLine has_all ("certutil", "download.anydesk.com")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```
<br>
<img width="1621" height="532" alt="image" src="https://github.com/user-attachments/assets/fcb5b7a6-3269-4b97-ab50-d59a9f8e0ff9" />
<br>
**Task:** The remote tool was installed across the environment.
<br>
**Question:** List all hostnames where it was deployed.

<details>
<summary>Click to see answer</summary>

Answer: `as-pc1, as-pc2, as-srv`

</details>
# SECTION 6: LATERAL MOVEMENT
One host wasn't enough. The attacker moved through the environment, and not every method
worked the first time. Track the path they took, the tools they tried, the accounts they used,
and the order they moved.
---
## 🚩21. Failed Execution
To identify failed remote execution attempts, I queried **DeviceProcessEvents** across the affected hosts for common lateral movement tools such as `psexec`, `wmic`, `winrs`, and `schtasks`. Reviewing the command lines shows attempts using both **PsExec** and **WMIC** for remote process creation.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ProcessCommandLine has_any ("psexec", "wmic", "winrs", "sc \\\\", "Invoke-Command", "schtasks")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```
<br>
<img width="1624" height="591" alt="image" src="https://github.com/user-attachments/assets/a382e5fe-f46f-46a9-bce7-34577411b433" />
<br>
**Task:** The attacker attempted remote execution methods that failed.
<br>
**Question:** What two tools were tried?

<details>
<summary>Click to see answer</summary>

Answer: `PsExec.exe, WMIC.exe`

</details>

---
## 🚩22. Target Host
After identifying remote execution attempts using PsExec and WMIC, I reviewed the command lines to determine the intended target. The WMIC commands clearly reference /node:AS-PC2, indicating the remote system specified for process creation.
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ProcessCommandLine has_any ("psexec", "wmic", "winrs", "sc \\\\", "Invoke-Command", "schtasks")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```
<br>
<img width="1624" height="591" alt="image" src="https://github.com/user-attachments/assets/e1be8706-b1a6-457e-b766-8a2f536f930b" />
<br>
**Task:** Remote execution was attempted against a specific system.
<br>
**Question:** What hostname was targeted in the failed attempts?

<details>
<summary>Click to see answer</summary>

Answer: `as-pc2`

</details>

---
## 🚩23. Successful Pivot
After identifying failed WMIC and PsExec attempts, I shifted to **DeviceLogonEvents** to look for successful authentication activity. Filtering for `LogonSuccess` and reviewing the `LogonTyp` column shows **RemoteInteractive**, which aligns with successful RDP usage per Microsoft documentation.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, ActionType, AccountName, LogonType, Protocol, RemoteIP
| order by TimeGenerated desc
```

<br>
<img width="1622" height="731" alt="image" src="https://github.com/user-attachments/assets/12e4df71-08b4-49e9-b7ae-6151a95ce01a" />
<img width="862" height="752" alt="image" src="https://github.com/user-attachments/assets/c7507325-321c-41da-a323-71a14db9862f" />
<br>
**Task:** After failed attempts, a different method achieved lateral movement.
<br>
**Question:** What Windows executable was used?

<details>
<summary>Click to see answer</summary>

Answer: `mstsc.exe`

</details>

---
## 🚩24. Movement Path
Continuing through the MDE process timeline, I observed `net.exe localgroup administrators` executed shortly after other enumeration commands. This indicates the attacker was checking membership of the local privileged group to assess escalation or lateral movement opportunities.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "LogonSuccess"
| where LogonType == "Unlock"
| project TimeGenerated, DeviceName, ActionType, AccountName, LogonType, Protocol, RemoteIP
| order by TimeGenerated asc
```
<br>
 <img width="1287" height="505" alt="image" src="https://github.com/user-attachments/assets/dc9c4b7c-b3f6-4379-946f-ea21da19b2a0" />
<br>
**Task:** The attacker moved through the environment in a specific sequence
<br>
**Question:** What is the full lateral movement path?

<details>
<summary>Click to see answer</summary>

Answer: `as-pc1 > as-pc2 > as-srv`

</details>

---
## 🚩25. Compromised Account
To identify which credentials were used for the successful pivot, I used **DeviceLogonEvents** filtered to `LogonSuccess` events and projected the `AccountName` field. The results show the successful authentication associated with lateral movement.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "LogonSuccess"
| where LogonType == "Unlock"
| project TimeGenerated, AccountName, DeviceName, ActionType, LogonType, Protocol, RemoteIP
```
<br>
<img width="1619" height="377" alt="image" src="https://github.com/user-attachments/assets/0cfd54e7-cbe7-403f-946a-d0e43be985b4" />
<br>
**Task:** A valid account was used for successful lateral movement.
<br>
**Question:** What username authenticated successfully?
<details>
 
<summary>Click to see answer</summary>

Answer: `david.mitchell`

</details>
---

## 🚩26. Account Activation
To determine how the attacker enabled additional access, I reviewed `net.exe` Mirosoft Documentation.
<br>
[Microsoft Net user Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)#:~:text=Description-,/active%3A%7Bno%20%7C%20yes%7D,-Enables%20or%20disables)
<br>
<img width="867" height="135" alt="image" src="https://github.com/user-attachments/assets/0241756e-58b2-4883-b2e5-afd8e478e272" />
<br>
**Task:** A disabled account was enabled for further access.
<br>
**Question:** What net.exe parameter was used to activate the account?

<details>
<summary>Click to see answer</summary>

Answer: `/active:yes`

</details>

---
## 🚩27. Activation Context
To identify who enabled the account, I queried **DeviceProcessEvents** for command lines containing `/active:yes` across the compromised hosts. Projecting the `AccountName` field reveals the user context under which the `net.exe user Administrator /active:yes` command was executed.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where ProcessCommandLine has "/active:yes"
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<br>
<img width="1624" height="447" alt="image" src="https://github.com/user-attachments/assets/553029c7-2699-409d-9636-a8ab5f07115c" />
<br>
**Task:** The account activation was performed by a specific user.
<br>
**Question:** Who performed this action?

<details>
<summary>Click to see answer</summary>

Answer: `david.mitchell`

</details>
---
# SECTION 7: PERSISTENCE - SCHEDULED TASK
The attacker planted additional persistence beyond the remote tool. Scheduled tasks and
new accounts extend their access even if one mechanism is discovered and removed.

## 🚩28. Scheduled Persistence
To identify persistence, I queried **DeviceProcessEvents** for `schtasks.exe` executions across the compromised hosts. The command line shows `/create /tn MicrosoftEdgeUpdateCheck`, confirming a scheduled task was created to maintain access.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-17))
| where FileName == "schtasks.exe"
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| project InitiatingProcessCommandLine, ProcessCommandLine
```
<br>
<img width="1624" height="374" alt="image" src="https://github.com/user-attachments/assets/648c80a3-efb6-4f3e-a02b-6aec9cd26f7a" />
<br>
**Task:** A scheduled task was created for persistence.
<br>
**Question:** What is the task name?

<details>
<summary>Click to see answer</summary>

Answer: `MicrosoftEdgeUpdateCheck`

</details>
---

## 🚩29. Renamed Binary
After identifying the scheduled task, I reviewed the same `schtasks.exe /create` command to see what binary it was configured to run. The `/tr` argument points to `C:\Users\Public\RuntimeBroker.exe`, which is a suspicious location for a legimate Windows executable and suggests the payload was renamed to blend in.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-17))
| where FileName == "schtasks.exe"
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| project InitiatingProcessCommandLine, ProcessCommandLine
```
<br>
<img width="1624" height="374" alt="image" src="https://github.com/user-attachments/assets/4ce63ff9-4c34-40e5-8956-8ef29cdbeb88" />
<br>
**Task:** The persistence payload was renamed to avoid detection.
<br>
**Question:** What filename was used?

<details>
<summary>Click to see answer</summary>

Answer: `RuntimeBroker.exe`

</details>
---
## 🚩30. Persistence Hash
After identifying RuntimeBroker.exe as the scheduled task payload, I pivoted to DeviceFileEvents to fingerprint the file. Filtering on FileName == "RuntimeBroker.exe" and projecting SHA256 reveals the hash, which matches a previously identified payload in the investigation.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where FileName =~ "RuntimeBroker.exe"
| project TimeGenerated, DeviceName, FolderPath, FileName, SHA256
```
<br>
<img width="1625" height="471" alt="image" src="https://github.com/user-attachments/assets/3c233069-a0d6-4b4f-9720-f0d213ab061f" />

<br>
**Task:** The persistence payload shares a hash with another file in the investigation.
<br>
**Question:** What is the SHA256 hash?

<details>
<summary>Click to see answer</summary>

Answer: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

</details>
---

## 🚩31. Backdoor Account
Reviewing DeviceProcessEvents for `net.exe` executions containing the `/add` parameter reveals the creation of a new local account.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where FileName =~ "net.exe"
| where ProcessCommandLine has "/add"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<br>
<img width="1280" height="395" alt="image" src="https://github.com/user-attachments/assets/3dde2a7f-207d-42e5-842c-501aad740a1d" />
<br>
**Task:** A new local account was created for future access.
<br>
**Question:** What is the username?

<details>
<summary>Click to see answer</summary>

Answer: `svc_backup`

</details>
---

# SECTION 8: DATA ACCESS
The attacker found what they came for. Sensitive data was located, accessed, and staged for
extraction. Identify what was taken, where it was accessed from, and how it was packaged.

## 🚩32. Sensitive Document
To determine whether sensitive data was accessed after lateral movement, I reviewed **DeviceProcessEvents** for activity referencing the file server share (`\\as-srv\`).

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2")
| where AccountName in ("david.mitchell","svc_backup")
| where ProcessCommandLine has "\\\\as-srv\\"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<br>
<img width="1626" height="395" alt="image" src="https://github.com/user-attachments/assets/51ae51d9-112d-4503-815c-c267039fb4ae" />
<br>
**Task:** A sensitive document was accessed on the file server.
<br>
**Question:** What is the filename?

<details>
<summary>Click to see answer</summary>

Answer: `BACS_Payments_Dec2025.ods`

</details>
---

The attacker found what they came for. Sensitive data was located, accessed, and staged for
extraction. Identify what was taken, where it was accessed from, and how it was packaged.

## 🚩33. Modification Evidence
For `.ods` files, LibreOffice creates a lock file when the document is opened for editing. I used Google and AI to help me find the file artifact syntax.
<br>
<img width="1395" height="503" alt="image" src="https://github.com/user-attachments/assets/737fe77b-0528-4c37-b477-8067542aa3c9" />
<br>
**Task:** The document was opened for editing, not just viewing.
<br>
**Question:** What file artifact proves this?

<details>
<summary>Click to see answer</summary>

Answer: `.~lock.BACS_Payments_Dec2025.ods#`

</details>

---

## 🚩34. Access Origin
By querying **DeviceProcessEvents** and filtering on `ProcessCommandLine` containing `BACS_Payments_Dec2025.ods`, we can identify the host that opened the document. Projecting the DeviceName column shows the access originated from `as-pc2`.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ProcessCommandLine has_any ("BACS_Payments_Dec2025.ods")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<br>
<img width="1626" height="395" alt="image" src="https://github.com/user-attachments/assets/51ae51d9-112d-4503-815c-c267039fb4ae" />
<br>
**Task:** The document was accessed from a specific workstation.
<br>
**Question:** Which hostname accessed the file?

<details>
<summary>Click to see answer</summary>

Answer: `as-pc2`

</details>

---


## 🚩35. Exfil Archive
To determine whether data was staged for exfiltration, I searched **DeviceProcessEvents** for common archive utilities and compression commands such as `zip`, `7z`, `rar`, `tar`, and `Compress-Archive`.).

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ProcessCommandLine has_any ("zip","7z","rar","tar","Compress-Archive")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<br>
<img width="1617" height="499" alt="image" src="https://github.com/user-attachments/assets/311dc18a-5c07-47a4-837c-8d896503401d" />

<br>
**Task:** Data was archived before potential exfiltration
<br>
**Question:** What is the archive filename?

<details>
<summary>Click to see answer</summary>

Answer: `Shares.7z`

</details>

---


## 🚩36. Archive Hash
After identifying **Shares.7z** as the staged archive, I pivoted to **DeviceFileEvents** and filtered on `FileName == "Shares.7z"` to retrieve its SHA256 cryptographic fingerprint.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where FileName has "Shares"
| project TimeGenerated, DeviceName, FileName, SHA256
| order by TimeGenerated asc
```
<br>
<img width="1628" height="444" alt="image" src="https://github.com/user-attachments/assets/0c4c1ae7-3d16-49b5-8443-d088c958fabc" />
<br>
**Task:** Identify the SHA256 hash of the staged archive.
<br>
**Question:** What is the file hash?

<details>
<summary>Click to see answer</summary>

Answer: `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

</details>

---

# SECTION 9: ANTI-FORENSICS & MEMORY
Before leaving, the attacker tried to cover their tracks. Logs were cleared, binaries renamed,
and tools loaded in ways designed to avoid detection. Identify the anti-forensics techniques
and what evidence survived.

## 🚩37. Log Clearing
I switched back to the MDE timeline to look for evidence of defense evasion. I specifically searched for wevtutil.exe activity because I know that wevtutil is the built-in Windows Event Log Utility. It is commonly abused by attackers to clear event logs using the cl (clear log) parameter.

<br>
<img width="648" height="244" alt="image" src="https://github.com/user-attachments/assets/b9f66b2b-1e85-4b46-a4a1-da312e23ef51" />
<img width="627" height="236" alt="image" src="https://github.com/user-attachments/assets/b2883d5b-0988-4179-924a-51a99f132839" />
<br>
**Task:** The attacker cleared logs to cover their tracks.
<br>
**Question:** Name any two logs that were cleared.

<details>
<summary>Click to see answer</summary>

Answer: `System, Application`

</details>

---

## 🚩38. Reflective Loading
To identify evidence of reflective code loading, I queried the **DeviceEvents** table and summarized events by `ActionType` across the compromised hosts (`as-pc1`, `as-pc2`, `as-srv`) within the investigation timeframe. Reflective loading typically involves injecting or loading a module directly into memory without writing it to disk. The relevant ActionType observed in the results was: `ClrUnbackedModuleLoaded`.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| summarize Events=count() by ActionType
| order by Events asc
```
<br>
<img width="1622" height="424" alt="image" src="https://github.com/user-attachments/assets/201ee216-7e69-4cff-bf1a-d8f32ed3e2da" />
<br>
**Task:** Evidence of reflective code loading was captured.
<br>
**Question:** What ActionType recorded this activity?

<details>
<summary>Click to see answer</summary>

Answer: `ClrUnbackedModuleLoaded`

</details>

---

## 🚩39. Memory Tool
After identifying `ClrUnbackedModuleLoaded` as the ActionType associated with reflective loading, I refined the query to isolate those specific events:
- Table: **DeviceEvents**
- Filter: `ActionType == "ClrUnbackedModuleLoaded"`
- Scope: Compromised hosts (`as-pc1`, `as-pc2`, `as-srv`)
- Output: Included the `AdditionalFields` column
**SharpChrome** is a well-known credential theft tool designed to extract saved credentials from Chromium-based browsers. It is commonly executed in memory to evade disk-based detection, which aligns with the `ClrUnbackedModuleLoaded`. telemetry.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, ActionType, DeviceName, AdditionalFields
```
<br>
<img width="1626" height="428" alt="image" src="https://github.com/user-attachments/assets/9f01ff21-5a59-4943-b116-5158cac473d1" />
/>
<br>
**Task:** A credential theft tool was loaded directly into memory.
<br>
**Question:** What tool was used?

<details>
<summary>Click to see answer</summary>

Answer: `SharpChrome`

</details>

---

## 🚩40. Host Process
Now putting all the puzzle pieces togehter, to identify which legitimate process was hosting the in-memory credential theft tool, I filtered **DeviceEvents** using:
- ActionType == "ClrUnbackedModuleLoaded"
- AdditionalFields has "SharpChrome"
Then I projected the `InitiatingProcessFileName` column.

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-13) .. datetime(2026-01-17))
|where DeviceName in ("as-pc1","as-pc2","as-srv")
|where ActionType == "ClrUnbackedModuleLoaded"
|where AdditionalFields has "SharpChrome"
|project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, AdditionalFields
```
<br>
<img width="1628" height="385" alt="image" src="https://github.com/user-attachments/assets/d159ffc0-4eb4-465f-b494-8d544b4dcf66" />
<br>
**Task:** The credential theft tool was injected into a legitimate process.
<br>
**Question:** What process was hosting the malicious assembly?

<details>
<summary>Click to see answer</summary>

Answer: `notepad`

</details>
---

**Report Completed By:** Vlad Zelenskiy
**Status:** All 40 flags investigated and confirmed
