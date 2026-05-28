# Splunk SIEM — SOC Detection Lab

**Deutsche Kurzbeschreibung:** Aufbau eines Security Operations Center in einer Lab-Umgebung mit Splunk Enterprise als SIEM. Angriffssimulation mit Atomic Red Team über vier MITRE ATT&CK-Techniken, Erkennung mit gezielten SPL-Abfragen, Threat Hunting und SOC-Dashboard-Entwicklung. Dokumentiert den vollständigen SOC-Analyst-Workflow: von der Angriffssimulation bis zur Alert-Konfiguration und proaktiven Bedrohungssuche.

---

## What This Project Is About

This is a full SOC detection workflow built from scratch. Splunk Enterprise on Ubuntu ingesting Sysmon logs from a Windows 11 endpoint, attack simulation with Atomic Red Team mapped to MITRE ATT&CK, SPL detection queries for each technique, a live alert, a custom dashboard, and three threat hunting scenarios.

The focus is the analyst work, not the infrastructure. The lab setup is mentioned briefly below, but every screenshot in this README comes from the attack simulation and investigation side.

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
