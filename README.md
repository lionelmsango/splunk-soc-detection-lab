# Splunk SIEM — SOC Detection Lab

**Deutsche Kurzbeschreibung:** Aufbau eines Security Operations Center in einer Lab-Umgebung mit Splunk Enterprise als SIEM. Angriffssimulation mit Atomic Red Team über vier MITRE ATT&CK-Techniken, Erkennung mit gezielten SPL-Abfragen, Threat Hunting und SOC-Dashboard-Entwicklung. Dokumentiert den vollständigen SOC-Analyst-Workflow: von der Angriffssimulation bis zur Alert-Konfiguration und proaktiven Bedrohungssuche.

---

## What This Project Is About

This is a full SOC detection workflow built from scratch. Splunk Enterprise on Ubuntu ingesting Sysmon logs from a Windows 11 endpoint, attack simulation with Atomic Red Team mapped to MITRE ATT&CK, SPL detection queries for each technique, a live alert, a custom dashboard, and three threat hunting scenarios.

The focus is the analyst work, not the infrastructure. The lab setup is mentioned briefly below, but every screenshot in this README comes from the attack simulation and investigation side.

---

---

## Architecture

![Lab Architecture](https://github.com/lionelmsango/splunk-soc-detection-lab/blob/35460b2b61afe820fbd0e3f256127d11e9dcdce0/screenshots/splunk_architecture.svg)
