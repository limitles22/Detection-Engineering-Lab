# T1071.001 – Application Layer Protocol (HTTP)

## Overview
Emulación de Command and Control sobre HTTP usando PowerShell 
ejecutada con MITRE CALDERA.

## Attack Simulation
- Tool: MITRE CALDERA
- Technique: T1071.001
- LOLBIN: powershell.exe
- Behavior: HTTP requests with anomalous User-Agents

## Detection Logic
Esta detección se enfoca en comportamiento:
- PowerShell ejecutando web requests
- User-Agents atípicos o sospechosos

## Telemetry Used
- Sysmon (Event ID 1, 3, 11, 22)
- PowerShell Operational Logs (4103, 4104)
- Network traffic (HTTP)

## Sigma Rules
- psh_http_anomalous_user_agent.yml

## Tested With
-  Windows 10 / Sysmon
-  PowerShell ScriptBlock Logging enabled
-  Wazuh (converted rule)

## Notes
La detección prioriza visibilidad temprana de C2 por sobre artefactos secundarios.

