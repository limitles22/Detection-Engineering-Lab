# Detection Engineering Lab

Este repositorio documenta un laboratorio práctico de detection engineering
basado en MITRE ATT&CK.

Las técnicas son emuladas utilizando MITRE CALDERA y validadas desde el
lado defensivo mediante correlación de:
- Sysmon
- PowerShell Operational Logs
- Telemetría de red
- SIEM (Wazuh)

## Objetivos
- Emular técnicas reales de adversarios
- Evaluar visibilidad defensiva
- Diseñar detecciones basadas en comportamiento (Sigma)
- Validar detecciones en SIEM

## Herramientas
- MITRE CALDERA
- Sysmon
- PowerShell Logging
- Wazuh
- Wireshark

## Técnicas analizadas
- T1071.001 – Application Layer Protocol: Web Protocols
- T1105 – Ingress Tool Transfer
