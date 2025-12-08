T1071.001 – Application Layer Protocol: Web Protocols
Descripción

La técnica T1071.001 consiste en el uso de protocolos web (HTTP/HTTPS) como canal de Command and Control (C2), aprovechando tráfico legítimo para camuflar la comunicación maliciosa.

Emulación

Herramienta: MITRE CALDERA

Plataforma: Windows

Uso de PowerShell como LOLBIN

Comunicación HTTP saliente iniciada desde el endpoint

Uso de User-Agents anómalos para eludir detecciones básicas

Telemetría observada

Sysmon

Event ID 1 – Process Creation

Event ID 3 – Network Connection

Event ID 11 – File Creation

PowerShell Operational Logs

Event ID 40962 – Engine Start

Event ID 4103 – Command Invocation

Event ID 4104 – Script Block Logging

Red

Tráfico HTTP GET en texto claro

User-Agent no estándar asociado a la ejecución de PowerShell

Detección

Se diseñó una regla Sigma basada en comportamiento, enfocada en:

Ejecución de comandos web desde PowerShell

Presencia de User-Agents poco comunes

Contexto del proceso y línea de comandos

Resultado

La detección logró identificar directamente el canal de C2 sobre HTTP, sin depender únicamente de artefactos secundarios, validando la efectividad de un enfoque basado en comportamiento.
