# T1071.001 – Application Layer Protocol: Web Protocols

## Descripción
Esta técnica consiste en utilizar protocolos web (HTTP/HTTPS) como canal
de Command and Control.

## Emulación
- Herramienta: MITRE CALDERA
- Técnica ejecutada desde endpoint Windows
- PowerShell como LOLBIN
- Comunicación HTTP saliente con User-Agent anómalo

## Telemetría observada

### Sysmon
- Event ID 1 – Process Creation
- Event ID 3 – Network Connection
- Event ID 11 – File Creation

### PowerShell Logs
- Event ID 40962 – Engine Start
- Event ID 4103 – Command Invocation
- Event ID 4104 – Script Block Logging

### Network
- HTTP GET en texto claro
- User-Agent no estándar

## Detección
Se diseñó una regla Sigma enfocada en:
- PowerShell ejecutando comandos web
- User-Agents anómalos
- Contexto de proceso

## Resultado
La detección logró identificar directamente el canal de C2 sobre HTTP.
