## T1071.001 – Application Layer Protocol: Web Protocols

### Descripción
Esta técnica consiste en el uso de protocolos web (HTTP/HTTPS) como canal de **Command and Control (C2)**, buscando camuflar el tráfico malicioso dentro de comunicaciones web legítimas.

### Emulación
- **Herramienta:** MITRE CALDERA  
- **Sistema objetivo:** Endpoint Windows  
- **Ejecución:** PowerShell como LOLBIN  
- **Comportamiento:** Comunicación HTTP saliente utilizando User-Agents anómalos  

### Telemetría observada

#### Sysmon
- Event ID 1 – Process Creation  
- Event ID 3 – Network Connection  
- Event ID 11 – File Creation  

#### PowerShell – Operational Logs
- Event ID 40962 – Engine Start  
- Event ID 4103 – Command Invocation  
- Event ID 4104 – Script Block Logging  

#### Red
- Tráfico HTTP observado mediante **Wireshark**
- Solicitudes HTTP GET en texto claro hacia infraestructura C2
- Uso de **User-Agents** no estándar
- Identificación de un **patrón de beaconing** (intervalos regulares de comunicación)
 

### Detección
Se diseñó una regla Sigma enfocada en:
- Ejecución de comandos web desde PowerShell  
- Presencia de User-Agents anómalos  
- Contexto del proceso y línea de comandos  

### Resultado
La detección permitió identificar directamente el uso de HTTP como canal de C2 durante la ejecución, demostrando la efectividad de detecciones basadas en comportamiento y no únicamente en artefactos secundarios.
