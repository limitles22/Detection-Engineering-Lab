## Evidence – T1071.001

Esta evidencia documenta la ejecución completa de la técnica **T1071.001 – Application Layer Protocol: Web Protocols**,
desde la emulación ofensiva hasta la detección en SIEM.

### 1. Emulación en CALDERA
Se ejecutó una ability utilizando PowerShell para generar tráfico HTTP saliente,
simulando comunicación de Command and Control mediante User-Agent anómalo.

![CALDERA Execution](img/01_caldera.png)

### 2. PowerShell Script Block Logging
Se observa el **Event ID 4104**, donde queda registrado el contenido del script
con múltiples ejecuciones de `Invoke-WebRequest` y User-Agents no estándar.

![PowerShell 4104](img/02_powershell_4104.png)

### 3. Actividad de red (Sysmon)
Sysmon registra la conexión de red saliente iniciada por `powershell.exe`,
confirmando tráfico HTTP hacia un destino externo.

![Sysmon Network](img/03_sysmon_network.png)

### 4. Detección en Wazuh
La regla personalizada en Wazuh dispara una alerta correlacionando
proceso, comando y User-Agent anómalo, detectando directamente
la técnica **T1071.001**.

![Wazuh Alert](img/04_wazuh_alert.png)

### Conclusión
La correlación entre telemetría de host, logs de PowerShell y SIEM permitió
identificar de forma confiable el uso de HTTP como canal de C2,
validando la detección de la técnica T1071.001.

