# Técnicas MITRE ATT&CK

Esta carpeta contiene el análisis práctico de técnicas MITRE ATT&CK emuladas en laboratorio
y validadas desde el lado defensivo.

Cada técnica se trabaja siguiendo el mismo enfoque:

## Metodología
1. **Emulación ofensiva**
   - Uso de MITRE CALDERA para ejecutar la técnica en un endpoint Windows.
   - Ejecución controlada y trazable.

2. **Observación de telemetría**
   - Sysmon
   - PowerShell Operational Logs
   - Tráfico de red
   - Eventos ingeridos en SIEM (Wazuh)

3. **Diseño de detección**
   - Creación de reglas Sigma basadas en comportamiento.
   - Enfoque en patrones, no en herramientas específicas.

4. **Validación**
   - Conversión de la regla Sigma a Wazuh.
   - Confirmación de detección efectiva sobre la emulación real.

## Estructura
Cada carpeta de técnica incluye:

- `README.md`  
  Descripción de la técnica, emulación y telemetría observada.
- `detections/`  
  Reglas Sigma y reglas SIEM asociadas.
- `evidence/`  
  Evidencia visual de la emulación, logs y alertas generadas.

## Técnicas cubiertas
- **T1071.001** – Application Layer Protocol: Web Protocols  
  - Variante analizada: PowerShell (LOLBIN)

Este repositorio busca demostrar **detección basada en comportamiento**, desde la ejecución
real hasta su validación en un SIEM.


