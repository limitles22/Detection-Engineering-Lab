# T1059.001 – PowerShell

## Descripción

Esta carpeta documenta la emulación y el análisis de la técnica  
**T1059.001 – Command and Scripting Interpreter: PowerShell** del framework
MITRE ATT&CK.

La definición formal de la técnica puede consultarse en:
https://attack.mitre.org/techniques/T1059/001/

El laboratorio se centra en observar el comportamiento generado por la
ejecución de PowerShell en un sistema Windows y en extraer conclusiones
desde una perspectiva defensiva.

---

## Objetivo del laboratorio

- Emular la técnica T1059.001 en un entorno controlado
- Analizar la telemetría y evidencia generada en el endpoint
- Identificar oportunidades de detección basadas en comportamiento
- Documentar conclusiones relevantes para seguridad y detección

---

## Emulación de la técnica

La técnica es emulada utilizando **CALDERA** sobre un sistema Windows.

Los detalles de la ejecución, incluyendo la habilidad utilizada y los
parámetros de la emulación, se documentan en la carpeta `emulation/`.

---

## Evidencia observada

Durante la emulación se observa evidencia asociada al uso de PowerShell,
incluyendo:

- Creación de procesos relacionados con PowerShell
- Parámetros de línea de comando utilizados
- Eventos de ejecución y logging
- Relación proceso padre / proceso hijo

El análisis detallado de la evidencia se encuentra documentado en la
carpeta `evidence/`.

---

## Detección

A partir de la evidencia observada se desarrollan ideas de detección
basadas en comportamiento y contexto.

Estas ideas se presentan de forma conceptual y deben ser adaptadas antes
de ser utilizadas en entornos productivos.  
El detalle se encuentra en la carpeta `detection/`.

---

## Mitigaciones

Se describen mitigaciones y controles defensivos relevantes asociados a
esta técnica, enfocados en hardening y visibilidad.

Más información en la carpeta `mitigations/`.

---

## Conclusiones

Las observaciones y conclusiones finales del laboratorio se documentan en
la carpeta `conclusions/`.

---
