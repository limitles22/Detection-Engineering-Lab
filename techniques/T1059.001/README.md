# Análisis de Técnica MITRE ATT&CK: T1059.001 (PowerShell)

![Status](https://img.shields.io/badge/Status-Completed-success)

![Severity](https://img.shields.io/badge/Severity-High-red)

![Data Sources](https://img.shields.io/badge/Data_Sources-Sysmon_|_PowerShell-blue)

Emulación y análisis defensivo de la técnica **T1059.001 – Command and Scripting Interpreter: PowerShell** utilizando **CALDERA** en un entorno Windows.

Referencia oficial: https://attack.mitre.org/techniques/T1059/001/

---

## 1. Objetivo del Ejercicio

Este laboratorio busca:

- Emular la técnica T1059.001 mediante:
  - `-Command` (texto claro)
  - `-EncodedCommand` (ofuscado en Base64)
- Evaluar la visibilidad generada por cada variante.
- Analizar telemetría crítica para detecciones: Sysmon, Event 4688 y Event 4104.
- Identificar oportunidades de detección, correlación y hardening.

El foco está en comparar:  
**CommandLine visible vs. CommandLine ofuscado**, destacando el rol del **Event ID 4104** en la deofuscación.

---

## 2. Entorno de Pruebas

**Infraestructura**

| Componente        | Detalle                     |
|-------------------|-----------------------------|
| Servidor C2       | CALDERA 5.x (Ubuntu Sever)  |
| Agente            | Sandcat (Go)                |
| Equipo Víctima    | Windows 10 Enterprise       |
| Antivirus         | Defender desactivado        |
| Red               | HTTP entre CALDERA y agente |

**Telemetría habilitada**

- **Sysmon (config SwiftOnSecurity)**  
  - Event ID 1: Process Creation  
  - Event ID 3: Network Connection  
  - Event ID 11: File Create

- **PowerShell Operational Logs**  
  - Event ID 4104: Script Block Logging  
  - Event ID 4103: Module Logging

- **Windows Security Log**  
  - Event ID 4688: Process Creation

---

## 3. Arquitectura del Ejercicio

```mermaid
graph TD
    A[Ubuntu Server / CALDERA C2] -->|C2 Traffic| B(Windows 10 / Sandcat Agent)
    B -->|Executes| C{PowerShell.exe}
    C -->|Variant A| D[-Command]
    C -->|Variant B| E[-EncodedCommand]
    D -->|Logs| F[Sysmon + Event Logs]
    E -->|Logs| F
    F -->|Analysis| G[Analista SOC]
    
    style A fill:#ff9999,stroke:#333,stroke-width:1.5px
    style B fill:#99ccff,stroke:#333,stroke-width:1.5px
    style G fill:#99ff99,stroke:#333,stroke-width:1.5px
