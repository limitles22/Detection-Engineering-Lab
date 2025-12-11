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
    A[Ubuntu Server\nCALDERA C2] -->|Tareas C2| B[Windows 10\nSandcat Agent]
    B -->|Ejecuta| C[PowerShell.exe]
    C --> D[-Command\n(Texto Claro)]
    C --> E[-EncodedCommand\n(Base64)]
    D -->|Logs| F[Sysmon + Event Logs\n(4688, 4104)]
    E -->|Logs| F
    F -->|Análisis| G[Analista SOC]
    
    %% High-contrast styles
    style A fill:#1E3A8A,stroke:#ffffff,stroke-width:1px
    style B fill:#1E40AF,stroke:#ffffff,stroke-width:1px
    style C fill:#0F766E,stroke:#ffffff,stroke-width:1px
    style D fill:#15803D,stroke:#ffffff,stroke-width:1px
    style E fill:#166534,stroke:#ffffff,stroke-width:1px
    style F fill:#7C2D12,stroke:#ffffff,stroke-width:1px
    style G fill:#4C1D95,stroke:#ffffff,stroke-width:1px
