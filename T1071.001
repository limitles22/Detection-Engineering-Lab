Hoy estuve en laboratorio con MITRE CALDERA, emulando la técnica T1071.001 (Application Layer Protocol – Web Protocols) para evaluar qué tan visible es realmente desde el lado defensivo.

Ejecuté la técnica desde CALDERA y monitoreé el host con Sysmon, revisé eventos nativos de PowerShell y validé qué llegaba a Wazuh como SIEM.

### Detecciones

### **Sysmon**

*Eventos ordenados cronológicamente*

### **Event ID 1 – Process Creation**

- Se ejecuta **PowerShell** desde una ruta legítima del sistema (**LOLBIN**).
- Se fuerza el parámetro **`ExecutionPolicy Bypass`**, lo que indica una posible **evasión de controles de seguridad**.
- El proceso luego inicia **actividad de red web**.
- Se observa el uso de **User-Agents anómalos**, poco comunes en ejecuciones legítimas.
- El evento permite identificar **usuario**, **proceso**, y **línea de comandos completa**.

Este evento representa el **punto inicial de la cadena de ataque**. Permite pivotar hacia eventos posteriores de creación de archivos (Sysmon ID 11) y comunicaciones de red (Sysmon ID 22 y 3), facilitando la correlación completa de la técnica **T1071.001**.

### **Event ID 11 – File Create**

- **PowerShell** crea un archivo temporal en el directorio del usuario (`AppData\Local\Temp`).
- El nombre del archivo sugiere un **script temporal generado automáticamente** (`__PSScriptPolicyTest_*.ps1`).
- Esta acción ocurre **inmediatamente después** de la creación del proceso (Event ID 1).
- No se observa interacción del usuario ni persistencia del archivo.

Este evento confirma que PowerShell genera **artefactos temporales durante la ejecución**, un comportamiento común en técnicas utilizadas para comunicación remota y evasión de controles básicos.

### **Event ID 22 – DNS Query**

- **PowerShell** realiza una **consulta DNS** hacia `www.google.com`.
- La consulta es consecuencia directa de un **Web Request**.
- El proceso responsable es **powershell.exe**.
- Se resuelve la dirección IP del destino externo.

Antes de cualquier conexión web existe una resolución DNS. Este evento permite identificar de forma temprana que **PowerShell es el proceso que inicia la comunicación hacia un dominio externo**, algo poco habitual en estaciones de trabajo.

### **Event ID 3 – Network Connection**

- **powershell.exe** inicia una **conexión de red saliente**.
- Se utiliza el **protocolo TCP**.
- El destino corresponde a una **dirección IP externa (Internet)**.
- El puerto destino es **80 (HTTP)**.
- La conexión es **iniciada por el host** (`Initiated = true`).

Este evento confirma definitivamente la **comunicación de red real**. Demuestra que el proceso no solo se ejecutó, sino que **estableció comunicación HTTP con un destino externo.** 

---

## **PowerShell – Windows Event Log**

Además de Sysmon, la técnica **T1071.001** dejó huellas claras en los **PowerShell Operational Logs**, demostrando que este tipo de comunicación también puede detectarse **solo con logs nativos de Windows**.

### **Event ID 40962 – PowerShell Engine Start**

Marca el arranque del motor de PowerShell. Sirve como **punto inicial temporal** para correlacionar toda la actividad que ocurre después.

### **Event ID 4103 – Command Invocation**

Registra los **cmdlets que se ejecutan**, en este caso llamadas a **Invoke-WebRequest**. Suele aparecer varias veces y permite entender **qué acciones está realizando PowerShell**.

### **Event ID 4104 – Script Block Logging**

Muestra el **contenido del script ejecutado**. Es uno de los eventos más valiosos desde defensa, ya que expone directamente el uso de PowerShell para generar tráfico HTTP.

### **Wireshark – Network Visibility**

Para complementar la visibilidad en host, capturamos tráfico de red durante la ejecución utilizando Wireshark.

- Se observa **tráfico HTTP en texto claro** generado desde el host comprometido.
- El tráfico corresponde a comunicaciones **salientes** iniciadas por el endpoint.
- Se identifican **múltiples solicitudes HTTP tipo GET**.
- Las conexiones coinciden temporalmente con:
    - **Sysmon Event ID 3 (Network Connection)**
    - **Ejecuciones `Invoke-WebRequest` desde PowerShell**
- El tráfico utiliza **User-Agents no estándar**, lo cual es consistente con técnicas de **Command and Control vía HTTP**.

---

## **Correlación**

Al analizar en conjunto las distintas fuentes de telemetría, se puede reconstruir la ejecución de la técnica **T1071.001**.

Desde el endpoint, **Sysmon** permitió identificar el inicio de PowerShell, la creación de archivos temporales y las conexiones de red hacia Internet. En paralelo, los **logs nativos de PowerShell** mostraron la ejecución de comandos como `Invoke-WebRequest`, aportando contexto sobre **qué estaba haciendo realmente el proceso**. Finalmente, **Wireshark** confirmó tráfico HTTP saliente en texto claro, con **User-Agents atípicos**, y en el mismo marco temporal que los eventos del host.

## Wazuh

Después de correlacionar los eventos  de las distintas fuentes de eventos (**Sysmon, PowerShell y Wireshark)** pasamos a mirar qué había pasado en **Wazuh**, que es el SIEM que usamos en el laboratorio.

Wazuh **sí levantó una alerta**, pero no exactamente por la técnica que estaba probando. Lo que detectó fue **T1105 (Ingress Tool Transfer)**, a partir de la creación de un archivo temporal por PowerShell en una ruta típica que suele aparecer en actividades maliciosas.

Wazuh detectó **la consecuencia de la ejecución**, no la comunicación HTTP usada como canal de C2 (**T1071.001**). Esa técnica quedó clara recién cuando correlamos varias fuentes juntas (host + PowerShell + red), pero no porque existiera una regla específica que la identifique de forma directa.

## Regla Sigma
https://github.com/limitles22/Detection-Engineering-Lab/blob/main/sigma_t1071_001.yml

Esta regla Sigma apunta a un comportamiento bastante típico pero fácil de pasar por alto: **PowerShell usando HTTP con User-Agents raros**. No busca una herramienta específica ni una URL concreta, sino la **combinación peligrosa**: PowerShell ejecutando comandos web (`Invoke-WebRequest`, `iwr`, `curl`, etc.) y, además, setear User-Agents que no son normales para scripts legítimos. La idea es detectar **comunicación de C2 camuflada como tráfico web común**, justo lo que define T1071.001. Es una regla pensada para dar **visibilidad temprana**

**Resultado**:

- La regla **detectó correctamente** la ejecución de PowerShell usando `Invoke-WebRequest`.
- Se identificaron **User-Agents anómalos** definidos en la línea de comandos.
- La detección ocurrió en **tiempo cercano a la ejecución**, sin depender de artefactos secundarios.

Con esta regla, Wazuh logró **detectar directamente el canal de C2 sobre HTTP**, y no solo una consecuencia colateral de la ejecución.

## Conclusión

La técnica **T1071.001** puede pasar desapercibida si se analiza una sola fuente de telemetría. Sin embargo, combinando **Sysmon**, **PowerShell Operational Logs** y **red**, es posible reconstruir claramente el comportamiento.

Además, la creación de **reglas Sigma basadas en comportamiento**, y no en herramientas específicas, permite llevar esta visibilidad al SIEM y detectar **C2 sobre HTTP** de forma temprana.
