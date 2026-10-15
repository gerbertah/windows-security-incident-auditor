# Windows Security Incident & Forensics Auditor (PowerShell)

Herramienta ligera y de solo lectura desarrollada en PowerShell para realizar triaje forense, auditorías de seguridad e investigación inicial de incidentes en entornos Windows.

Compatible con **Windows 10, Windows 11** y **Windows Server (2012, 2016, 2019, 2022 y 2025)**.

---

## 🎯 Capacidades Principales

- **Identificación Automática:** Detecta el sistema operativo, la arquitectura del kernel y el rol del equipo (Controlador de Dominio vs Standalone/Miembro).
- **Triaje de Autenticaciones:**
  - `4625`: Extracción de fuerza bruta con IP remota, cuenta atacada y consolidación de Top IPs.
  - `4624`: Detección de sesiones interactivas y conexiones RDP entrantes (Tipo 2 y Tipo 10).
- **Gestión de Cuentas y Privilegios:**
  - `4720`, `4722`, `4724`, `4726`: Identificación de cuentas creadas, modificadas o desbloqueadas, atribuyendo al administrador responsable.
  - `4728`, `4732`, `4756`: Auditoría de asignación a grupos sensibles y escaladas de privilegios.
- **Inventario Administrativo:** Enumeración de miembros del grupo local `Administrators` (mediante SID de objeto `S-1-5-32-544` independiente del idioma del SO) y grupos de Active Directory (`Domain Admins`, `Enterprise Admins`) si es un DC.
- **Exportación Dual:**
  - Archivos `.csv` delimitados por punto y coma para SIEM, Excel o análisis masivo.
  - Dashboard `.html` responsivo, moderno y sin dependencias externas.

---

## ⚙️ Requisitos

- Windows PowerShell 5.1 o PowerShell 7+.
- Privilegios de **Administrador local**.
- Directivas de auditoría de inicio de sesión y gestión de cuentas activas en la directiva local o de dominio (`secpol.msc` / GPO).

---

## 🚀 Uso Rápido

Ejecuta PowerShell con privilegios elevados:

```powershell
# Modo interactivo (pregunta dias, ruta y alcance)
.\Audit-WindowsSecurity.ps1

# Ejecucion desatendida / automatizada (ideal para tareas programadas o scripts de respuesta)
.\Audit-WindowsSecurity.ps1 -Dias 30 -Modo Todo -SinPreguntas

# Modo con privilegios elevados en una sola linea cambias el 7 por los dias que necesites
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Audit-WindowsSecurity.ps1 -Dias 7 -Modo Todo -MaximoPorEvento 5000 -SinPreguntas"
