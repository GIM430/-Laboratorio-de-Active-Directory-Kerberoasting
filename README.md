# 🔐 Laboratorio de Active Directory — Kerberoasting

Laboratorio propio de ciberseguridad montado en local con VirtualBox: construcción de un entorno de Active Directory desde cero y ejecución de un ataque de **Kerberoasting** contra una cuenta de servicio, extremo a extremo (desde la petición del ticket hasta el crackeo de la contraseña).

> ⚠️ Todo el laboratorio se ejecuta en máquinas virtuales aisladas, sin conexión a redes de producción ni a terceros. El objetivo es puramente educativo: entender cómo funciona uno de los ataques más comunes contra Active Directory en entornos corporativos reales.

---

## 📋 Índice

- [Objetivo](#-objetivo)
- [Arquitectura del laboratorio](#-arquitectura-del-laboratorio)
- [Parte 1 — Construcción del entorno](#-parte-1--construcción-del-entorno)
- [Parte 2 — El ataque: Kerberoasting](#-parte-2--el-ataque-kerberoasting)
- [Concepto técnico clave](#-concepto-técnico-clave)
- [Por qué importa en el mundo real](#-por-qué-importa-en-el-mundo-real)
- [Mitigaciones](#-mitigaciones)
- [Lecciones aprendidas](#-lecciones-aprendidas)

---

## 🎯 Objetivo

Entender de forma práctica cómo un atacante con acceso mínimo (un simple usuario de dominio, sin privilegios de administrador) puede comprometer cuentas de servicio con privilegios elevados a través de una debilidad estructural del protocolo Kerberos, y cómo se ve ese ataque tanto desde el lado ofensivo como defensivo.

## 🏗️ Arquitectura del laboratorio

| Máquina | Rol | Sistema operativo | Specs |
|---|---|---|---|
| **DC01** | Domain Controller | Windows Server 2022 Standard (Desktop Experience) | 4GB RAM, 2 vCPU, 50GB disco |
| **CLIENTE01** | Estación de trabajo unida al dominio | Windows 11 Enterprise | 4GB RAM, 2 vCPU, 50GB disco |
| **Kali Linux** | Máquina atacante (crackeo offline) | Kali Linux | — |

**Dominio**: `lab.local` (NetBIOS: `LAB`)

**Red**: VirtualBox, adaptador NAT para las fases de instalación/activación, con Guest Additions instaladas para gestión práctica de las VMs.

---

## 🛠️ Parte 1 — Construcción del entorno

### 1. Preparación de las VMs
- Descarga de imágenes oficiales de evaluación desde el [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter): Windows Server 2022 (180 días) y Windows 11 Enterprise (90 días)
- Creación de las VMs en VirtualBox con recursos dedicados independientes

### 2. Instalación y configuración del Domain Controller (DC01)
- Instalación de Windows Server 2022, edición **Desktop Experience**
- Renombrado del equipo a `DC01`
- Configuración de **IP estática** y DNS propio (requisito de un DC):
  ```powershell
  Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false
  New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.0.2.15 -PrefixLength 24 -DefaultGateway 10.0.2.2
  Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
  ```
- Instalación del rol **AD DS**:
  ```powershell
  Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
  ```
- Promoción a Domain Controller, creando el bosque/dominio `lab.local`:
  ```powershell
  Install-ADDSForest -DomainName "lab.local" -InstallDNS
  ```

### 3. Estructura de Active Directory
- Creación de la Unidad Organizativa `Empleados`:
  ```powershell
  New-ADOrganizationalUnit -Name "Empleados" -Path "DC=lab,DC=local"
  ```
- Creación de un usuario de dominio estándar (`jperez`) sin privilegios especiales
- Creación de una **cuenta de servicio** (`svc_sql`), pensada para simular una cuenta típica de una aplicación/base de datos en un entorno corporativo:
  ```powershell
  $p = ConvertTo-SecureString "Passw0rd123!" -AsPlainText -Force
  New-ADUser -Name "Juan Perez" -SamAccountName jperez -UserPrincipalName jperez@lab.local `
    -Path "OU=Empleados,DC=lab,DC=local" -AccountPassword $p -Enabled $true

  $p2 = ConvertTo-SecureString "SuperSecret2024!" -AsPlainText -Force
  New-ADUser -Name "Service Account" -SamAccountName svc_sql -UserPrincipalName svc_sql@lab.local `
    -Path "OU=Empleados,DC=lab,DC=local" -AccountPassword $p2 -Enabled $true
  ```

### 4. Unión del cliente al dominio (CLIENTE01)
- Instalación de Windows 11 Enterprise
- Unión al dominio `lab.local`
- Inicio de sesión con el usuario `jperez` desde el cliente, replicando el escenario de un "PC de empleado" real

### 5. Asignación de SPN a la cuenta de servicio
Paso crítico que convierte a `svc_sql` en objetivo de Kerberoasting — un **SPN (Service Principal Name)** vincula la cuenta con un servicio de red, lo cual es exactamente el tipo de configuración que dispara la vulnerabilidad:
```powershell
setspn -A MSSQLSvc/dc01.lab.local:1433 svc_sql
```

### Problemas de sysadmin resueltos durante el montaje
Parte importante del aprendizaje fue depurar problemas reales de entorno, no solo seguir una guía sin fricción:
- Diferencias entre red **NAT** y **Red interna** en VirtualBox, y cuándo usar cada una
- Redimensionado de disco: el tamaño inicial se quedó corto para instalar Windows 11 y hubo que ampliarlo
- Pantalla en negro al arrancar por configuración de **arranque EFI**
- El instalador de Windows 11 forzando el uso de una cuenta Microsoft en el OOBE (bypass necesario para cuenta local)
- Permisos de administrador requeridos para instalar correctamente las **Guest Additions**
- Configuración de **carpetas compartidas** host↔VM para mover archivos (como Rubeus) sin depender de acceso a internet dentro del laboratorio aislado
- Portapapeles compartido de VirtualBox fallando hasta instalar correctamente las Guest Additions

---

## ⚔️ Parte 2 — El ataque: Kerberoasting

### Paso 1 — Petición del ticket TGS como usuario sin privilegios
Desde **CLIENTE01**, con sesión iniciada como `jperez` (usuario de dominio normal, sin ningún privilegio administrativo), se usó **[Rubeus](https://github.com/GhostPack/Rubeus)** para solicitar un ticket de servicio (TGS) correspondiente al SPN de `svc_sql`:

```powershell
Rubeus.exe kerberoast /outfile:hashes.txt
```

Al tener `svc_sql` un SPN registrado, el Domain Controller entrega el ticket sin problema — **cualquier usuario autenticado del dominio puede pedir un TGS de cualquier cuenta con SPN**, es una operación legítima del protocolo Kerberos, no requiere permisos especiales.

### Paso 2 — Extracción del hash
El ticket TGS viene cifrado con una clave derivada de la contraseña de la cuenta de servicio (`svc_sql`). Rubeus extrae ese material cifrado en formato crackeable (compatible con Hashcat) al archivo `hashes.txt`.

### Paso 3 — Transferencia a Kali Linux
El archivo con el hash se movió a la máquina Kali (vía carpeta compartida) para el crackeo offline.

### Paso 4 — Crackeo offline con Hashcat
```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```
(Modo `13100` = Kerberos 5, etype 23, TGS-REP)

**Resultado**: contraseña recuperada en texto claro → `SuperSecret2024!`

---

## 🔑 Concepto técnico clave

> Cualquier usuario autenticado de un dominio Active Directory —sin necesitar privilegios especiales— puede pedir tickets de servicio (TGS) para cualquier cuenta que tenga un SPN configurado. Ese ticket va cifrado con la contraseña de la cuenta de servicio, así que si consigues el ticket, te lo llevas offline y lo crackeas con calma, **sin que el Domain Controller se entere de que lo estás intentando** — no hay bloqueo por intentos fallidos, porque técnicamente no se produce ningún login fallido.

Esto convierte a Kerberoasting en un ataque especialmente peligroso:
- **No requiere privilegios previos** más allá de una cuenta de dominio válida
- **No genera bloqueos** de cuenta ni alertas típicas de fuerza bruta online
- **Es completamente offline** una vez obtenido el ticket, sin límite de intentos ni interacción con el DC
- **Escala con la debilidad de la contraseña**: cuentas de servicio antiguas, con contraseñas nunca rotadas, caen en minutos con diccionarios como `rockyou.txt`

## 🏢 Por qué importa en el mundo real

Las cuentas de servicio son uno de los objetivos favoritos de un atacante tras comprometer un único usuario normal, por varios motivos típicos en entornos corporativos reales:
- Suelen tener **privilegios elevados** (acceso a bases de datos, otros servidores, tareas programadas)
- Sus contraseñas casi nunca se rotan, porque **"rompe cosas"** si se cambian sin coordinación
- Muchas veces se configuraron hace años y nadie recuerda ni revisa su seguridad
- Comprometer una de estas cuentas suele ser el paso intermedio entre "un usuario normal pillado por phishing" y "control total del dominio"

## 🛡️ Mitigaciones

| Medida | Efecto |
|---|---|
| Contraseñas largas y aleatorias para cuentas de servicio (25+ caracteres) | Hace inviable el crackeo por diccionario/fuerza bruta |
| **Managed Service Accounts (gMSA)** | Rotación automática de contraseña gestionada por AD, elimina el problema de raíz |
| Auditoría periódica de SPNs asignados | Detecta cuentas de servicio innecesarias o mal configuradas |
| Monitorización de peticiones TGS anómalas (Event ID 4769) | Permite detección temprana, aunque el ataque en sí no "falle" ningún login |
| Principio de mínimo privilegio en cuentas de servicio | Reduce el impacto si la cuenta se compromete igualmente |

## 📚 Lecciones aprendidas

- Cómo se estructura y administra un dominio de Active Directory desde cero (DC, DNS, OUs, usuarios, SPNs)
- Uso práctico de PowerShell para administración de sistemas Windows y AD
- Cómo funciona el protocolo Kerberos y por qué su diseño (necesario para la autenticación) también abre esta superficie de ataque
- Uso de herramientas ofensivas reales (Rubeus, Hashcat) en un flujo de trabajo completo
- Diagnóstico y resolución de problemas de entorno típicos de virtualización y sysadmin
- Visión combinada ataque/defensa: no basta con ejecutar el ataque, sino entender qué lo permite y cómo se mitiga

---

## ⚖️ Disclaimer

Este laboratorio se ejecuta íntegramente en un entorno virtualizado, aislado y de propiedad personal, con fines exclusivamente educativos y de formación en ciberseguridad defensiva/ofensiva. Ninguna de las técnicas aquí documentadas debe aplicarse contra sistemas sin autorización explícita.
