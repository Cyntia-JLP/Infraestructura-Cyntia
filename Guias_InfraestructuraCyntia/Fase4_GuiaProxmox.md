# Guía Proxmox - Fase 4

**Infraestructura fase 4: Windows Server 2022 y Active Directory**

---

## 1. Punto de partida

La VM `vm-windows-ad` (VMID 200) ya existía en Proxmox con Windows Server 2022 Standard instalado. La verificamos desde el host:

```bash
qm status 200
qm start 200
```

La VM estaba en **VLAN 10** (tag=10 en Proxmox), que corresponde a la red de producción simulada `192.168.10.0/24`. Sin embargo, al entrar a Windows e intentar configurar la red, **no aparecía ningún adaptador de red**. Esto nos llevó al primer paso correctivo.

---

## 2. Corregir el adaptador de red

### Por qué ocurre

La VM fue creada con un adaptador de red **VirtIO** (el más eficiente en Proxmox), pero Windows Server no incluye los drivers VirtIO por defecto. Sin el driver, el sistema operativo no puede ver el adaptador y por tanto no hay conectividad de red.

### Por qué elegimos e1000

El adaptador **e1000** emula una tarjeta Intel Gigabit Ethernet, cuyos drivers vienen incorporados en Windows desde hace años. Es ligeramente menos eficiente que VirtIO, pero para el propósito del proyecto (simular un entorno de PYME) es completamente válido y evita tener que montar una segunda ISO de drivers.

### Comandos ejecutados (desde SSH en el host Proxmox)

```bash
# Apagar la VM antes de cambiar hardware
qm stop 200

# Sustituir el adaptador VirtIO por e1000, manteniendo la VLAN 10
qm set 200 --net0 e1000,bridge=vmbr0,tag=10

# Arrancar de nuevo
qm start 200
```

Tras esto, al entrar a Windows ya aparecía el adaptador de red en el Administrador de dispositivos.

---

## 3. Configurar IP estática en Windows

### Por qué IP estática

Un controlador de dominio Active Directory **debe tener siempre la misma IP**. Los clientes del dominio necesitan encontrar el DC en una dirección conocida para autenticarse. Si la IP cambia, el dominio deja de funcionar.

### Pasos en Windows

Panel de control → Centro de redes y recursos compartidos → Cambiar configuración del adaptador → clic derecho en el adaptador → Propiedades → Protocolo de Internet versión 4 (TCP/IPv4) → Propiedades

Valores configurados:

| Campo | Valor |
| --- | --- |
| Dirección IP | 192.168.10.10 |
| Máscara de subred | 255.255.255.0 |
| Puerta de enlace predeterminada | 192.168.10.1 |
| DNS preferido | 192.168.20.2 (PiHole) |
| DNS alternativo | 8.8.8.8 |

### Verificación desde PowerShell

```powershell
ping 192.168.10.1
ping 8.8.8.8
```

Ambos pings respondieron correctamente, confirmando conectividad con el gateway y con internet.

---

## 4. Instalar el rol AD DS

### Por qué este rol

**AD DS (Active Directory Domain Services)** es el componente que convierte un Windows Server normal en un controlador de dominio. Sin este rol instalado, no existe la funcionalidad de Active Directory.

### Pasos en el Administrador del servidor (GUI)

1. Administrar → **Agregar roles y características**
2. Siguiente → Siguiente → Siguiente (instalación basada en roles)
3. En **Roles de servidor** → marcar **Servicios de dominio de Active Directory**
4. Clic en **Agregar características** cuando lo solicite
5. Siguiente → Siguiente → Siguiente → **Instalar**
6. Esperar 2-3 minutos. **No reiniciar todavía.**

Al terminar aparece una **bandera amarilla** en el Administrador del servidor — es la notificación que indica que el rol está instalado pero el servidor aún no está configurado como DC.

### Alternativa por PowerShell (equivalente)

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

---

## 5. Promover a controlador de dominio

### Por qué este paso

Instalar el rol AD DS solo copia los ficheros necesarios. Para que el servidor actúe como **controlador de dominio**, hay que **promoverlo**: esto crea la base de datos de Active Directory, configura el DNS integrado y establece el dominio.

### Pasos en la GUI

1. Clic en la **bandera amarilla** → “Promover este servidor a controlador de dominio”
2. Seleccionar: **Agregar un nuevo bosque**
3. Nombre del dominio raíz: `cyntia.local`
4. Nivel funcional del bosque y dominio: **Windows Server 2016** (o superior)
5. Marcar Servidor DNS
6. Establecer la contraseña de DSRM (modo de restauración)
7. Siguiente → Siguiente → Siguiente → **Instalar**

El servidor se reiniciará automáticamente. Es normal y esperado.

### Alternativa por PowerShell

```powershell
Install-ADDSForest `
  -DomainName "cyntia.local" `
  -DomainNetbiosName "CYNTIA" `
  -InstallDns:$true `
  -Force:$true
```

### Resultado

Tras el reinicio, el servidor ya es el DC del dominio `cyntia.local`. El inicio de sesión cambia a `CYNTIA\Administrador`.

---

## 6. Crear estructura AD

### Por qué esta estructura

Active Directory organiza los objetos (usuarios, equipos, grupos) en **Unidades Organizativas (OUs)** igual que los departamentos de una empresa real. Esta jerarquía permite aplicar políticas de seguridad (GPOs) a grupos específicos de usuarios, que es exactamente lo que haría una PYME real gestionada por Cyntia.

### Objetos predeterminados de AD

Al abrir el Administrador de AD, ya aparecen usuarios y grupos como `Administradores de empresas`, `Admins. del dominio`, `DnsAdmins`, etc. Estos son **objetos built-in protegidos** que Windows crea automáticamente y que son necesarios para el funcionamiento interno del dominio. No se pueden ni se deben borrar.

### Crear OUs, grupos y usuarios desde PowerShell

```powershell
# Unidades Organizativas
New-ADOrganizationalUnit -Name "Empleados" -Path "DC=cyntia,DC=local"
New-ADOrganizationalUnit -Name "Servidores" -Path "DC=cyntia,DC=local"
New-ADOrganizationalUnit -Name "Admins" -Path "DC=cyntia,DC=local"

# Grupos de seguridad
New-ADGroup -Name "GRP_Usuarios" -GroupScope Global -Path "OU=Empleados,DC=cyntia,DC=local"
New-ADGroup -Name "GRP_Admins" -GroupScope Global -Path "OU=Admins,DC=cyntia,DC=local"

# Usuarios de prueba
New-ADUser -Name "Ana Garcia" -SamAccountName "agarcia" `
  -UserPrincipalName "agarcia@cyntia.local" `
  -Path "OU=Empleados,DC=cyntia,DC=local" `
  -AccountPassword (ConvertTo-SecureString "-" -AsPlainText -Force) `
  -Enabled $true

New-ADUser -Name "Carlos Lopez" -SamAccountName "clopez" `
  -UserPrincipalName "clopez@cyntia.local" `
  -Path "OU=Empleados,DC=cyntia,DC=local" `
  -AccountPassword (ConvertTo-SecureString "-" -AsPlainText -Force) `
  -Enabled $true

# Asignar usuarios al grupo
Add-ADGroupMember -Identity "GRP_Usuarios" -Members "agarcia","clopez"
```

---

## 7. Instalar el agente Wazuh en Windows

### Por qué el agente

Wazuh funciona con un modelo **manager + agentes**. El manager (corriendo en Docker en `lxc-soc-core`, IP `192.168.20.3`) es el cerebro central. Para que Windows Server envíe sus eventos de seguridad al SOC, necesita tener instalado el **agente Wazuh**, que actúa como un recolector y transmisor de logs en el propio sistema monitorizado.

### Instalación desde PowerShell en Windows

```powershell
# Descargar el instalador
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile "C:\wazuh-agent.msi"

# Instalar apuntando al manager
msiexec.exe /i C:\wazuh-agent.msi /q WAZUH_MANAGER="192.168.20.3" WAZUH_AGENT_NAME="vm-windows-ad"

# Arrancar el servicio
NET START WazuhSvc
```

### Registro manual del agente (método aplicado)

El agente dio error de duplicado al intentar auto-registrarse. Se optó por el registro manual desde el host Proxmox:

```bash
# Crear el agente en el manager manualmente
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/manage_agents -a 192.168.10.10 -n vm-windows-ad

# Exportar la clave del agente
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/manage_agents -e 001
```

La clave generada se importó en Windows:

```powershell
NET STOP WazuhSvc
Remove-Item "C:\Program Files (x86)\ossec-agent\client.keys" -ErrorAction SilentlyContinue
& "C:\Program Files (x86)\ossec-agent\manage_agents.exe" -i <CLAVE>
NET START WazuhSvc
```

### Verificación

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Resultado confirmado:

```
ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: vm-windows-ad, IP: any, Active
```

---

## 8. Configurar ossec.conf

### Por qué esta configuración

El agente Wazuh, por defecto, no sabe qué logs recoger de Windows. Hay que indicarle explícitamente que monitorice los **canales de eventos de Windows** relevantes para un entorno Active Directory: `Security` (autenticaciones, cambios de cuenta), `System` (arranque, errores), `Application` y `Directory Service` (eventos propios de AD).

### Edición del fichero en Windows

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Añadir dentro de `<ossec_config>` antes del cierre `</ossec_config>`:

```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Security</location>
</localfile>

<localfile>
  <log_format>eventchannel</log_format>
  <location>System</location>
</localfile>

<localfile>
  <log_format>eventchannel</log_format>
  <location>Application</location>
</localfile>

<localfile>
  <log_format>eventchannel</log_format>
  <location>Directory Service</location>
</localfile>
```

### Reiniciar el agente para aplicar cambios

```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

---

## 9. Pasos pendientes

```powershell
# Habilitar políticas de auditoría (para generar eventos en el canal Security)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

# Habilitar IIS
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Habilitar RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Crear share SMB de prueba
New-Item -ItemType Directory -Path "C:\Shares\Empresa"
New-SmbShare -Name "Empresa" -Path "C:\Shares\Empresa" -FullAccess "GRP_Usuarios"
```
