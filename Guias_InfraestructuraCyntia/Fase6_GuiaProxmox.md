# Guía Proxmox - Fase 6

**Infraestructura fase 6: OpenCanary + Wazuh: Honeypot integrado en el SOC Cyntia**

---

## 1. Contexto y objetivos

### ¿Qué es un honeypot?

Un honeypot es un sistema señuelo que simula ser un servidor real (SSH, web, base de datos, etc.) sin ninguna función legítima. Cualquier intento de acceso a estos servicios falsos es, por definición, actividad maliciosa o sospechosa, ya que ningún usuario legítimo debería estar intentando conectarse a ellos.

### ¿Por qué OpenCanary?

OpenCanary es una solución de honeypot open source que permite desplegar múltiples servicios señuelo en un único proceso Python. En el proyecto Cyntia se usa para:

- Detectar reconocimiento interno (escaneos de red desde dentro de las VLANs)
- Detectar movimiento lateral (un atacante que ya está dentro intentando pivotar)
- Capturar credenciales usadas en intentos de acceso
- Generar alertas de máxima prioridad en Wazuh ante cualquier interacción

OpenCanary se despliega en **lxc-honeypot (VMID 103, IP 192.168.20.4, VLAN 20)**, un contenedor LXC Debian 12 dedicado exclusivamente a esta función.

---

## 2. Instalación de OpenCanary en lxc-honeypot

### Acceder al contenedor

```bash
pct exec 103 -- bash
```

### Instalar dependencias del sistema

```bash
apt-get update && apt-get upgrade -y
apt-get install -y python3-pip python3-dev libssl-dev libffi-dev build-essential git
```

### Instalar OpenCanary via pip

```bash
pip3 install opencanary --break-system-packages
```

OpenCanary se instala en `/usr/local/bin/`, que no está en el PATH por defecto en Debian. Hay que añadirlo:

```bash
export PATH=$PATH:/usr/local/bin
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
```

### Verificar la instalación

```bash
opencanaryd --version
# Salida esperada: 0.9.7
```

---

## 3. Configuración de servicios señuelo

### Crear el fichero de configuración

OpenCanary usa un fichero JSON en `/etc/opencanaryd/opencanary.conf`. Lo creamos directamente con los servicios que queremos simular:

```bash
cat > /etc/opencanaryd/opencanary.conf << 'EOF'
{
    "device.node_id": "opencanary-honeypot-cyntia",
    "logging.file": "/var/log/opencanary.log",
    "logging.file.debug": false,

    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",

    "http.enabled": true,
    "http.port": 8080,
    "http.banner": "Apache/2.4.41 (Ubuntu)",

    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.7.0-opencanary",

    "smb.enabled": true,

    "ssh.enabled": true,
    "ssh.port": 2222,
    "ssh.version": "SSH-2.0-OpenSSH_8.4p1",

    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary.log",
                    "formatter": "plain"
                },
                "syslog-unix": {
                    "class": "logging.handlers.SysLogHandler",
                    "address": "/dev/log",
                    "formatter": "plain"
                }
            }
        }
    }
}
EOF
```

### Por qué el SSH va en el puerto 2222 y no en el 22

El contenedor ya usa el puerto 22 para su propio servicio SSH (necesario para administración). Por eso el honeypot SSH se despliega en el puerto 2222. En un entorno real de producción, el SSH de administración estaría en otro puerto o deshabilitado, y el honeypot podría usar el 22.

### Servicios señuelo desplegados

| Servicio | Puerto | logtype en alertas |
| --- | --- | --- |
| FTP | 21 | 2000 |
| HTTP | 8080 | 3000 |
| MySQL | 3306 | 8001 |
| SMB | 445 | 5000 |
| SSH | 2222 | 4000/4001/4002 |

---

## 4. Servicio systemd para autostart

Para que OpenCanary arranque automáticamente con el sistema, creamos un servicio systemd:

```bash
cat > /etc/systemd/system/opencanary.service << 'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
ExecStart=/usr/local/bin/opencanaryd --dev --allow-run-as-root
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Habilitamos y arrancamos:

```bash
systemctl daemon-reload
systemctl enable opencanary
systemctl start opencanary
```

Verificamos que está corriendo:

```bash
systemctl status opencanary --no-pager | head -5
```

### Verificación de alertas del honeypot

Desde el host cyntia, probamos que los servicios responden y generan alertas:

```bash
# SSH honeypot
ssh root@192.168.20.4 -p 2222
# (introducir contraseña incorrecta)

# HTTP honeypot
curl -v http://192.168.20.4:8080/index.html

# MySQL honeypot
mysql -h 192.168.20.4 -u root -ptest
```

Comprobamos el log:

```bash
pct exec 103 -- bash -c "tail -5 /var/log/opencanary.log"
```

---

## 5. Instalación del agente Wazuh en lxc-honeypot

Para integrar OpenCanary con Wazuh, instalamos el agente Wazuh directamente en lxc-honeypot. El agente leerá el fichero de log de OpenCanary y enviará cada evento al manager.

### Instalar curl

```bash
pct exec 103 -- bash -c "apt-get install -y curl"
```

### Añadir el repositorio oficial de Wazuh

```bash
pct exec 103 -- bash -c "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update && apt-get install -y --allow-downgrades wazuh-agent=4.9.2-1"
```

**Por qué la versión 4.9.2-1:** El manager de Wazuh que tenemos desplegado en lxc-soc-core es la versión 4.9.2. Wazuh requiere que el agente tenga la misma versión o inferior que el manager. Si instalamos una versión más nueva, el manager rechazará la conexión.

### Configurar el agente

El ossec.conf del agente debe apuntar al manager y configurar la lectura del log de OpenCanary:

```bash
pct exec 103 -- bash -c "cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>192.168.20.1</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>no</enabled>
    </enrollment>
  </client>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/opencanary.log</location>
  </localfile>
</ossec_config>
EOF"
```

**Por qué `log_format: json`:** Los logs de OpenCanary son objetos JSON. Si usamos `syslog`, Wazuh intenta parsearlos como syslog y los descarta. Con `json`, el decoder de Wazuh los procesa correctamente y puede extraer campos como `logtype`, `node_id`, `src_host`, etc.

**Por qué apunta a 192.168.20.1 y no a 192.168.20.3:** El agente no puede conectar directamente al puerto 1514 de lxc-soc-core (192.168.20.3) porque Docker dentro del LXC no es accesible desde otros contenedores en la misma VLAN. La solución es usar el host Proxmox (192.168.20.1) como relay mediante socat.

### Configurar el servicio systemd del agente

```bash
pct exec 103 -- bash -c "cat > /etc/systemd/system/wazuh-agent.service << 'EOF'
[Unit]
Description=Wazuh agent
After=network.target

[Service]
Type=simple
ExecStart=/var/ossec/bin/wazuh-agentd -f
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload"
```

---

## 6. Cadena de relays socat

### El problema de conectividad

La arquitectura de red de Cyntia tiene un problema de conectividad específico: el puerto 1514 de Wazuh está expuesto por Docker dentro de lxc-soc-core, pero las conexiones TCP desde otros contenedores de la misma VLAN son rechazadas por las reglas internas de Docker (cadena DOCKER-USER de iptables).

La solución es una **cadena de relays socat** que actúa como proxy TCP:

```
lxc-honeypot (103)
    → 192.168.20.1:1514 (host Proxmox - socat relay)
        → 192.168.20.3:21514 (lxc-soc-core - socat relay)
            → 172.18.0.2:1514 (contenedor Docker wazuh.manager)
```

### Relay 1: En el host Proxmox (para el puerto 1514)

```bash
cat > /etc/systemd/system/wazuh-relay.service << 'EOF'
[Unit]
Description=Wazuh relay for lxc-honeypot
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:1514,bind=192.168.20.1,fork TCP:192.168.20.3:21514
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wazuh-relay
systemctl start wazuh-relay
```

### Relay 2: En el host Proxmox (para el puerto 1515 - enrollment)

El puerto 1515 es el de enrollment de Wazuh, por donde el agente se registra automáticamente con el manager:

```bash
cat > /etc/systemd/system/wazuh-relay-enroll.service << 'EOF'
[Unit]
Description=Wazuh enrollment relay for lxc-honeypot
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:1515,bind=192.168.20.1,fork TCP:192.168.20.3:21515
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wazuh-relay-enroll
systemctl start wazuh-relay-enroll
```

### Relay 3: En lxc-soc-core (para el puerto 1514 hacia Docker)

```bash
pct exec 101 -- bash -c "apt-get install -y socat"

pct exec 101 -- bash -c "cat > /etc/systemd/system/wazuh-docker-relay.service << 'EOF'
[Unit]
Description=Wazuh Docker relay
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:21514,fork TCP:172.18.0.2:1514
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable wazuh-docker-relay && systemctl start wazuh-docker-relay"
```

### Relay 4: En lxc-soc-core (para el puerto 1515 hacia Docker)

```bash
pct exec 101 -- bash -c "cat > /etc/systemd/system/wazuh-docker-relay-enroll.service << 'EOF'
[Unit]
Description=Wazuh Docker enrollment relay
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:21515,fork TCP:172.18.0.2:1515
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable wazuh-docker-relay-enroll && systemctl start wazuh-docker-relay-enroll"
```

### Añadir reglas nftables en el host

El host debe permitir el tráfico desde VLAN 20 hacia los puertos de relay:

```bash
nano /etc/nftables.conf
```

Añadir en `chain input`:

```
iifname "vmbr0.20" tcp dport 1514 accept
iifname "vmbr0.20" tcp dport 1515 accept
```

Añadir también la regla intra-VLAN 20:

```
iifname "vmbr0.20" oifname "vmbr0.20" accept
```

Aplicar:

```bash
systemctl restart nftables
```

### Verificar la cadena completa

```bash
# Desde honeypot al host
pct exec 103 -- bash -c "nc -zv -w3 192.168.20.1 1514"
# Esperado: Connection to 192.168.20.1 1514 port succeeded!

# Desde lxc-soc-core hacia Docker
pct exec 101 -- bash -c "nc -zv 127.0.0.1 21514"
# Esperado: Connection to 127.0.0.1 21514 port succeeded!
```

---

## 7. Registro del agente en el manager

### Habilitar el puerto 1514 para agentes en Wazuh

El manager de Wazuh por defecto solo tiene configurado el puerto 514 para syslog. Hay que añadir el bloque `secure` para que acepte conexiones de agentes en el 1514.

En lxc-soc-core, editamos el fichero de configuración del manager:

```bash
pct exec 101 -- bash
nano /opt/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```

Añadir antes del último `</ossec_config>`:

```xml
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
```

Aplicar la configuración al contenedor Docker:

```bash
docker exec single-node-wazuh.manager-1 bash -c "cat /wazuh-config-mount/etc/ossec.conf > /var/ossec/etc/ossec.conf"
docker restart single-node-wazuh.manager-1
```

### Registrar el agente manualmente

Con el enrollment automático desactivado, hay que registrar el agente manualmente en el manager y luego importar la clave en el agente.

**Paso 1:** Crear el agente en el manager:

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -a 192.168.20.4 -n lxc-honeypot"
```

**Paso 2:** Obtener la clave generada:

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -e 003"
```

**Paso 3:** Importar la clave en el agente del honeypot:

```bash
pct exec 103 -- bash -c "/var/ossec/bin/manage_agents -i <CLAVE_BASE64>"
# Confirmar con 'y'
```

**Paso 4:** Arrancar el agente:

```bash
pct exec 103 -- bash -c "/var/ossec/bin/wazuh-control start"
```

**Paso 5:** Verificar que el agente aparece como Active:

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
```

Salida esperada:

```
ID: 003, Name: lxc-honeypot, IP: 192.168.20.4, Active
```

---

## 8. Reglas personalizadas en Wazuh

OpenCanary genera logs JSON con un campo `logtype` que identifica el tipo de evento. Wazuh no tiene reglas predefinidas para OpenCanary, así que creamos reglas personalizadas.

### Crear el fichero de reglas

En lxc-soc-core:

```bash
cat > /tmp/opencanary_rules.xml << 'EOF'
<group name="opencanary,honeypot,">
  <rule id="100200" level="10">
    <decoded_as>json</decoded_as>
    <field name="node_id" type="pcre2">opencanary</field>
    <description>OpenCanary: Honeypot interaction detected</description>
  </rule>
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="logtype" type="pcre2">4002</field>
    <description>OpenCanary: SSH login attempt on honeypot</description>
  </rule>
  <rule id="100203" level="12">
    <if_sid>100200</if_sid>
    <field name="logtype" type="pcre2">8001</field>
    <description>OpenCanary: MySQL login attempt on honeypot</description>
  </rule>
  <rule id="100204" level="12">
    <if_sid>100200</if_sid>
    <field name="logtype" type="pcre2">3000</field>
    <description>OpenCanary: HTTP request to honeypot web server</description>
  </rule>
  <rule id="100205" level="12">
    <if_sid>100200</if_sid>
    <field name="logtype" type="pcre2">2000</field>
    <description>OpenCanary: FTP login attempt on honeypot</description>
  </rule>
  <rule id="100206" level="12">
    <if_sid>100200</if_sid>
    <field name="logtype" type="pcre2">5000</field>
    <description>OpenCanary: SMB connection attempt on honeypot</description>
  </rule>
</group>
EOF
```

Copiar al contenedor Docker y reiniciar:

```bash
docker cp /tmp/opencanary_rules.xml single-node-wazuh.manager-1:/var/ossec/ruleset/rules/opencanary_rules.xml
docker restart single-node-wazuh.manager-1
```

### Por qué `type="pcre2"` en los campos

Wazuh por defecto hace comparación exacta de strings. El campo `logtype` en el JSON de OpenCanary es un número entero, pero Wazuh lo parsea como string. Al usar `type="pcre2"` permitimos que la comparación sea mediante expresión regular, lo que es más robusto y funciona correctamente con valores numéricos.

### Habilitar archivado completo para debugging

Para verificar que todos los eventos llegan correctamente al manager (aunque no disparen reglas), habilitamos el archivado completo:

En el `wazuh_manager.conf`, dentro de `<global>`:

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Esto guarda todos los eventos en `/var/ossec/logs/archives/archives.json`, lo que es muy útil para debugging.

---

## 9. Verificación de la integración

### Verificar el flujo completo

**1. Generar alerta SSH:**

```bash
ssh root@192.168.20.4 -p 2222
# Introducir contraseña incorrecta
```

**2. Verificar en el log de OpenCanary:**

```bash
pct exec 103 -- bash -c "tail -3 /var/log/opencanary.log"
```

**3. Verificar en alertas de Wazuh:**

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 grep 'OpenCanary' /var/ossec/logs/alerts/alerts.json | tail -2"
```

**4. Verificar en archives (todos los eventos):**

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 grep 'opencanary' /var/ossec/logs/archives/archives.json | tail -2"
```

### Tipos de eventos generados por servicio

| Servicio | logtype | Datos capturados |
| --- | --- | --- |
| SSH (conexión) | 4000 | SESSION ID |
| SSH (versión) | 4001 | LOCALVERSION, REMOTEVERSION |
| SSH (login) | 4002 | USERNAME, PASSWORD, versiones |
| HTTP | 3000 | HOSTNAME, PATH, USERAGENT, SKIN |
| MySQL | 8001 | USERNAME, PASSWORD (hash) |
| FTP | 2000 | USERNAME, PASSWORD |
| SMB | 5000 | datos de conexión |

---

## 10. Resumen de la arquitectura final

### Diagrama de flujo de alertas

```
OpenCanary (lxc-honeypot 192.168.20.4)
    │
    │ escribe JSON en /var/log/opencanary.log
    ▼
Wazuh Agent (lxc-honeypot)
    │
    │ TCP → 192.168.20.1:1514
    ▼
socat relay (host Proxmox)
    │
    │ TCP → 192.168.20.3:21514
    ▼
socat relay (lxc-soc-core)
    │
    │ TCP → 172.18.0.2:1514
    ▼
wazuh-remoted (Docker container)
    │
    │ procesa con decoder json
    ▼
wazuh-analysisd
    │
    │ aplica reglas 100200-100206
    ▼
Alerta nivel 12 en alerts.json
    │
    ▼
Wazuh Dashboard (https://100.92.243.96)
```

### Servicios en ejecución tras la implementación

**En el host Proxmox:**
- `wazuh-relay.service` — socat 192.168.20.1:1514 → 192.168.20.3:21514
- `wazuh-relay-enroll.service` — socat 192.168.20.1:1515 → 192.168.20.3:21515

**En lxc-honeypot (103):**
- `opencanary.service` — honeypots SSH, HTTP, FTP, MySQL, SMB
- `wazuh-agent` — agente ID 003, leyendo /var/log/opencanary.log

**En lxc-soc-core (101):**
- `wazuh-docker-relay.service` — socat 21514 → 172.18.0.2:1514
- `wazuh-docker-relay-enroll.service` — socat 21515 → 172.18.0.2:1515

### Estado final verificado

```
ID: 000, Name: wazuh.manager,  IP: 127.0.0.1,     Active/Local
ID: 001, Name: vm-windows-ad,  IP: any,            Active
ID: 003, Name: lxc-honeypot,   IP: 192.168.20.4,   Active
```

### Reglas personalizadas activas

| ID | Nivel | Descripción |
| --- | --- | --- |
| 100200 | 10 | Honeypot interaction detected |
| 100201 | 12 | SSH login attempt |
| 100203 | 12 | MySQL login attempt |
| 100204 | 12 | HTTP request |
| 100205 | 12 | FTP login attempt |
| 100206 | 12 | SMB connection attempt |
