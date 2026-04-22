# Guía Proxmox - Fase 10

**Infraestructura fase 10: Playbooks de Respuesta Automática y Threat Intelligence**

---

## 1. Contexto y objetivos

En este punto del proyecto Cyntia, toda la infraestructura de detección estaba operativa: Wazuh recibía alertas de Suricata, OpenCanary y los agentes de lxc-honeypot y lxc-ldap. Sin embargo, la detección por sí sola no es suficiente en un SOC real — cuando se detecta una amenaza, el sistema debe poder **reaccionar automáticamente** sin esperar intervención humana.

El objetivo de esta sesión fue implementar los **playbooks de respuesta automática**, que son scripts Python que Wazuh ejecuta automáticamente cuando se dispara una regla concreta. Además, se integró **Threat Intelligence** para que el sistema pueda consultar bases de datos globales de IPs maliciosas antes de tomar decisiones.

El flujo completo queda así:

```
Wazuh detecta alerta
        ↓
Active Response dispara playbook
        ↓
Playbook consulta Threat Intel (AbuseIPDB/OTX)
        ↓
Si es maliciosa → block_ip + disable_user + isolate_host
        ↓
create_ticket → JSON local + notificación Telegram
```

---

## 2. Preparación del entorno nftables

Antes de crear ningún playbook, necesitábamos un mecanismo en el firewall para poder bloquear IPs dinámicamente sin reiniciar nftables. nftables soporta **sets** — estructuras de datos que pueden modificarse en caliente.

### 2.1 Añadir el set blocked_ips al fichero nftables.conf

El fichero `/etc/nftables.conf` del host Proxmox quedó con esta estructura añadida:

```
table inet filter {

    # Set de IPs bloqueadas automáticamente por los playbooks
    set blocked_ips {
        type ipv4_addr
        flags dynamic, timeout
        timeout 24h
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Bloquear IPs marcadas por playbooks
        ip saddr @blocked_ips drop

        # ... resto de reglas ...
    }
}
```

**Por qué así:**
- `flags dynamic` permite añadir y eliminar elementos en tiempo real sin reiniciar el servicio
- `timeout 24h` hace que las IPs se desbloqueen automáticamente tras 24 horas
- La regla `ip saddr @blocked_ips drop` va al principio del chain input para que sea lo primero que se evalúe

### 2.2 Aplicar y verificar

```bash
systemctl restart nftables
nft list set inet filter blocked_ips
```

La salida correcta muestra el set vacío:

```
table inet filter {
    set blocked_ips {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1d
    }
}
```

---

## 3. Relay nftables para playbooks

### 3.1 Por qué necesitamos un relay

Los playbooks se ejecutan dentro del contenedor Docker de Wazuh (en lxc-soc-core, VLAN20). Ese contenedor no tiene acceso directo a nftables del host Proxmox — son niveles de aislamiento completamente diferentes.

La solución es el **patrón socat relay** que ya hemos usado en el proyecto: creamos un proceso en el host que escucha en un puerto de VLAN20, recibe comandos en texto plano y los ejecuta localmente.

### 3.2 Script del relay

```bash
cat > /usr/local/bin/nftables-relay.sh << 'EOF'
#!/bin/bash
while true; do
    CMD=$(socat -T5 TCP-LISTEN:7777,bind=192.168.20.1,reuseaddr -)

    if echo "$CMD" | grep -q "^nft add element inet filter blocked_ips"; then
        IP=$(echo "$CMD" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [ -n "$IP" ]; then
            nft add element inet filter blocked_ips { $IP timeout 24h }
            echo "[$(date)] IP bloqueada: $IP" >> /var/log/cyntia-blocks.log
        fi

    elif echo "$CMD" | grep -q "^nft delete element inet filter blocked_ips"; then
        IP=$(echo "$CMD" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [ -n "$IP" ]; then
            nft delete element inet filter blocked_ips { $IP }
            echo "[$(date)] IP liberada: $IP" >> /var/log/cyntia-blocks.log
        fi
    fi
done
EOF
chmod +x /usr/local/bin/nftables-relay.sh
```

**Por qué se filtra el comando:** el relay solo acepta dos comandos específicos (`add` y `delete`) para evitar inyección de comandos arbitrarios. Cualquier otra cosa se ignora.

### 3.3 Servicio systemd

```bash
cat > /etc/systemd/system/nftables-relay.service << 'EOF'
[Unit]
Description=nftables relay para playbooks Cyntia
After=network.target nftables.service

[Service]
ExecStart=/usr/local/bin/nftables-relay.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nftables-relay
systemctl start nftables-relay
```

### 3.4 Abrir el puerto en nftables

En `chain input` del nftables.conf:

```
# Relay playbooks - comandos nftables desde lxc-soc-core
iifname "vmbr0.20" tcp dport 7777 accept
```

---

## 4. Playbook block_ip.py

### 4.1 Ubicación y propósito

- **Ruta:** `/opt/cyntia-playbooks/block_ip.py` (en lxc-soc-core)
- **Propósito:** Bloquear automáticamente una IP maliciosa en el firewall del host
- **Activación:** Cuando Wazuh detecta alertas de OpenCanary (reglas 100201, 100203, 100204)

### 4.2 Lógica del script

```python
#!/usr/bin/env python3
import sys, json, subprocess, datetime

LOG_FILE = "/var/ossec/logs/active-responses.log"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [block_ip]{msg}\n")

def block_ip(ip):
    try:
        cmd = f"nft add element inet filter blocked_ips{{{ip}}}"
        result = subprocess.run(
            ["socat", "-", "TCP:192.168.20.1:7777"],
            input=cmd.encode(),
            capture_output=True,
            timeout=5
        )
        log(f"IP bloqueada:{ip}")
        return True
    except Exception as e:
        log(f"ERROR bloqueando{ip}:{e}")
        return False

def main():
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)
        ip = alert.get("data", {}).get("srcip") or \
             alert.get("data", {}).get("src_ip") or \
             alert.get("data", {}).get("src_host")

        if not ip:
            log("No se encontró IP en la alerta")
            sys.exit(1)

        # No bloquear IPs privadas
        private = ["192.168.", "10.", "172.", "127."]
        if any(ip.startswith(p) for p in private):
            log(f"IP privada ignorada:{ip}")
            sys.exit(0)

        log(f"Alerta recibida - Bloqueando IP:{ip}")
        block_ip(ip)

    except json.JSONDecodeError:
        log(f"Error parseando JSON")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### 4.3 Preparación previa

```bash
# Crear fichero de log de Wazuh
pct exec 101 -- bash -c "mkdir -p /var/ossec/logs && touch /var/ossec/logs/active-responses.log && chmod 660 /var/ossec/logs/active-responses.log"
```

### 4.4 Prueba

```bash
pct exec 101 -- bash -c "echo '{\"data\": {\"srcip\":\"5.6.7.8\"}}' | python3 /opt/cyntia-playbooks/block_ip.py"
nft list set inet filter blocked_ips
```

---

## 5. Playbook disable_ldap_user.py

### 5.1 Propósito

Cuando se detecta actividad sospechosa asociada a un usuario, este playbook lo aísla completamente:
1. Cambia `loginShell` a `/bin/false` — impide login en sistemas Linux
2. Cambia la contraseña por una aleatoria imposible — bloquea todos los servicios LDAP
3. Añade al usuario al grupo `disabled` — trazabilidad y auditoría

También incluye modo `--enable` para reactivar el usuario manualmente.

### 5.2 Dependencias

```bash
# Instalar solo herramientas cliente LDAP (ligero)
pct exec 101 -- bash -c "apt-get install -y ldap-utils"
```

**Nota importante:** `slappasswd` no está disponible sin instalar el servidor completo. Se genera el hash SSHA directamente con Python:

```python
def get_hashed_password(password):
    import hashlib, base64, os
    salt = os.urandom(4)
    sha = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(sha + salt).decode()
```

### 5.3 Uso

```bash
# Deshabilitar (automático desde Wazuh o manual):
echo '{"data": {"srcuser": "agarcia"}}' | python3 /opt/cyntia-playbooks/disable_ldap_user.py

# Reactivar manualmente:
python3 /opt/cyntia-playbooks/disable_ldap_user.py --enable agarcia
```

**Tras reactivar**, hay que cambiar la contraseña manualmente desde LAM en `http://100.92.243.96:8080/lam` porque el script la invalidó con un valor aleatorio.

---

## 6. Playbook isolate_host.py

### 6.1 Diferencia con disable_ldap_user.py

- `disable_ldap_user.py` actúa sobre la **identidad** del usuario
- `isolate_host.py` actúa sobre el **dispositivo** en la red

En un ataque real se usan los dos juntos: se deshabilita al usuario comprometido Y se aísla su equipo.

### 6.2 Lógica

Usa el mismo relay socat que block_ip.py, enviando el comando `nft add element` con la IP del agente comprometido:

```python
def isolate_host(ip):
    send_nft_command(f"nft add element inet filter blocked_ips{{{ip} timeout 24h}}")
    log(f"Host aislado:{ip}")

def release_host(ip):
    send_nft_command(f"nft delete element inet filter blocked_ips{{{ip}}}")
    log(f"Host liberado:{ip}")
```

### 6.3 IPs protegidas

El script nunca aísla IPs del SOC ni del gateway:

```python
protected = ["192.168.20.", "192.168.3.1", "127."]
if any(ip.startswith(p) for p in protected):
    log(f"IP protegida, no se aísla:{ip}")
    sys.exit(0)
```

### 6.4 Uso

```bash
# Aislar (automático desde Wazuh o manual):
echo '{"agent": {"ip": "192.168.10.5"}}' | python3 /opt/cyntia-playbooks/isolate_host.py

# Liberar manualmente:
python3 /opt/cyntia-playbooks/isolate_host.py --release 192.168.10.5
```

---

## 7. Playbook create_ticket.py y bot Telegram

### 7.1 Propósito

Cada vez que Wazuh detecta una alerta de los grupos opencanary o honeypot:
1. Crea un fichero JSON con todos los detalles del incidente
2. Envía una notificación inmediata al grupo de Telegram del equipo SOC

### 7.2 Configuración del bot Telegram

**Crear el bot:**
1. Buscar `@BotFather` en Telegram
2. Ejecutar `/newbot`
3. Asignar nombre y username
4. Guardar el token generado

**Obtener el Chat ID del grupo:**
1. Crear grupo de Telegram con todos los miembros del equipo
2. Añadir el bot al grupo
3. Enviar un mensaje mencionando al bot
4. Ejecutar: `curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"`
5. El Chat ID está en `result[].message.chat.id` (valor negativo para grupos)

### 7.3 Estructura del ticket

Cada ticket se guarda en `/opt/cyntia-playbooks/tickets/TKT-YYYYMMDD-HHMMSS.json`:

```json
{
  "id": "TKT-20260416-181506",
  "timestamp": "2026-04-16 18:15:06",
  "status": "abierto",
  "rule_id": "100201",
  "description": "SSH login attempt on honeypot",
  "severity": 12,
  "agent": "lxc-honeypot",
  "agent_ip": "192.168.20.4",
  "src_ip": "1.2.3.4",
  "src_user": "root"
}
```

### 7.4 Mensaje Telegram

El bot envía al grupo un mensaje formateado con todos los detalles de la incidencia, permitiendo que los 3 miembros del equipo sean notificados simultáneamente en tiempo real.

---

## 8. Threat Intelligence — AbuseIPDB y OTX

### 8.1 Propósito

Antes de tomar decisiones automáticas, el sistema consulta dos fuentes externas de inteligencia de amenazas para confirmar si una IP es realmente maliciosa:

- **AbuseIPDB:** base de datos colaborativa de IPs reportadas por la comunidad. Devuelve un score de 0-100%.
- **AlienVault OTX:** plataforma de threat intelligence que agrupa indicadores de compromiso (IoCs) en “pulsos”. Si una IP aparece en pulsos, es sospechosa.

### 8.2 Lógica de veredicto

```python
is_malicious = False
if abuse and abuse["score"] >= 50:    # AbuseIPDB con score alto
    is_malicious = True
if otx and otx["pulses"] > 0:         # OTX con indicadores
    is_malicious = True
```

Si cualquiera de las dos fuentes confirma la amenaza, se activa `block_ip.py` automáticamente.

### 8.3 Prueba con IP real maliciosa

```bash
echo '{"data": {"srcip": "185.220.101.1"}}' | python3 /opt/cyntia-playbooks/threat_intel.py
```

Resultado:

```
AbuseIPDB [185.220.101.1] score=100% reports=133 country=DE isp=Artikel10 e.V.
Veredicto [185.220.101.1]: MALICIOSA
IP maliciosa confirmada - activando block_ip para 185.220.101.1
IP bloqueada: 185.220.101.1
```

### 8.4 Informes generados

Cada análisis genera un fichero JSON en `/opt/cyntia-playbooks/threat_reports/`:

```
/opt/cyntia-playbooks/threat_reports/185.220.101.1-20260419-204434.json
```

---

## 9. Registro en Wazuh como Active Responses

### 9.1 Copiar scripts al contenedor Docker de Wazuh

```bash
docker cp /opt/cyntia-playbooks/block_ip.py single-node-wazuh.manager-1:/var/ossec/active-response/bin/block_ip.py
docker cp /opt/cyntia-playbooks/disable_ldap_user.py single-node-wazuh.manager-1:/var/ossec/active-response/bin/disable_ldap_user.py
docker cp /opt/cyntia-playbooks/isolate_host.py single-node-wazuh.manager-1:/var/ossec/active-response/bin/isolate_host.py
docker cp /opt/cyntia-playbooks/create_ticket.py single-node-wazuh.manager-1:/var/ossec/active-response/bin/create_ticket.py
docker cp /opt/cyntia-playbooks/threat_intel.py single-node-wazuh.manager-1:/var/ossec/active-response/bin/threat_intel.py

# Permisos correctos
for script in block_ip.py disable_ldap_user.py isolate_host.py create_ticket.py threat_intel.py; do
    docker exec single-node-wazuh.manager-1 chmod 750 /var/ossec/active-response/bin/$script
    docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/active-response/bin/$script
done
```

### 9.2 Configuración en ossec.conf

Añadido en `/opt/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`:

```xml
<!-- PLAYBOOKS CYNTIA SOC -->

<command>
  <name>block-ip</name>
  <executable>block_ip.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>disable-ldap-user</name>
  <executable>disable_ldap_user.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>isolate-host</name>
  <executable>isolate_host.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>create-ticket</name>
  <executable>create_ticket.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>threat-intel</name>
  <executable>threat_intel.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>100201,100203,100204</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <command>disable-ldap-user</command>
  <location>local</location>
  <rules_id>100201,100202,100203</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <command>isolate-host</command>
  <location>local</location>
  <rules_id>100201,100202,100203</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <command>create-ticket</command>
  <location>local</location>
  <rules_id>100200,100201,100202,100203,100204,100205,100206</rules_id>
  <timeout>86400</timeout>
</active-response>

<active-response>
  <command>threat-intel</command>
  <location>local</location>
  <rules_id>100200,100201,100202,100203,100204,100205,100206</rules_id>
  <timeout>86400</timeout>
</active-response>
```

### 9.3 Aplicar configuración

```bash
docker exec single-node-wazuh.manager-1 bash -c "cat /wazuh-config-mount/etc/ossec.conf > /var/ossec/etc/ossec.conf"
docker restart single-node-wazuh.manager-1
sleep 30
docker exec single-node-wazuh.manager-1 grep -i "active-response" /var/ossec/logs/ossec.log | tail -3
```
