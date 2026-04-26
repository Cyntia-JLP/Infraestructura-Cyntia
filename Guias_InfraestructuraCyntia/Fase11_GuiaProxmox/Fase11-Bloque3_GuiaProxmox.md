# Guías Proxmox - Fase 11 - Bloque 3

Notificaciones Telegram en playbooks

## Objetivo y arquitectura

El objetivo es que cada vez que Wazuh ejecute un playbook de respuesta automática, el equipo SOC reciba un mensaje en Telegram con información clara sobre qué ocurrió, sobre qué sistema, cuándo y por qué.

### Flujo completo

```
Evento detectado (honeypot / LDAP / Suricata)
        ↓
Wazuh genera alerta con regla X
        ↓
Wazuh ejecuta playbook como active response
        ↓
Playbook realiza su acción principal
        ↓
Playbook envía notificación a Telegram
```

### Formato de entrada de Wazuh

Cuando Wazuh ejecuta un active response automáticamente, envuelve la alerta en un formato especial:

```json
{
  "version": 1,
  "command": "add",
  "parameters": {
    "alert": {
      "rule": {"id": "100201", "level": 14, "description": "..."},
      "agent": {"id": "003", "name": "lxc-honeypot"},
      "timestamp": "2026-04-25T10:00:00",
      "data": {"srcip": "185.220.101.1", "dst_port": "2222"}
    }
  }
}
```

Todos los scripts deben desempaquetar `parameters.alert` antes de leer los datos:

```python
alert = json.loads(sys.stdin.read())
if "parameters" in alert and "alert" in alert.get("parameters", {}):
    alert = alert["parameters"]["alert"]
```

---

## 1. notify_telegram.py — active response directo

Script independiente registrado como active response en Wazuh. Se ejecuta automáticamente cuando se detectan alertas críticas de OpenCanary o LDAP.

### Ubicación

- `/opt/cyntia-playbooks/notify_telegram.py` (en lxc-soc-core)
- `/var/ossec/active-response/bin/notify_telegram.py` (en contenedor Wazuh)
- `/var/lib/docker/volumes/single-node_wazuh_active_response/_data/notify_telegram.py` (volumen persistente)

### Código

```python
#!/usr/bin/env python3
import sys, json, datetime, urllib.request, urllib.parse

BOT_TOKEN = "-"
CHAT_ID   = "-"

ICONOS = {
    "100201":"🚨","100202":"🚨","100203":"🔴",
    "100204":"⚠️","100205":"⚠️","100206":"🍯","100200":"🍯",
    "5710":"🔨","5712":"🔨","5763":"🔨","2502":"🔨",
    "5901":"👤","5902":"👤",
}

DESCRIPCIONES = {
    "100200":"Actividad detectada en honeypot",
    "100201":"Conexion SSH al honeypot",
    "100202":"Intento de login SSH con credenciales en honeypot",
    "100203":"LOGIN SSH COMPLETADO - INTRUSION CRITICA",
    "100204":"Peticion HTTP al honeypot",
    "100205":"Conexion MySQL al honeypot",
    "100206":"Actividad generica en honeypot",
    "5710":"Multiples intentos SSH fallidos (brute force)",
    "5712":"Ataque SSH por fuerza bruta detectado",
    "5763":"Posible ataque SSH detectado",
    "2502":"Multiples autenticaciones fallidas",
    "5901":"Nuevo usuario creado en el sistema",
    "5902":"Nuevo grupo creado en el sistema",
}

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("/var/ossec/logs/active-responses.log", "a") as f:
        f.write("[" + ts + "] [notify_telegram] " + msg + "\n")

def send_telegram(message):
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
        log("Mensaje enviado OK")
    except Exception as e:
        log("ERROR enviando: " + str(e))

def main():
    try:
        raw = json.loads(sys.stdin.read())
    except Exception as e:
        log("ERROR parseando JSON: " + str(e))
        sys.exit(1)

    # Desempaquetar formato Wazuh
    if "parameters" in raw and "alert" in raw.get("parameters", {}):
        alert = raw["parameters"]["alert"]
    else:
        alert = raw

    rule_id   = str(alert.get("rule", {}).get("id", ""))
    level     = str(alert.get("rule", {}).get("level", 0))
    desc      = alert.get("rule", {}).get("description", "Alerta")
    agente    = alert.get("agent", {}).get("name", "desconocido")
    timestamp = str(alert.get("timestamp", ""))[:19].replace("T", " ")
    data      = alert.get("data", {})

    src_ip   = data.get("src_host") or data.get("srcip") or data.get("src_ip") or "desconocida"
    dst_host = str(data.get("dst_host", ""))
    dst_port = str(data.get("dst_port", ""))

    icono       = ICONOS.get(rule_id, "⚠️")
    descripcion = DESCRIPCIONES.get(rule_id, desc)

    lineas = [
        icono + " *ALERTA CYNTIA SOC*",
        "━━━━━━━━━━━━━━━━━━━━",
        "📋 *Descripcion:* " + descripcion,
        "🎯 *Nivel:* " + level + "/15",
        "🖥️ *Agente:* " + agente,
        "🕐 *Hora:* " + timestamp,
    ]

    if src_ip and src_ip != "desconocida":
        lineas.append("📍 *IP origen:* `" + src_ip + "`")
    if dst_host and dst_port:
        lineas.append("🎯 *Destino:* " + dst_host + ":" + dst_port)
    elif dst_port:
        lineas.append("🎯 *Puerto:* " + dst_port)

    lineas.append("🔑 *Regla:* #" + rule_id)

    if rule_id == "100203":
        lineas.append("\n🔴 *ACCION REQUERIDA: Revisar honeypot inmediatamente*")

    log("Procesando regla=" + rule_id + " agente=" + agente + " src=" + src_ip)
    send_telegram("\n".join(lineas))

if __name__ == "__main__":
    main()
```

### Registro en ossec.conf

```xml
<command>
    <name>notify-telegram</name>
    <executable>notify_telegram.py</executable>
    <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
    <command>notify-telegram</command>
    <location>server</location>
    <rules_id>100201,100202,100203,100204,100205,5710,5712,2502,5901,5902</rules_id>
</active-response>
```

**Importante:** `<location>server</location>` — el script corre en el manager, no en el agente. Si se pone `local`, Wazuh intentará ejecutarlo en el agente donde no existe.

---

## 2. block_ip.py — notificación de bloqueo

### Mensaje que llega a Telegram

```
🔒 IP BLOQUEADA — Cyntia SOC
━━━━━━━━━━━━━━━━━━━━
📍 IP: 185.220.101.1
⏱️ Duracion: 24 horas
🕐 Hora: 2026-04-25 10:53:33
🔑 Accion: Bloqueada en nftables
```

### Función añadida al script

```python
def notify_telegram(ip):
    try:
        import urllib.request, urllib.parse, datetime
        url = "https://api.telegram.org/bot8732029794:-/sendMessage"
        msg = (
            "🔒 *IP BLOQUEADA — Cyntia SOC*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📍 *IP:* `" + ip + "`\n"
            "⏱️ *Duracion:* 24 horas\n"
            "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
            "🔑 *Accion:* Bloqueada en nftables"
        )
        data = urllib.parse.urlencode({"chat_id": "-1003716097465", "text": msg, "parse_mode": "Markdown"}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        log("ERROR Telegram: " + str(e))
```

Se llama tras el bloqueo exitoso: `notify_telegram(ip)` — sin el parámetro `razon` ya que en block_ip la razón siempre es la misma.

---

## 3. isolate_host.py — notificación de aislamiento

### Mensaje que llega a Telegram

```
🔴 HOST AISLADO — Cyntia SOC
━━━━━━━━━━━━━━━━━━━━
🖥️ Host: 192.168.10.5
⚡ Accion: Aislamiento completo de red
⏱️ Duracion: Hasta liberacion manual
🕐 Hora: 2026-04-25 09:22:29
📋 Razon: Conexion SSH al honeypot
⚠️ ACCION REQUERIDA: Revisar incidente inmediatamente
```

### Función añadida al script

```python
def notify_telegram(mensaje):
    try:
        import urllib.request, urllib.parse
        url = "https://api.telegram.org/bot{}/sendMessage".format(
            "-"
        )
        data = urllib.parse.urlencode({
            "chat_id": "-",
            "text": mensaje,
            "parse_mode": "Markdown"
        }).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        log("ERROR Telegram: " + str(e))
```

La llamada incluye la razón extraída de la alerta:

```python
razon = alert.get("rule", {}).get("description", "Actividad sospechosa detectada")
log(f"Alerta recibida - Aislando host:{ip}")
isolate_host(ip, razon)
```

La función `isolate_host` acepta `razon` como parámetro:

```python
def isolate_host(ip, razon="Actividad sospechosa detectada"):
    # ... lógica de aislamiento ...
    log(f"Host aislado:{ip}")
    notify_telegram(
        "🔴 *HOST AISLADO — Cyntia SOC*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🖥️ *Host:* `" + ip + "`\n"
        "⚡ *Accion:* Aislamiento completo de red\n"
        "⏱️ *Duracion:* Hasta liberacion manual\n"
        "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
        "📋 *Razon:* " + razon + "\n"
        "⚠️ *ACCION REQUERIDA: Revisar incidente inmediatamente*"
    )
```

---

## 4. disable_ldap_user.py — notificación de usuario deshabilitado

### Mensaje que llega a Telegram

```
👤 USUARIO DESHABILITADO — Cyntia SOC
━━━━━━━━━━━━━━━━━━━━
🏢 Cliente: MedTrans Iberica S.L.
👤 Usuario: ijimenez
⚡ Accion: Shell /bin/false + contrasena invalidada
🕐 Hora: 2026-04-25 09:33:56
📋 Razon: Intento de login SSH con credenciales en honeypot
⚠️ Revisar si es falso positivo
```

### Mismo patrón que isolate_host

```python
razon = alert.get("rule", {}).get("description", "Actividad sospechosa detectada")
log(f"Alerta recibida - Aislando usuario:{username}")
disable_user(username, razon)
```

```python
def disable_user(username, razon="Actividad sospechosa detectada"):
    # ... lógica de deshabilitación LDAP ...
    log(f"AISLAMIENTO COMPLETO:{username} ({dn})")
    notify_telegram(
        "👤 *USUARIO DESHABILITADO — Cyntia SOC*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🏢 *Cliente:* MedTrans Iberica S.L.\n"
        "👤 *Usuario:* `" + username + "`\n"
        "⚡ *Accion:* Shell /bin/false + contrasena invalidada\n"
        "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
        "📋 *Razon:* " + razon + "\n"
        "⚠️ *Revisar si es falso positivo*"
    )
```

### Reactivar usuario manualmente

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "
python3 /var/ossec/active-response/bin/disable_ldap_user.py --enable <username>
"
```

---

## 5. create_ticket.py — ya tenía Telegram

`create_ticket.py` ya incluía notificación Telegram desde la implementación inicial. Durante esta sesión se corrigió el desempaquetado de `parameters.alert` para que los campos (severidad, agente, IP) aparezcan correctamente en lugar de “N/A”.

### Mensaje corregido

```
🚨 NUEVA INCIDENCIA - Cyntia SOC

🎫 Ticket: TKT-20260425-100454
⚠️ Severidad: 15
📋 Descripción: LOGIN SSH COMPLETADO EN HONEYPOT
🖥️ Agente: lxc-honeypot (N/A)
🌐 IP origen: 185.220.101.1
👤 Usuario: N/A
🕐 Hora: 2026-04-25 11:03:28

Revisa el panel de Wazuh para más detalles.
```

---

## 6. threat_intel.py — notificación con score

### Mensaje que llega a Telegram

```
🔴 THREAT INTEL — Cyntia SOC
━━━━━━━━━━━━━━━━━━━━
📍 IP analizada: 185.220.101.1
🔍 Veredicto: MALICIOSA
📊 AbuseIPDB score: 100%
🌐 OTX pulses: 0
🕐 Hora: 2026-04-25 11:03:40
🔒 Accion: IP bloqueada automaticamente
```

### Función añadida

```python
def notify_telegram_ti(ip, veredicto, score_abuse, pulses_otx):
    try:
        import urllib.request, urllib.parse, datetime
        url = "https://api.telegram.org/bot8732029794:-/sendMessage"
        icono = "🔴" if veredicto == "MALICIOSA" else "✅"
        msg = (
            icono + " *THREAT INTEL — Cyntia SOC*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📍 *IP analizada:* `" + ip + "`\n"
            "🔍 *Veredicto:* " + veredicto + "\n"
            "📊 *AbuseIPDB score:* " + str(score_abuse) + "%\n"
            "🌐 *OTX pulses:* " + str(pulses_otx) + "\n"
            "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
            + ("🔒 *Accion:* IP bloqueada automaticamente" if veredicto == "MALICIOSA" else "ℹ️ *Accion:* Sin bloqueo")
        )
        data = urllib.parse.urlencode({"chat_id": "-1003716097465", "text": msg, "parse_mode": "Markdown"}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        log("ERROR Telegram TI: " + str(e))
```

Se llama al final de `analyze_ip()`:

```python
score = abuse["score"] if abuse else 0
pulses = otx["pulses"] if otx else 0
notify_telegram_ti(ip, verdict, score, pulses)
```

---

## 7. Dependencias en contenedor Wazuh

Los scripts `isolate_host.py` y `disable_ldap_user.py` requieren `socat` y `ldapsearch` respectivamente. El contenedor Wazuh (Amazon Linux 2023) no los incluye por defecto.

### Instalación manual

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "
/usr/bin/dnf install -y socat openldap-clients 2>&1 | tail -5
socat -V 2>&1 | head -1
ldapsearch --version 2>&1 | head -1
"
```

### Persistencia tras reinicios

Las instalaciones en el contenedor se pierden si Docker recrea el contenedor. Para que sean persistentes, se añadió al final de `cyntia-start.sh`:

```bash
# En /usr/local/bin/cyntia-start.sh (host Proxmox)
# Instalar dependencias necesarias para los playbooks en el contenedor Wazuh
sleep 30
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /usr/bin/dnf install -y socat openldap-clients > /dev/null 2>&1 || true
```

---

## 8. Persistencia de scripts

Los scripts en `/var/ossec/active-response/bin/` dentro del contenedor Docker están montados en el volumen `single-node_wazuh_active_response`. Hay que copiar los scripts TANTO al contenedor como al volumen para garantizar persistencia:

```bash
pct exec 101 -- bash -c "
for script in block_ip isolate_host disable_ldap_user create_ticket threat_intel notify_telegram; do
    # Copiar al contenedor (uso inmediato)
    docker cp /opt/cyntia-playbooks/\${script}.py\
      single-node-wazuh.manager-1:/var/ossec/active-response/bin/
    docker exec single-node-wazuh.manager-1 chmod 750\
      /var/ossec/active-response/bin/\${script}.py
    docker exec single-node-wazuh.manager-1 chown root:wazuh\
      /var/ossec/active-response/bin/\${script}.py

    # Copiar al volumen persistente (sobrevive reinicios del contenedor)
    cp /opt/cyntia-playbooks/\${script}.py\
       /var/lib/docker/volumes/single-node_wazuh_active_response/_data/\${script}.py
    chmod 750 /var/lib/docker/volumes/single-node_wazuh_active_response/_data/\${script}.py
    echo\"\${script} → OK\"
done
"
```

---

## 9. Problemas encontrados y soluciones

### Problema 1: `location: local` vs `location: server`

**Síntoma:** `notify_telegram` registraba “Mensaje enviado OK” en el log pero Telegram no recibía nada cuando Wazuh lo ejecutaba automáticamente.

**Causa:** Con `location: local`, Wazuh intenta ejecutar el script en el agente que generó la alerta (lxc-honeypot), donde el script no existe.

**Solución:** Cambiar a `location: server` para que se ejecute en el manager.

```xml
<active-response>
    <command>notify-telegram</command>
    <location>server</location>  <!-- NO local -->
    <rules_id>...</rules_id>
</active-response>
```

### Problema 2: `parameters.alert` no desenvuelto

**Síntoma:** Los playbooks ejecutaban sin errores pero los mensajes de Telegram mostraban “descripcion: Alerta”, “nivel: 0/15”, “agente: desconocido”.

**Causa:** Wazuh envuelve la alerta en `parameters.alert` al llamar a un active response. Los scripts leían el JSON directamente sin desempaquetar.

**Solución:** Añadir desempaquetado al inicio de cada función `main()`:

```python
raw = json.loads(sys.stdin.read())
if "parameters" in raw and "alert" in raw.get("parameters", {}):
    alert = raw["parameters"]["alert"]
else:
    alert = raw
```

### Problema 3: `razon` not defined en funciones internas

**Síntoma:** `NameError: name 'razon' is not defined` en `disable_user()` y `isolate_host()`.

**Causa:** `razon` se extraía en `main()` pero la llamada a `notify_telegram` estaba dentro de la función `disable_user()` o `isolate_host()`, que no tenían acceso a esa variable.

**Solución:** Pasar `razon` como parámetro a las funciones:

```python
# En main():
razon = alert.get("rule", {}).get("description", "Actividad sospechosa")
disable_user(username, razon)

# En la función:
def disable_user(username, razon="Actividad sospechosa detectada"):
    ...
```

### Problema 4: `socat` y `ldapsearch` no disponibles en contenedor

**Síntoma:** `[Errno 2] No such file or directory: 'socat'` y `FileNotFoundError: 'ldapsearch'`.

**Causa:** El contenedor Wazuh (Amazon Linux 2023) no incluye estas herramientas.

**Solución:** Instalar con `dnf` y añadir al `cyntia-start.sh` para persistencia.

### Problema 5: Script ossec.conf con bloque `notify-telegram` fuera de `<ossec_config>`

**Síntoma:** El active response `notify-telegram` estaba registrado pero Wazuh nunca lo ejecutaba.

**Causa:** Al añadir el bloque XML, quedó posicionado fuera del último `</ossec_config>`, haciendo que Wazuh lo ignorara.

**Solución:** Reescribir el ossec.conf asegurando que el bloque queda dentro del último `<ossec_config>`:

```python
last_pos = content.rfind('</ossec_config>')
content = content[:last_pos] + bloque_notify + '\n\n</ossec_config>' + content[last_pos+15:]
```

---

## 10. Verificación y tests

### Test manual de cada playbook

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "
# Template JSON de Wazuh para tests
ALERT='{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{
\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Conexion SSH al honeypot\"},
\"agent\":{\"id\":\"003\",\"name\":\"lxc-honeypot\"},
\"timestamp\":\"2026-04-25T11:00:00\",
\"data\":{\"srcip\":\"185.220.101.1\",\"dst_host\":\"192.168.10.4\",\"dst_port\":\"2222\"}}}}'

echo '=== block_ip ==='
echo\$ALERT | python3 /var/ossec/active-response/bin/block_ip.py
sleep 2

echo '=== notify_telegram ==='
echo\$ALERT | python3 /var/ossec/active-response/bin/notify_telegram.py
sleep 2

echo '=== isolate_host (IP no privada) ==='
echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Test\"},\"agent\":{\"name\":\"lxc-honeypot\",\"ip\":\"185.220.101.1\"},\"timestamp\":\"2026-04-25T11:00:00\",\"data\":{\"srcip\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/isolate_host.py
sleep 2

echo '=== disable_ldap_user ==='
echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100202\",\"level\":15,\"description\":\"Intento de login SSH con credenciales en honeypot\"},\"agent\":{\"name\":\"lxc-ldap\"},\"timestamp\":\"2026-04-25T11:00:00\",\"data\":{\"srcip\":\"192.168.10.2\",\"dstuser\":\"agarcia\"}}}}' | python3 /var/ossec/active-response/bin/disable_ldap_user.py
sleep 2

echo '=== create_ticket ==='
echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100203\",\"level\":15,\"description\":\"LOGIN SSH COMPLETADO EN HONEYPOT\"},\"agent\":{\"id\":\"003\",\"name\":\"lxc-honeypot\"},\"timestamp\":\"2026-04-25T11:00:00\",\"data\":{\"srcip\":\"185.220.101.1\",\"src_host\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/create_ticket.py
sleep 2

echo '=== threat_intel ==='
echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Conexion SSH al honeypot\"},\"agent\":{\"name\":\"lxc-honeypot\"},\"timestamp\":\"2026-04-25T11:00:00\",\"data\":{\"srcip\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/threat_intel.py
"
```

### Verificar log de active responses

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  tail -20 /var/ossec/logs/active-responses.log
```

### Reactivar usuarios de prueba

Tras los tests, varios usuarios LDAP quedan deshabilitados. Reactivarlos:

```bash
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "
for user in agarcia rlopez mfernandez cnavarro lsanchez pmoreno ijimenez jmartinez; do
    python3 /var/ossec/active-response/bin/disable_ldap_user.py --enable\$user 2>/dev/null
    echo\"\$user reactivado\"
done
"

# Verificar estado final
pct exec 201 -- ldapsearch -x -H ldap://localhost \
  -D 'cn=admin,dc=cyntia,dc=local' -w 'LDAP$$C7n74#&&' \
  -b 'ou=MedTrans,dc=cyntia,dc=local' \
  '(objectClass=inetOrgPerson)' uid loginShell 2>/dev/null \
  | grep -E '^uid:|^loginShell:'
```

### Resumen mensajes Telegram

| Playbook | Icono | Datos en el mensaje |
| --- | --- | --- |
| `block_ip` | 🔒 | IP, duración, hora, acción |
| `isolate_host` | 🔴 | Host IP, acción, duración, hora, razón |
| `disable_ldap_user` | 👤 | Cliente, usuario, acción, hora, razón |
| `create_ticket` | 🚨 | Ticket ID, severidad, descripción, agente, IP, hora |
| `threat_intel` | 🔴/✅ | IP, veredicto, score AbuseIPDB, OTX pulses, hora, acción |
| `notify_telegram` | Variable | Descripción, nivel, agente, hora, IP, destino, regla |