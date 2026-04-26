# Guías Proxmox - Fase 11 - Bloque 2

# Extensión de visibilidad a lxc-ldap (MedTrans Ibérica)

## Objetivo

Para la presentación del proyecto, lxc-ldap representa el servidor del cliente ficticio **MedTrans Ibérica S.L.**. El objetivo de este bloque es que todas las herramientas del SOC (Wazuh, Grafana, Prometheus, Suricata, OpenCanary) vean y analicen lxc-ldap como si fuera la infraestructura de un cliente real.

**Antes de este bloque:**
- Wazuh: agente 006 activo, pero con poca actividad
- Grafana/Prometheus: solo monitorizaban lxc-soc-core
- Suricata: solo veía tráfico VLAN20
- OpenCanary: honeypot solo en VLAN20

**Después de este bloque:**
- Prometheus: métricas de CPU/RAM/red de lxc-ldap en tiempo real
- Suricata: segunda interfaz eth1 en VLAN10
- OpenCanary: servicios trampa visibles desde VLAN10
- Script de monitorización: genera actividad y eventos cada 10 minutos

---

## 1. Node Exporter en lxc-ldap

### Instalación

```bash
pct exec 201 -- bash -c "
# Descargar Node Exporter
cd /tmp
wget -q https://github.com/prometheus/node_exporter/releases/download/v1.8.1/node_exporter-1.8.1.linux-amd64.tar.gz
tar xzf node_exporter-1.8.1.linux-amd64.tar.gz
cp node_exporter-1.8.1.linux-amd64/node_exporter /usr/local/bin/
chmod +x /usr/local/bin/node_exporter

# Crear usuario de sistema
useradd --no-create-home --shell /bin/false node_exporter 2>/dev/null || true

# Crear servicio systemd
cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable node_exporter
systemctl start node_exporter
sleep 2
systemctl is-active node_exporter
ss -tulnp | grep 9100
"
```

### Abrir puerto en nftables

Prometheus está en VLAN20 y necesita llegar a Node Exporter en VLAN10 (puerto 9100):

```bash
# En memoria (inmediato)
nft add rule inet filter forward iifname "vmbr0.20" oifname "vmbr0.10" tcp dport 9100 accept

# Verificar
nft list chain inet filter forward | grep 9100

# Persistente en /etc/nftables.conf
python3 -c "
with open('/etc/nftables.conf', 'r') as f:
    content = f.read()
content = content.replace(
    '        # VLAN20 → VLAN10 (playbooks de respuesta)',
    '        # VLAN20 → VLAN10: Prometheus scrape Node Exporter\n        iifname\"vmbr0.20\" oifname\"vmbr0.10\" tcp dport 9100 accept\n        # VLAN20 → VLAN10 (playbooks de respuesta)'
)
with open('/etc/nftables.conf', 'w') as f:
    f.write(content)
print('OK')
"
nft -c -f /etc/nftables.conf && echo 'SINTAXIS OK'
```

### Añadir lxc-ldap como target en Prometheus

```bash
pct exec 101 -- bash -c "
cat > /opt/cyntia-monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['172.20.0.2:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['172.20.0.3:9100']
        labels:
          instance: 'lxc-soc-core'
          cliente: 'SOC-interno'

  - job_name: 'node-exporter-ldap'
    static_configs:
      - targets: ['192.168.10.2:9100']
        labels:
          instance: 'lxc-ldap'
          cliente: 'MedTrans-Iberica'
EOF

# Reiniciar Prometheus
cd /opt/cyntia-monitoring && docker compose restart prometheus
sleep 20

# Verificar targets
curl -s http://172.20.0.2:9090/api/v1/targets | python3 -c\"
import sys, json
d = json.load(sys.stdin)
for t in d['data']['activeTargets']:
    print(f'{t[\\\"labels\\\"][\\\"job\\\"]} | {t[\\\"labels\\\"].get(\\\"instance\\\",\\\"?\\\")} | {t[\\\"health\\\"]}')
\"
"
```

**Resultado esperado:**

```
node-exporter | lxc-soc-core | up
node-exporter-ldap | lxc-ldap | up
prometheus | 172.20.0.2:9090 | up
```

---

## 2. Suricata en VLAN10

### Añadir interfaz eth1 a lxc-soc-core

```bash
# Añadir interfaz VLAN10 (en caliente, sin reiniciar)
pct set 101 --net1 name=eth1,bridge=vmbr0,ip=192.168.10.3/24,tag=10,type=veth

# Verificar que se añadió
pct config 101 | grep net

# Levantar la interfaz
pct exec 101 -- bash -c "
ip link set eth1 up
sleep 1
ip addr show eth1
ip route | grep 192.168.10
"
```

**Importante:** El comando puede añadir una ruta default duplicada por eth1. Hay que eliminarla:

```bash
# Eliminar gateway duplicado de eth1
pct exec 101 -- ip route del default via 192.168.10.1 dev eth1

# Verificar rutas (solo debe haber una ruta default, por eth0)
pct exec 101 -- ip route

# Hacer permanente (sin gateway en net1)
pct set 101 --net1 name=eth1,bridge=vmbr0,ip=192.168.10.3/24,tag=10,type=veth
```

### Test de conectividad

```bash
pct exec 101 -- bash -c "
ping -c3 192.168.10.2
echo 'Conectividad OK'
"
```

### Configurar Suricata para eth1

Añadir eth1 en el fichero `/etc/suricata/suricata.yaml` dentro de lxc-soc-core:

```bash
pct exec 101 -- python3 -c "
with open('/etc/suricata/suricata.yaml', 'r') as f:
    content = f.read()

eth1_config = '''  - interface: eth1
    threads: 1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: no
    tpacket-v3: no
    buffer-size: 16384

'''

content = content.replace(
    '  # Put default values here. These will be used for an interface that is not\n  # in the list above.\n  - interface: default',
    eth1_config + '  # Put default values here. These will be used for an interface that is not\n  # in the list above.\n  - interface: default'
)

with open('/etc/suricata/suricata.yaml', 'w') as f:
    f.write(content)
print('OK')
"

# Reiniciar Suricata
pct exec 101 -- bash -c "
systemctl restart suricata
sleep 10
systemctl is-active suricata

# Verificar que eth1 está en el log de arranque
grep 'eth1' /var/log/suricata/suricata.log | head -5
"
```

**Nota importante:** Se intentó primero con `use-mmap: yes` y `tpacket-v3: yes` pero no funcionaba en LXC. La configuración con `use-mmap: no` y `tpacket-v3: no` es la que funciona correctamente en entornos LXC.

### Verificar captura en eth1

```bash
pct exec 101 -- bash -c "
# Generar tráfico en VLAN10
ldapsearch -x -H ldap://192.168.10.2\
  -D 'cn=admin,dc=cyntia,dc=local'\
  -w 'LDAP\$\$C7n74#&&'\
  -b 'dc=cyntia,dc=local' '(objectClass=*)' dn 2>/dev/null | wc -l

sleep 10

# Verificar eventos en eth1
grep -c '\"in_iface\":\"eth1\"' /var/log/suricata/eve.json
grep '\"in_iface\":\"eth1\"' /var/log/suricata/eve.json | tail -3 | python3 -c\"
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f'{d[\\\"timestamp\\\"][:19]} | {d[\\\"event_type\\\"]} | {d.get(\\\"src_ip\\\",\\\"?\\\")} → {d.get(\\\"dest_ip\\\",\\\"?\\\")}')
    except: pass
\"
"
```

**Tráfico visible en eth1:**
- Prometheus scrapeando Node Exporter (puerto 9100) cada 15s
- Consultas LDAP desde lxc-soc-core hacia lxc-ldap
- Respuestas de activos de red
- Tráfico del script ldap_monitor.sh

---

## 3. OpenCanary en VLAN10

### Añadir interfaz eth1 a lxc-honeypot

```bash
# Añadir interfaz VLAN10
pct set 103 --net1 name=eth1,bridge=vmbr0,ip=192.168.10.4/24,tag=10,type=veth

# Verificar
pct config 103 | grep net

# Levantar interfaz
pct exec 103 -- bash -c "
ip link set eth1 up
sleep 1
ip addr show eth1
ip route | grep 192.168.10
"
```

**Ventaja:** OpenCanary ya escuchaba en `0.0.0.0` en todos los puertos — no hay que modificar su configuración. Al añadir eth1, automáticamente es visible desde VLAN10.

### Verificar servicios disponibles desde VLAN10

```bash
# Desde lxc-ldap (VLAN10) hacia honeypot VLAN10
pct exec 201 -- bash -c "
ping -c3 192.168.10.4
nc -zv -w3 192.168.10.4 2222 2>&1  # SSH
nc -zv -w3 192.168.10.4 8080 2>&1  # HTTP
nc -zv -w3 192.168.10.4 21   2>&1  # FTP
nc -zv -w3 192.168.10.4 3306 2>&1  # MySQL
"
```

### Test completo: evento → Wazuh

```bash
# Generar evento SSH desde lxc-ldap hacia honeypot
pct exec 201 -- bash -c "
(echo 'SSH-2.0-OpenSSH_test'; sleep 3) | nc -w4 192.168.10.4 2222
echo 'evento enviado'
"

sleep 15

# Verificar en OpenCanary
pct exec 103 -- tail -3 /var/log/opencanary.log | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('src_host'):
            print(f'logtype={d[\"logtype\"]} src={d[\"src_host\"]} dst={d.get(\"dst_host\")}:{d.get(\"dst_port\")}')
    except: pass
"

# Verificar alerta en Wazuh
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  tail -20 /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        rid = d['rule']['id']
        if rid.startswith('1002'):
            print(f'REGLA {rid} (lvl{d[\"rule\"][\"level\"]}) — {d[\"rule\"][\"description\"]}')
            print(f'  src={d.get(\"data\",{}).get(\"src_host\",\"?\")} time={d.get(\"timestamp\",\"?\")}')
    except: pass
"
```

**Flujo verificado:**

```
lxc-ldap (192.168.10.2) → honeypot VLAN10 (192.168.10.4:2222)
→ OpenCanary logtype=4000
→ agente=003 (lxc-honeypot)
→ REGLA 100201 nivel 14 — "OpenCanary: conexion SSH detectada en honeypot"
```

---

## 4. Script ldap_monitor.sh

### Propósito

El script simula la monitorización continua que un SOC gestionado haría sobre el servidor LDAP del cliente. Se ejecuta cada 10 minutos desde lxc-soc-core y produce tres efectos:

1. **Suricata** detecta tráfico LDAP real en eth1 (VLAN10)
2. **OpenLDAP** registra cada consulta en slapd.log → agente 006 lo envía a Wazuh
3. El intento de auth fallida intencionado puede disparar reglas de Wazuh

### Creación del script

```bash
pct exec 101 -- python3 -c "
script = '''#!/bin/bash
LDAP_HOST=\"192.168.10.2\"
LDAP_ADMIN=\"cn=admin,dc=cyntia,dc=local\"
LDAP_PASS='-'
LOG=\"/opt/cyntia-playbooks/ldap_monitor.log\"
MAX_LINES=500

log() { echo\"\$(date '+%Y-%m-%d %H:%M:%S')\$1\" >>\"\$LOG\"; }

# Rotación automática
if [ -f\"\$LOG\" ] && [\$(wc -l <\"\$LOG\") -gt\$MAX_LINES ]; then
    tail -100\"\$LOG\" >\"\$LOG.tmp\" && mv\"\$LOG.tmp\"\"\$LOG\"
fi

log\"=== Inicio verificacion MedTrans ===\"

# 1. Verificar usuarios activos
USERS=\$(ldapsearch -x -H ldap://\$LDAP_HOST -D\"\$LDAP_ADMIN\" -w\"\$LDAP_PASS\"\
  -b\"ou=MedTrans,dc=cyntia,dc=local\"\"(objectClass=inetOrgPerson)\" uid 2>/dev/null\
  | grep -c\"^uid:\")
log\"Usuarios activos:\$USERS\"

# 2. Verificar grupo disabled
DISABLED=\$(ldapsearch -x -H ldap://\$LDAP_HOST -D\"\$LDAP_ADMIN\" -w\"\$LDAP_PASS\"\
  -b\"cn=disabled,ou=grupos,dc=cyntia,dc=local\"\"(objectClass=*)\" member 2>/dev/null\
  | grep -c\"^member:\")
log\"Usuarios deshabilitados:\$DISABLED\"

# 3. Verificar cuenta de servicio wazuh-reader
ldapsearch -x -H ldap://\$LDAP_HOST\
  -D\"uid=wazuh-reader,ou=servicios,dc=cyntia,dc=local\"\
  -w '-'\
  -b\"dc=cyntia,dc=local\"\"(objectClass=*)\" dn > /dev/null 2>&1
if [\$? -eq 0 ]; then log\"wazuh-reader auth: OK\"
else log\"ALERTA: wazuh-reader auth FALLIDA\"; fi

# 4. Auth fallida intencionada (genera eventos en Wazuh/Suricata)
ldapsearch -x -H ldap://\$LDAP_HOST\
  -D\"uid=monitor-check,ou=servicios,dc=cyntia,dc=local\"\
  -w\"wrongpassword\"\
  -b\"dc=cyntia,dc=local\"\"(objectClass=*)\" dn > /dev/null 2>&1
log\"Auth check completado\"
log\"=== Fin verificacion ===\"
'''
with open('/opt/cyntia-playbooks/ldap_monitor.sh', 'w') as f:
    f.write(script)
print('OK')
"

pct exec 101 -- bash -c "
chmod +x /opt/cyntia-playbooks/ldap_monitor.sh

# Añadir al cron de lxc-soc-core cada 10 minutos
(crontab -l 2>/dev/null | grep -v ldap_monitor;\
  echo '*/10 * * * * /opt/cyntia-playbooks/ldap_monitor.sh') | crontab -
crontab -l | grep ldap_monitor

# Test inmediato
bash /opt/cyntia-playbooks/ldap_monitor.sh
cat /opt/cyntia-playbooks/ldap_monitor.log
"
```

**Salida esperada:**

```
2026-04-23 10:41:13 === Inicio verificacion MedTrans ===
2026-04-23 10:41:13 Usuarios activos: 8
2026-04-23 10:41:13 Usuarios deshabilitados: 0
2026-04-23 10:41:13 wazuh-reader auth: OK
2026-04-23 10:41:13 Auth check completado
2026-04-23 10:41:13 === Fin verificacion ===
```

**Atención:** El crontab debe estar en lxc-soc-core (pct exec 101), NO en el host Proxmox. Si se añade en el host dará error “not found” porque el script no existe en el host.

---

## 5. Playbooks actualizados para LDAP

### Active responses ampliados

Se añadieron reglas de Wazuh relacionadas con LDAP a los active responses existentes. Los cambios se aplican en ambos ficheros de configuración:

```bash
pct exec 101 -- python3 -c "
files = [
    '/opt/wazuh-docker/single-node/config/wazuh_cluster/ossec.conf',
    '/opt/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf'
]
for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()
    # block-ip: añadir brute force SSH y auth fallida LDAP
    content = content.replace(
        '<rules_id>100201,100203,100204</rules_id>',
        '<rules_id>100201,100203,100204,5710,5712,5763,2502</rules_id>'
    )
    # create-ticket y threat-intel: añadir eventos de usuarios y ldap
    content = content.replace(
        '<rules_id>100200,100201,100202,100203,100204,100205,100206</rules_id>',
        '<rules_id>100200,100201,100202,100203,100204,100205,100206,5710,5712,5763,5901,5902,2502,220</rules_id>'
    )
    with open(filepath, 'w') as f:
        f.write(content)
    print(f'OK: {filepath}')
"

# Reiniciar Wazuh para aplicar cambios
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control restart 2>/dev/null | tail -3
```

### Tabla de reglas por playbook

| Playbook | Reglas que lo activan |
| --- | --- |
| `block-ip` | 100201, 100203, 100204, **5710, 5712, 5763, 2502** |
| `disable-ldap-user` | 100201, 100202, 100203 (solo OpenCanary — acción agresiva) |
| `isolate-host` | 100201, 100202, 100203 (solo OpenCanary — acción agresiva) |
| `create-ticket` | Todo: OpenCanary + **SSH brute force + usuarios nuevos + auth fallida** |
| `threat-intel` | Todo: igual que create-ticket |

### Reglas Wazuh relevantes para LDAP

| Regla | Descripción | Nivel |
| --- | --- | --- |
| 5710 | Multiple SSH login failures | 10 |
| 5712 | SSH brute force (more than 6 failures) | 10 |
| 5763 | Possible SSH scan | 8 |
| 2502 | Multiple authentication failures | 10 |
| 5901 | New group added to the system | 8 |
| 5902 | New user added to the system | 8 |
| 220 | Syscheck integrity check | 7 |

---

## Verificación completa

### Estado final de todos los componentes

```bash
# Targets Prometheus (deben ser 4: prometheus, soc-core, ldap, ldap-exporter)
pct exec 101 -- curl -s http://172.20.0.2:9090/api/v1/targets | python3 -c "
import sys, json
d = json.load(sys.stdin)
for t in d['data']['activeTargets']:
    print(f'{t[\"labels\"][\"job\"]:30} | {t[\"health\"]}')
"

# Suricata escuchando en eth0 y eth1
pct exec 101 -- grep 'All AFP capture threads' /var/log/suricata/suricata.log | tail -1

# OpenCanary visible desde VLAN10
pct exec 201 -- nc -zv -w3 192.168.10.4 2222 2>&1

# Agentes Wazuh activos
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/agent_control -l

# Script cron activo
pct exec 101 -- crontab -l | grep ldap_monitor
```