# Guías Proxmox - Fase 11 - Bloque 1

Auditoría completa del sistema

---

## Bloque 1 — Host Proxmox

### Verificación inicial

```bash
hostname && pveversion && pvecm status 2>/dev/null
pct list
tailscale status
nft list ruleset | head -100
systemctl is-active wazuh-relay.service wazuh-relay-enroll.service \
  wazuh-relay-vlan10.service wazuh-relay-vlan10-enroll.service nftables-relay.service
systemctl is-active cyntia-start.service postfix fail2ban
```

### Resultados

| Componente | Estado | Observación |
| --- | --- | --- |
| Cluster PVE | ✅ | 2 nodos, quorate, ambos con votos |
| Tailscale | ✅ | cyntia=100.92.243.96, backup=100.101.167.16 |
| nftables | ✅ | blocked_ips con timeout 1d, DNAT correcto |
| Socat relays | ✅ | 5 servicios activos |
| Postfix | ✅ | Activo |
| fail2ban | ✅ | Activo |
| cyntia-start.service | ⚠️ | `inactive` — es oneshot, comportamiento esperado |

### Hallazgo: IP Tailscale del nodo backup

La IP del nodo backup había cambiado. La nueva IP correcta es `100.101.167.16` (antes `100.106.127.17`).

```bash
ssh -J root@100.92.243.96 root@100.101.167.16 "hostname && tailscale ip"
```

---

## Bloque 2 — Contenedores LXC

### Verificación

```bash
# Recursos y configuración de red
for id in 100 101 102 103 104 201; do
  echo "=== VMID$id ==="
  pct config $id | grep -E "hostname|memory|cores|net|onboot"
done

# DNS de cada LXC
for id in 100 101 102 103 104 201; do
  echo "=== VMID$id DNS ==="
  pct exec $id -- cat /etc/resolv.conf
done
```

### Hallazgos y correcciones

**lxc-ldap (201) sin `onboot: 1`** — no arrancaba tras reinicios del host.

```bash
# Corrección
pct set 201 --onboot 1
```

**Docker con `restart: always`** — todos los contenedores Docker sobreviven reinicios sin necesitar cyntia-start.sh.

```bash
# Verificar restart policy
pct exec 101 -- docker inspect --format \
  '{{.Name}} → restart:{{.HostConfig.RestartPolicy.Name}}' \
  $(pct exec 101 -- docker ps -aq)
```

Resultado esperado: `restart:always` en todos.

---

## Bloque 3 — PiHole DNS

### Verificación

```bash
pct exec 100 -- bash -c "
pihole status
cat /etc/pihole/custom.list 2>/dev/null
cat /etc/hosts | grep cyntia
grep -E 'DNS|DOMAIN' /etc/pihole/setupVars.conf
"
```

### Hallazgos

- El comando `pihole` fallaba dentro de `pct exec` por PATH limitado — no es un problema real.
- El fichero `custom.list` estaba **duplicado** (entradas repetidas).
- **Faltaban entradas** para `ldap`, `honeypot`, `backup` y `wazuh`.
- `lxc-ldap` usaba `1.1.1.1` como DNS en lugar de PiHole.
- No había regla nftables para permitir DNS de VLAN10 → VLAN20.

### Correcciones aplicadas

```bash
# 1. Crear custom.list limpio y completo
pct exec 100 -- bash -c "cat > /etc/pihole/custom.list << 'EOF'
192.168.20.2 pihole.cyntia.local
192.168.20.3 soc.cyntia.local
192.168.20.3 wazuh.cyntia.local
192.168.20.3 grafana.cyntia.local
192.168.20.4 honeypot.cyntia.local
192.168.20.5 backup.cyntia.local
192.168.10.2 ldap.cyntia.local
192.168.50.2 app.cyntia.local
EOF
"

# 2. Reiniciar PiHole-FTL
pct exec 100 -- systemctl restart pihole-FTL.service

# 3. Añadir regla DNS VLAN10 → VLAN20 en nftables (en memoria)
nft add rule inet filter forward iifname "vmbr0.10" oifname "vmbr0.20" udp dport 53 accept
nft add rule inet filter forward iifname "vmbr0.10" oifname "vmbr0.20" tcp dport 53 accept

# 4. Hacer permanente en /etc/nftables.conf
python3 -c "
with open('/etc/nftables.conf', 'r') as f:
    lines = f.readlines()
out = []
for line in lines:
    if line == 'iifname\"vmbr0.10\" oifname\"vmbr0.20\" udp dport 53 accept\n':
        out.append('        # VLAN10 → VLAN20: DNS\n')
        out.append('        iifname\"vmbr0.10\" oifname\"vmbr0.20\" udp dport 53 accept\n')
    elif line == 'iifname\"vmbr0.10\" oifname\"vmbr0.20\" tcp dport 53 accept\n':
        out.append('        iifname\"vmbr0.10\" oifname\"vmbr0.20\" tcp dport 53 accept\n')
    else:
        out.append(line)
with open('/etc/nftables.conf', 'w') as f:
    f.writelines(out)
print('OK')
"

# 5. Corregir DNS de lxc-ldap
pct exec 201 -- bash -c "cat > /etc/resolv.conf << 'EOF'
nameserver 192.168.20.2
options ndots:1
EOF
"

# 6. Verificar resolución desde todos los LXC
for id in 101 102 103 104 201; do
  echo "=== VMID$id ==="
  pct exec $id -- nslookup ldap.cyntia.local 2>/dev/null | grep -E "^Name|^Address" | grep -v "#53"
done
```

### Verificación final

```bash
nft -c -f /etc/nftables.conf && echo "SINTAXIS OK"
```

---

## Bloque 4 — Wazuh Stack

### Verificación

```bash
pct exec 101 -- bash -c "
# Estado contenedores Docker
docker ps --format 'table {{.Name}}\t{{.Status}}'

# Agentes activos
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# Localizar reglas OpenCanary
docker exec single-node-wazuh.manager-1 find /var/ossec -name '*opencanary*' 2>/dev/null

# Active responses configurados
docker exec single-node-wazuh.manager-1 grep -A5 'active-response' /var/ossec/etc/ossec.conf
"
```

### Hallazgos

1. **Reglas OpenCanary no existían** en el contenedor — el directorio `/var/ossec/etc/rules/` no existía.
2. **Doble bloque `<ossec_config>`** — la config tenía `<global>` duplicado con `email_notification`, `logall` y `logall_json`.
3. **`wazuh_manager.conf`** es el source of truth — coincide exactamente con lo que corre gracias al volumen montado.
4. **Logtypes de OpenCanary incorrectos** — se usaban 2000/3000/4000 pero la versión instalada usa 4000/4001/4002 para SSH.

### Corrección: crear reglas OpenCanary

```bash
pct exec 101 -- python3 -c "
rules = '''<group name=\"opencanary,honeypot,\">

  <rule id=\"100200\" level=\"12\">
    <decoded_as>json</decoded_as>
    <field name=\"node_id\">opencanary</field>
    <description>OpenCanary honeypot: actividad detectada</description>
    <options>no_full_log</options>
  </rule>

  <rule id=\"100201\" level=\"14\">
    <if_sid>100200</if_sid>
    <field name=\"logtype\">^4000$</field>
    <description>OpenCanary: conexion SSH detectada en honeypot</description>
  </rule>

  <rule id=\"100202\" level=\"15\">
    <if_sid>100200</if_sid>
    <field name=\"logtype\">^4001$</field>
    <description>OpenCanary: intento de login SSH con credenciales en honeypot</description>
  </rule>

  <rule id=\"100203\" level=\"15\">
    <if_sid>100200</if_sid>
    <field name=\"logtype\">^4002$</field>
    <description>OpenCanary: login SSH completado en honeypot - intrusion critica</description>
  </rule>

  <rule id=\"100204\" level=\"14\">
    <if_sid>100200</if_sid>
    <field name=\"logtype\">^3000$</field>
    <description>OpenCanary: peticion HTTP al honeypot</description>
  </rule>

  <rule id=\"100205\" level=\"15\">
    <if_sid>100200</if_sid>
    <field name=\"logtype\">^8001$</field>
    <description>OpenCanary: intento de conexion MySQL al honeypot</description>
  </rule>

  <rule id=\"100206\" level=\"12\">
    <if_sid>100200</if_sid>
    <description>OpenCanary: actividad generica en honeypot</description>
  </rule>

</group>'''
with open('/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/opencanary_rules.xml', 'w') as f:
    f.write(rules)
print('OK')
"

# Recargar Wazuh
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control restart 2>/dev/null | tail -3
```

### Corrección: receptor syslog duplicado

El manager tenía configurado un receptor syslog para `192.168.20.4` (honeypot) además del agente. Esto causaba que las alertas aparecieran con `agente=000` en lugar de `agente=003`.

```bash
pct exec 101 -- python3 -c "
import re
files = [
    '/opt/wazuh-docker/single-node/config/wazuh_cluster/ossec.conf',
    '/opt/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf'
]
for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()
    content = re.sub(
        r'\s*<remote>\s*<connection>syslog</connection>\s*<port>514</port>\s*<protocol>udp</protocol>\s*<allowed-ips>192\.168\.20\.4</allowed-ips>\s*</remote>',
        '', content, flags=re.DOTALL
    )
    with open(filepath, 'w') as f:
        f.write(content)
    print(f'OK: {filepath}')
"
pct exec 101 -- docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control restart 2>/dev/null | tail -3
```

### Corrección: 3 scripts faltaban en active-response

```bash
pct exec 101 -- bash -c "
docker cp /opt/cyntia-playbooks/disable_ldap_user.py\
  single-node-wazuh.manager-1:/var/ossec/active-response/bin/
docker cp /opt/cyntia-playbooks/create_ticket.py\
  single-node-wazuh.manager-1:/var/ossec/active-response/bin/
docker cp /opt/cyntia-playbooks/isolate_host.py\
  single-node-wazuh.manager-1:/var/ossec/active-response/bin/

docker exec single-node-wazuh.manager-1 chmod 750\
  /var/ossec/active-response/bin/disable_ldap_user.py\
  /var/ossec/active-response/bin/create_ticket.py\
  /var/ossec/active-response/bin/isolate_host.py

docker exec single-node-wazuh.manager-1 chown root:wazuh\
  /var/ossec/active-response/bin/disable_ldap_user.py\
  /var/ossec/active-response/bin/create_ticket.py\
  /var/ossec/active-response/bin/isolate_host.py
"
```

### Active responses configurados (reglas ampliadas)

Se añadieron reglas LDAP a los active responses existentes:

```xml
<!-- block-ip ahora también activa con brute force SSH y auth fallida -->
<rules_id>100201,100203,100204,5710,5712,5763,2502</rules_id>

<!-- create-ticket y threat-intel incluyen eventos de usuarios y ldap -->
<rules_id>100200,100201,100202,100203,100204,100205,100206,5710,5712,5763,5901,5902,2502,220</rules_id>
```

---

## Bloque 5 — Suricata

### Verificación

```bash
pct exec 101 -- bash -c "
systemctl is-active suricata
systemctl show suricata --property=CPUQuota
grep -E 'af-packet|interface' /etc/suricata/suricata.yaml | grep -v '#' | head -10
wc -l /var/lib/suricata/rules/suricata.rules
grep '\"event_type\":\"alert\"' /var/log/suricata/eve.json | tail -5
"
```

### Resultados

| Métrica | Valor |
| --- | --- |
| Estado | ✅ activo |
| CPU quota | 25% |
| Interfaz | eth0 (VLAN20) |
| Reglas cargadas | 65.071 ET Open |
| Paquetes capturados | ~11.3M |
| Alertas generadas | ~88.470 |
| Drop rate | 0.16% (18.553 drops) |

**Limitación documentada:** Suricata en eth0 de lxc-soc-core solo ve tráfico VLAN20. No inspecciona tráfico de VLAN10 ni DMZ directamente (eso lo cubre la segunda interfaz añadida en el bloque 2).

---

## Bloque 6 — OpenCanary

### Verificación

```bash
pct exec 103 -- bash -c "
systemctl status opencanary --no-pager
ss -tulnp | grep -E '2222|8080|21|3306|445'
tail -5 /var/log/opencanary.log
"
```

### Resultados

| Servicio | Puerto | Estado |
| --- | --- | --- |
| SSH (trampa) | 2222 | ✅ escuchando |
| HTTP | 8080 | ✅ escuchando |
| FTP | 21 | ✅ escuchando |
| MySQL | 3306 | ✅ escuchando |
| SMB | 445 | — (bind a 0.0.0.0 sin verificar) |

**Logtypes reales** descubiertos durante la auditoría:

```bash
pct exec 103 -- grep 'src_host' /var/log/opencanary.log | python3 -c "
import sys, json, collections
logtypes = collections.Counter()
for line in sys.stdin:
    try:
        d = json.loads(line)
        logtypes[f'logtype={d[\"logtype\"]} dst_port={d.get(\"dst_port\",\"?\")}'] += 1
    except: pass
for k,v in sorted(logtypes.items()):
    print(f'{v}x {k}')
"
```

Resultado real:

| logtype | Puerto | Servicio real |
| --- | --- | --- |
| 1001 | -1 | Mensajes internos |
| 3000 | 8080 | HTTP |
| 4000 | 2222 | SSH (conexión) |
| 4001 | 2222 | SSH (credenciales enviadas) |
| 4002 | 2222 | SSH (login completado) |
| 8001 | 3306 | MySQL |

### Corrección: servicio wazuh-agent en lxc-honeypot

El servicio systemd solo arrancaba `wazuh-agentd`, dejando `wazuh-logcollector`, `wazuh-syscheckd` y otros sin iniciar.

```bash
pct exec 103 -- bash -c "cat > /etc/systemd/system/wazuh-agent.service << 'EOF'
[Unit]
Description=Wazuh agent
After=network.target

[Service]
Type=forking
ExecStart=/var/ossec/bin/wazuh-control start
ExecStop=/var/ossec/bin/wazuh-control stop
ExecReload=/var/ossec/bin/wazuh-control restart
PIDFile=/var/ossec/var/run/wazuh-agentd.pid
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
"

# Verificar tras reboot del LXC
pct reboot 103
sleep 20
pct exec 103 -- /var/ossec/bin/wazuh-control status
```

---

## Bloque 7 — Grafana + Prometheus

### Verificación

```bash
pct exec 101 -- bash -c "
# Targets de Prometheus
curl -s http://172.20.0.2:9090/api/v1/targets | python3 -c\"
import sys, json
d = json.load(sys.stdin)
for t in d['data']['activeTargets']:
    print(f'{t[\\\"labels\\\"][\\\"job\\\"]} | {t[\\\"scrapeUrl\\\"]} | {t[\\\"health\\\"]}')
\"

# Dashboards en Grafana
curl -s -u cyntia:- http://172.20.0.4:3000/api/search | python3 -c\"
import sys, json
for d in json.load(sys.stdin):
    print(f'{d.get(\\\"title\\\")} | uid={d.get(\\\"uid\\\")}')
\"

# Datasources
curl -s -u cyntia:- http://172.20.0.4:3000/api/datasources | python3 -c\"
import sys, json
for d in json.load(sys.stdin):
    print(f'{d[\\\"name\\\"]} | {d[\\\"type\\\"]} | {d[\\\"url\\\"]}')
\"
"
```

### Resultados

| Componente | Estado |
| --- | --- |
| Prometheus | ✅ activo |
| Node Exporter (soc-core) | ✅ target up |
| Grafana | ✅ activo |
| Dashboard “Node Exporter Full” | ✅ importado |

**Limitación documentada:** Solo monitorizaba lxc-soc-core. Se amplió en el bloque 2 para incluir lxc-ldap.

---

## Bloque 8 — OpenLDAP

### Verificación

```bash
pct exec 201 -- bash -c "
systemctl is-active slapd

# Estructura completa
ldapsearch -x -H ldap://localhost\
  -D 'cn=admin,dc=cyntia,dc=local' -w '-'\
  -b 'dc=cyntia,dc=local' '(objectClass=*)' dn 2>/dev/null | grep '^dn:'

# Estado usuarios
ldapsearch -x -H ldap://localhost\
  -D 'cn=admin,dc=cyntia,dc=local' -w '-'\
  -b 'ou=MedTrans,dc=cyntia,dc=local'\
  '(objectClass=inetOrgPerson)' uid loginShell 2>/dev/null\
  | grep -E '^uid:|^loginShell:'

# Agente Wazuh
systemctl is-active wazuh-agent

# Auditoría rsyslog
tail -5 /var/log/slapd.log

# LAM
curl -s -o /dev/null -w '%{http_code}' http://localhost/lam/
"
```

### Resultados

| Componente | Estado |
| --- | --- |
| slapd | ✅ activo |
| 8 usuarios MedTrans | ✅ todos con /bin/bash |
| 4 departamentos | ✅ direccion, IT, RRHH, operaciones |
| Agente Wazuh 006 | ✅ activo, lee syslog + auth.log + slapd.log |
| rsyslog | ✅ activo, slapd.log generándose |
| LAM | ✅ responde HTTP 200 |

### Hallazgo: admin en grupo disabled

Durante las pruebas, `cn=admin` quedó en el grupo `disabled`. La clase `groupOfNames` requiere al menos un miembro, por lo que no se puede eliminar el admin sin añadir otro miembro primero.

```bash
# Verificar grupo disabled
pct exec 201 -- ldapsearch -x -H ldap://localhost \
  -D 'cn=admin,dc=cyntia,dc=local' -w '-' \
  -b 'cn=disabled,ou=grupos,dc=cyntia,dc=local' \
  '(objectClass=*)' member 2>/dev/null | grep member
```

---

## Bloque 9 — Backups

### Verificación

```bash
# Localizar backups vzdump
find /mnt/backup-nfs/ -name "*.zst" | head -10
ls -lht /mnt/backup-nfs/

# BorgBackup
BORG_PASSPHRASE='-' borg list /mnt/backup-nfs/borg | tail -5

# NFS
mount | grep backup-nfs
df -h /mnt/backup-nfs

# Cron
crontab -l | grep backup
```

### Resultados

| Componente | Estado |
| --- | --- |
| vzdump diario | ✅ todos los LXC en `/mnt/backup-nfs/dump/` |
| BorgBackup | ✅ nightly 2AM, retención 7d/4w |
| Backups custom | ✅ wazuh + ldap.ldif + pihole cada día |
| NFS montado | ✅ 46GB libres de 94GB |
| Email Postfix | ✅ confirmado (llegan emails nocturnos) |

**Nota sobre Postfix:** `/var/log/syslog` no existe en este host (usa journald). Los logs se verifican con `journalctl -u postfix`.

---

## Bloque 10 — Playbooks

### Verificación

```bash
pct exec 101 -- bash -c "
# Scripts en contenedor
docker exec single-node-wazuh.manager-1 ls -lh /var/ossec/active-response/bin/\
  | grep -E 'block|disable|isolate|ticket|threat'

# Relay nftables
systemctl is-active nftables-relay.service

# Test relay (bloquear IP de prueba)
echo 'nft add element inet filter blocked_ips { 10.255.255.254 }' | nc -w3 192.168.20.1 7777
sleep 2
nft list set inet filter blocked_ips

# Limpiar
echo 'nft delete element inet filter blocked_ips { 10.255.255.254 }' | nc -w3 192.168.20.1 7777
"
```

### Resultados

| Script | En contenedor | Permisos |
| --- | --- | --- |
| block_ip.py | ✅ | 750 root:wazuh |
| create_ticket.py | ✅ | 750 root:wazuh |
| disable_ldap_user.py | ✅ | 750 root:wazuh |
| isolate_host.py | ✅ | 750 root:wazuh |
| threat_intel.py | ✅ | 750 root:wazuh |

### Test Threat Intelligence

```bash
pct exec 101 -- bash -c "
echo '{\"data\": {\"srcip\":\"185.220.101.1\"}}' |\
  timeout 20 python3 /opt/cyntia-playbooks/threat_intel.py
cat /opt/cyntia-playbooks/threat_reports/185.220.101.1-*.json | tail -1
"
```

**Resultado:** AbuseIPDB score=100%, veredicto MALICIOSA, IP bloqueada automáticamente.

**Nota:** OTX tiene timeout frecuente (~10s). No afecta al veredicto si AbuseIPDB ya detecta la IP.

---

## Correcciones aplicadas

Resumen de todas las correcciones realizadas durante la auditoría:

| # | Problema | Corrección |
| --- | --- | --- |
| 1 | lxc-ldap sin `onboot: 1` | `pct set 201 --onboot 1` |
| 2 | lxc-ldap DNS apuntaba a 1.1.1.1 | nameserver 192.168.20.2 en resolv.conf |
| 3 | PiHole custom.list duplicado y con entradas faltantes | Recreado con 8 entradas correctas |
| 4 | Sin regla nftables DNS VLAN10→VLAN20 | Reglas añadidas y persistentes en nftables.conf |
| 5 | Reglas OpenCanary no existían en Wazuh | Creadas con logtypes correctos (4000/4001/4002) |
| 6 | Logtypes OpenCanary incorrectos en reglas | Corregidos según análisis real del log |
| 7 | 3 scripts faltaban en active-response del contenedor | Copiados con permisos correctos |
| 8 | Receptor syslog duplicado en Wazuh | Eliminado de ossec.conf y wazuh_manager.conf |
| 9 | Servicio wazuh-agent solo arrancaba agentd | Corregido para usar wazuh-control start |
| 10 | admin en grupo disabled | Identificado (no eliminar por restricción groupOfNames) |
| 11 | Hook post-start problemático en lxc-soc-core | Eliminado de /etc/pve/lxc/101.conf |
| 12 | Backup alerts.json.bak de 1.7GB | Eliminado |