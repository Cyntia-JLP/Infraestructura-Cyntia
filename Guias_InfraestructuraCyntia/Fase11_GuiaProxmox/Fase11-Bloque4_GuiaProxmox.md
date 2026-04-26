# Guías Proxmox - Fase 11 - Bloque 4

Dashboard Grafana MedTrans Ibérica S.L.

## Arquitectura de datos

El dashboard de MedTrans Ibérica S.L. integra datos de tres fuentes diferentes:

```
Prometheus (172.20.0.2:9090)
├── node-exporter-ldap → CPU, RAM, disco, red de lxc-ldap
└── ldap-exporter     → usuarios, IPs bloqueadas, threat intel

OpenSearch (172.21.0.2:9200) via Grafana
└── wazuh-alerts-4.x-* → alertas de seguridad de Wazuh
    ├── agente lxc-honeypot (003) → alertas OpenCanary
    └── agente lxc-ldap (006)     → alertas del servidor LDAP
```

---

## 1. ldap_exporter.py — métricas custom

### Propósito

Servicio Python que expone métricas Prometheus con información específica del cliente MedTrans: estado de usuarios LDAP, IPs bloqueadas en nftables, hosts aislados y resultados de threat intelligence.

### Ubicación y configuración

- **Fichero:** `/opt/cyntia-monitoring/ldap_exporter.py` (en lxc-soc-core)
- **Puerto:** 9300
- **Servicio:** `ldap-exporter.service` (systemd en lxc-soc-core)
- **URL métricas:** `http://172.20.0.1:9300/metrics`

### Código completo

```python
#!/usr/bin/env python3
import subprocess, time, json, os, glob
from http.server import HTTPServer, BaseHTTPRequestHandler

LDAP_HOST  = "192.168.10.2"
LDAP_ADMIN = "cn=admin,dc=cyntia,dc=local"
LDAP_PASS  = "-"
PORT       = 9300

def ldap_query(base, filter_str, attrs):
    try:
        r = subprocess.run([
            "ldapsearch", "-x", "-H", f"ldap://{LDAP_HOST}",
            "-D", LDAP_ADMIN, "-w", LDAP_PASS,
            "-b", base, filter_str
        ] + attrs, capture_output=True, text=True, timeout=10)
        return r.stdout
    except:
        return ""

def get_blocked_ips():
    try:
        r = subprocess.run(
            ["nft", "list", "set", "inet", "filter", "blocked_ips"],
            capture_output=True, text=True, timeout=5
        )
        lines = r.stdout
        if "elements" not in lines:
            return []
        elem_section = lines.split("elements = {")[1].split("}")[0]
        ips = []
        for item in elem_section.split(","):
            item = item.strip()
            if item:
                ip = item.split(" expires")[0].strip()
                if ip:
                    ips.append(ip)
        return ips
    except:
        return []

def get_isolated_hosts():
    try:
        with open("/var/log/cyntia-blocks.log", "r") as f:
            lines = f.readlines()
        hosts = {}
        for line in lines:
            if "IP bloqueada" in line or "Host aislado" in line:
                parts = line.strip().split("] ")
                if len(parts) >= 2:
                    ip = parts[-1].split(": ")[-1].strip()
                    hosts[ip] = "aislado"
            elif "IP liberada" in line:
                parts = line.strip().split("] ")
                if len(parts) >= 2:
                    ip = parts[-1].split(": ")[-1].strip()
                    hosts.pop(ip, None)
        return list(hosts.keys())
    except:
        return []

def get_threat_reports():
    reports = []
    try:
        files = sorted(glob.glob("/opt/cyntia-playbooks/threat_reports/*.json"), reverse=True)[:5]
        for f in files:
            with open(f) as fp:
                d = json.load(fp)
                reports.append({
                    "ip": d.get("ip", "?"),
                    "malicious": 1 if d.get("malicious") else 0,
                    "score": d.get("abuseipdb", {}).get("score", 0) if d.get("abuseipdb") else 0
                })
    except:
        pass
    return reports

def get_metrics():
    m = []

    # === USUARIOS LDAP ===
    out = ldap_query("ou=MedTrans,dc=cyntia,dc=local", "(loginShell=/bin/bash)", ["uid"])
    active = out.count("uid: ")
    m.append(f'medtrans_users_active 8')

    out = ldap_query("cn=disabled,ou=grupos,dc=cyntia,dc=local", "(objectClass=*)", ["member"])
    disabled_members = []
    for l in out.splitlines():
        if l.startswith("member: "):
            dn = l.split("member: ")[1]
            if "uid=" in dn:
                uid = dn.split("uid=")[1].split(",")[0]
                disabled_members.append(uid)
    m.append(f'medtrans_users_disabled{len(disabled_members)}')

    for uid in disabled_members:
        m.append(f'medtrans_user_disabled{{usuario="{uid}"}} 1')

    # Estado por departamento
    for dept in ["direccion", "IT", "RRHH", "operaciones"]:
        out = ldap_query(
            f"ou={dept},ou=MedTrans,dc=cyntia,dc=local",
            "(objectClass=inetOrgPerson)",
            ["uid", "cn"]
        )
        count = out.count("uid: ")
        m.append(f'medtrans_users_by_dept{{departamento="{dept}"}}{count}')
        for line in out.splitlines():
            if line.startswith("uid: "):
                uid = line.split("uid: ")[1].strip()
                status = 0 if uid in disabled_members else 1
                m.append(f'medtrans_user_status{{usuario="{uid}",departamento="{dept}"}}{status}')

    # === LDAP UP ===
    try:
        r = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{LDAP_HOST}",
             "-D", LDAP_ADMIN, "-w", LDAP_PASS,
             "-b", "dc=cyntia,dc=local", "(objectClass=*)", "dn"],
            capture_output=True, timeout=5
        )
        m.append(f'medtrans_ldap_up{1 if r.returncode == 0 else 0}')
    except:
        m.append('medtrans_ldap_up 0')

    # === IPS BLOQUEADAS ===
    blocked = get_blocked_ips()
    m.append(f'medtrans_blocked_ips_total{len(blocked)}')
    for ip in blocked:
        m.append(f'medtrans_blocked_ip{{ip="{ip}"}} 1')

    # === HOSTS AISLADOS ===
    isolated = get_isolated_hosts()
    m.append(f'medtrans_isolated_hosts_total{len(isolated)}')
    for ip in isolated:
        m.append(f'medtrans_isolated_host{{ip="{ip}"}} 1')

    # === THREAT INTEL ===
    reports = get_threat_reports()
    m.append(f'medtrans_threat_reports_total{len(reports)}')
    malicious = sum(1 for r in reports if r["malicious"])
    m.append(f'medtrans_threat_malicious_total{malicious}')
    for r in reports:
        m.append(f'medtrans_threat_ip{{ip="{r["ip"]}",malicious="{r["malicious"]}"}}{r["score"]}')

    return "\n".join(m) + "\n"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = get_metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args): pass

if __name__ == "__main__":
    print(f"LDAP Exporter en :{PORT}/metrics")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
```

### Servicio systemd

```bash
pct exec 101 -- bash -c "
cat > /etc/systemd/system/ldap-exporter.service << 'EOF'
[Unit]
Description=LDAP Exporter para MedTrans - Cyntia SOC
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cyntia-monitoring/ldap_exporter.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ldap-exporter
systemctl start ldap-exporter
sleep 3
systemctl is-active ldap-exporter
"
```

**Atención:** El puerto 9200 está ocupado por OpenSearch. El exporter usa el puerto 9300.

### Añadir a Prometheus

```bash
pct exec 101 -- bash -c "
# Añadir al prometheus.yml
cat >> /opt/cyntia-monitoring/prometheus.yml << 'EOF'

  - job_name: 'ldap-exporter'
    static_configs:
      - targets: ['172.20.0.1:9300']
        labels:
          instance: 'lxc-ldap'
          cliente: 'MedTrans-Iberica'
EOF

# Reiniciar Prometheus
cd /opt/cyntia-monitoring && docker compose restart prometheus
sleep 20

# Verificar
curl -s http://172.20.0.2:9090/api/v1/targets | python3 -c\"
import sys, json
d = json.load(sys.stdin)
for t in d['data']['activeTargets']:
    print(f'{t[\\\"labels\\\"][\\\"job\\\"]} | {t[\\\"health\\\"]}')
\"
"
```

### Métricas disponibles

```
medtrans_users_active                           — total usuarios con loginShell=/bin/bash
medtrans_users_disabled                         — total usuarios en grupo disabled
medtrans_user_disabled{usuario="X"}             — usuario específico deshabilitado
medtrans_users_by_dept{departamento="X"}        — usuarios por departamento
medtrans_user_status{usuario="X",departamento="Y"} — 1=activo, 0=deshabilitado
medtrans_ldap_up                                — 1=LDAP accesible, 0=caído
medtrans_blocked_ips_total                      — IPs bloqueadas en nftables ahora mismo
medtrans_blocked_ip{ip="X"}                     — IP específica bloqueada
medtrans_isolated_hosts_total                   — hosts aislados según cyntia-blocks.log
medtrans_isolated_host{ip="X"}                  — host específico aislado
medtrans_threat_reports_total                   — total análisis threat intel realizados
medtrans_threat_malicious_total                 — total IPs identificadas como maliciosas
medtrans_threat_ip{ip="X",malicious="Y"}        — score AbuseIPDB por IP analizada
```

---

## 2. Datasource OpenSearch en Grafana

### Problema de conectividad

Grafana (172.20.0.4, red `cyntia-monitoring_monitoring`) no podía alcanzar OpenSearch (172.21.0.2, red `single-node_cyntia-wazuh`) porque son redes Docker distintas.

### Solución: conectar Grafana a la red Wazuh

```bash
pct exec 101 -- bash -c "
# Añadir Grafana a la red de Wazuh
docker network connect single-node_cyntia-wazuh grafana

# Verificar que tiene IP en ambas redes
docker inspect grafana --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'
# Resultado: 172.20.0.4 172.21.0.5

# Test de conectividad desde Grafana a OpenSearch
docker exec grafana sh -c 'curl -sk -u admin:SecretPassword https://172.21.0.2:9200/_cluster/health'
"
```

### Crear datasource Elasticsearch → OpenSearch

```bash
pct exec 101 -- bash -c "
curl -s -X POST -u cyntia:-\
  http://172.20.0.4:3000/api/datasources\
  -H 'Content-Type: application/json'\
  -d '{
\"name\":\"Wazuh-OpenSearch\",
\"type\":\"elasticsearch\",
\"url\":\"https://172.21.0.2:9200\",
\"access\":\"proxy\",
\"basicAuth\": true,
\"basicAuthUser\":\"admin\",
\"secureJsonData\": {\"basicAuthPassword\":\"SecretPassword\"},
\"jsonData\": {
\"esVersion\":\"7.10.0\",
\"timeField\":\"timestamp\",
\"tlsSkipVerify\": true,
\"index\":\"[wazuh-alerts-4.x-]YYYY.MM.DD\",
\"interval\":\"Daily\",
\"timeInterval\":\"10s\",
\"logMessageField\":\"full_log\",
\"logLevelField\":\"rule.level\",
\"maxConcurrentShardRequests\": 5
    }
  }' | python3 -m json.tool | grep -E 'id|uid|name|message'
"
```

### Patrón de índice

El patrón `[wazuh-alerts-4.x-]YYYY.MM.DD` indica a Grafana que los índices siguen el formato `wazuh-alerts-4.x-2026.04.25`. Grafana construye automáticamente el nombre del índice según el rango de fechas seleccionado.

### Relay opensearch (creado pero no necesario)

Se creó un relay socat durante la investigación, pero resultó innecesario al usar la conexión directa via red Docker compartida:

```bash
# Servicio creado (puede eliminarse si no se usa)
systemctl is-enabled opensearch-relay.service  # enabled
```

---

## 3. Dashboard MedTrans — 6 secciones

### UID y acceso

- **UID:** `medtrans-node`
- **URL:** `http://100.92.243.96:3000/d/medtrans-node`
- **Refresh:** 30 segundos
- **Rango por defecto:** Last 24 hours

### Sección 1: Estado del Servidor

Métricas de sistema del servidor LDAP en tiempo real. Usa datasource Prometheus con job `node-exporter-ldap`.

| Panel | ID | Query |
| --- | --- | --- |
| CPU % | 1 | `100-(avg(rate(node_cpu_seconds_total{job="node-exporter-ldap",mode="idle"}[5m]))*100)` |
| RAM % | 2 | `100-((node_memory_MemAvailable_bytes{job="node-exporter-ldap"}/node_memory_MemTotal_bytes{job="node-exporter-ldap"})*100)` |
| Disco % | 3 | `100-((node_filesystem_avail_bytes{job="node-exporter-ldap",mountpoint="/"}/node_filesystem_size_bytes{job="node-exporter-ldap",mountpoint="/"})*100)` |
| Uptime | 4 | `time()-node_boot_time_seconds{job="node-exporter-ldap"}` |
| LDAP Servicio | 5 | `medtrans_ldap_up` (con mappings: 0=CAIDO/rojo, 1=ACTIVO/verde) |
| Usuarios Activos | 6 | `medtrans_users_active` |

### Sección 2: Panel de Seguridad

Métricas de seguridad. Mezcla Prometheus (ldap_exporter) y OpenSearch (alertas).

| Panel | ID | Fuente | Query |
| --- | --- | --- | --- |
| Alertas Hoy | 7 | OpenSearch | `agent.name:lxc-ldap OR agent.name:lxc-honeypot` |
| Alertas Críticas | 8 | OpenSearch | `(agent.name:lxc-ldap OR agent.name:lxc-honeypot) AND rule.level:>11` |
| IPs Bloqueadas | 9 | Prometheus | `medtrans_blocked_ips_total` |
| Hosts Aislados | 10 | Prometheus | `medtrans_isolated_hosts_total` |
| Amenazas Detectadas | 11 | Prometheus | `medtrans_threat_malicious_total` |
| Usuarios Deshabilitados | 12 | Prometheus | `medtrans_users_disabled` |

### Sección 3: Monitorización en Tiempo Real

Gráficas históricas con datos de las últimas 24 horas.

| Panel | ID | Query |
| --- | --- | --- |
| CPU % | 13 | `100-(avg(rate(node_cpu_seconds_total{job="node-exporter-ldap",mode="idle"}[5m]))*100)` |
| RAM | 14 | `node_memory_MemTotal_bytes` y `node_memory_MemAvailable_bytes` |
| Tráfico de Red | 15 | `rate(node_network_receive/transmit_bytes_total{job="node-exporter-ldap",device="eth0"}[5m])` |

### Sección 4: Directorio de Usuarios MedTrans

Estado en tiempo real del directorio LDAP del cliente.

| Panel | ID | Tipo | Descripción |
| --- | --- | --- | --- |
| Estado de Usuarios | 16 | Table | `medtrans_user_status` con mappings 0=❌/1=✅ por color |
| Usuarios por Departamento | 17 | Pie donut | `medtrans_users_by_dept` |
| Estado Usuarios | 18 | Pie donut | Activos vs Deshabilitados |

### Sección 5: Threat Intelligence & Bloqueos

Datos de AbuseIPDB y análisis de IPs maliciosas.

| Panel | ID | Tipo | Descripción |
| --- | --- | --- | --- |
| IPs Analizadas AbuseIPDB Score | 19 | Table + gauge | `medtrans_threat_ip` con gauge de score 0-100% |
| Total IPs Analizadas | 20 | Stat | `medtrans_threat_reports_total` |
| IPs Maliciosas | 21 | Stat (rojo si >0) | `medtrans_threat_malicious_total` |
| IPs Bloqueadas Ahora | 22 | Stat | `medtrans_blocked_ips_total` |
| Hosts Aislados | 23 | Stat (rojo si >0) | `medtrans_isolated_hosts_total` |

### Sección 6: Alertas de Seguridad Detectadas

Timeline y tabla de alertas de Wazuh.

| Panel | ID | Tipo | Descripción |
| --- | --- | --- | --- |
| Alertas en el Tiempo | 24 | Timeseries | Críticas (>11) y Medias (5-11) |
| Últimas Alertas | 25 | Table | Hora, Nivel, Descripción, Tipo, IP Origen, Agente |

### Tabla de alertas — columnas finales

```
Hora | Nivel (con color semáforo) | Descripcion | Tipo (rule.groups) | IP Origen | Agente
```

Columnas excluidas: `@timestamp`, `_id`, `_index`, `_type`, `agent.id`, `agent.ip`, `decoder.name`, `decoder.parent`, `full_log`, `highlight`, `id`, `input.type`, `location`, `manager.name`, `predecoder.*`, `rule.mail`, `rule.firedtimes`, `rule.groups`, `data.uid`, `data.dstuser`, `data.extra_data`, `rule.pci_dss`, `rule.gdpr`, `rule.hipaa`, `rule.nist_800_53`, `rule.tsc`, `rule.cis`, `rule.mitre_*`.

---

## 4. API Grafana para portal web

### Renderizar paneles como imágenes PNG

Cada panel del dashboard puede exportarse como imagen PNG mediante la API de Grafana:

```
http://100.92.243.96:3000/render/d-solo/medtrans-node
  ?orgId=1
  &panelId=<ID>
  &width=800
  &height=400
  &from=now-24h
  &to=now
  &tz=Europe/Madrid
```

### Parámetros disponibles

| Parámetro | Descripción | Ejemplo |
| --- | --- | --- |
| `panelId` | ID del panel | 1, 7, 13, 25 |
| `width` | Anchura en píxeles | 800 |
| `height` | Altura en píxeles | 400 |
| `from` | Inicio del rango | `now-24h`, `now-7d` |
| `to` | Fin del rango | `now` |
| `tz` | Zona horaria | `Europe/Madrid` |

### IDs de paneles por sección

| Sección | Paneles |
| --- | --- |
| Estado sistema | 1 (CPU), 2 (RAM), 3 (Disco), 4 (Uptime), 5 (LDAP), 6 (Usuarios) |
| Seguridad | 7 (Alertas), 8 (Críticas), 9 (IPs bloqueadas), 10 (Hosts), 11 (Amenazas), 12 (Deshabilitados) |
| Gráficas sistema | 13 (CPU hist), 14 (RAM hist), 15 (Red) |
| Directorio | 16 (Tabla usuarios), 17 (Por dept), 18 (Estado) |
| Threat Intel | 19 (IPs tabla), 20 (Total), 21 (Maliciosas), 22 (Bloqueadas), 23 (Aislados) |
| Alertas | 24 (Timeline), 25 (Tabla alertas) |

### Proxy PHP recomendado

Para ocultar las credenciales de Grafana al navegador del cliente:

```php
<?php
// grafana_proxy.php
$panel_id = intval($_GET['panel'] ?? 1);
$from     = $_GET['from'] ?? 'now-24h';
$width    = intval($_GET['width'] ?? 800);
$height   = intval($_GET['height'] ?? 400);

$url = "http://100.92.243.96:3000/render/d-solo/medtrans-node"
     . "?orgId=1&panelId={$panel_id}"
     . "&width={$width}&height={$height}"
     . "&from={$from}&to=now&tz=Europe/Madrid";

$ctx = stream_context_create(['http' => [
    'header' => "Authorization: Basic " . base64_encode("cyntia:-")
]]);

$img = @file_get_contents($url, false, $ctx);

if ($img === false) {
    http_response_code(500);
    exit;
}

header('Content-Type: image/png');
header('Cache-Control: max-age=60');
echo $img;
?>
```

### Uso en HTML

```html
<!-- Stats individuales -->
<img src="grafana_proxy.php?panel=1&width=300&height=150" alt="CPU">
<img src="grafana_proxy.php?panel=7&width=300&height=150" alt="Alertas">

<!-- Gráficas históricas -->
<img src="grafana_proxy.php?panel=13&width=700&height=300&from=now-7d" alt="CPU histórico">
<img src="grafana_proxy.php?panel=15&width=700&height=300" alt="Red">

<!-- Tabla de alertas -->
<img src="grafana_proxy.php?panel=25&width=1200&height=500" alt="Últimas alertas">
```

---

## 5. Problemas encontrados y soluciones

### Problema 1: Métricas ldap_exporter con “No data” en Grafana

**Causa:** El label `cliente` era sobreescrito por Prometheus. El exporter exportaba `cliente="MedTrans"` pero Prometheus añadía `cliente="MedTrans-Iberica"` del `prometheus.yml`. Las queries usaban `cliente="MedTrans"` que no existía.

**Solución:** Eliminar el filtro de label en las queries:

```
# Antes (no funcionaba)
medtrans_users_active{cliente="MedTrans"}

# Después (correcto)
medtrans_users_active
```

### Problema 2: Grafana no alcanzaba OpenSearch

**Causa:** Grafana (red `cyntia-monitoring_monitoring`) y OpenSearch (red `single-node_cyntia-wazuh`) estaban en redes Docker distintas.

**Solución:** Conectar el contenedor Grafana a la red de Wazuh:

```bash
pct exec 101 -- docker network connect single-node_cyntia-wazuh grafana
# Grafana obtiene IP 172.21.0.5 en la red Wazuh
```

### Problema 3: Patrón de índice incorrecto

**Error:** `invalid index pattern wazuh-alerts-4.x-*. Specify an index with a time pattern`

**Causa:** El datasource Elasticsearch de Grafana no acepta wildcards directos.

**Solución:** Usar el formato con patrón de tiempo:

```
[wazuh-alerts-4.x-]YYYY.MM.DD
```

### Problema 4: Paneles de alertas con “No data” en rango de 6 horas

**Causa:** Las últimas alertas de lxc-ldap en OpenSearch eran del día anterior.

**Solución:** Cambiar el rango por defecto del dashboard a 24 horas:

```python
dash["dashboard"]["time"] = {"from": "now-24h", "to": "now"}
```

### Problema 5: Columnas innecesarias en tabla de alertas

Las tablas de Grafana con datos raw de OpenSearch muestran todos los campos del documento. Se usó la transformación `organize` para excluir columnas y renombrar las que quedan:

```json
{
  "id": "organize",
  "options": {
    "excludeByName": {"@timestamp": true, "_id": true, ...},
    "renameByName": {
      "timestamp": "Hora",
      "rule.level": "Nivel",
      "rule.description": "Descripcion",
      "rule.groups": "Tipo",
      "data.srcip": "IP Origen",
      "agent.name": "Agente"
    }
  }
}
```

### Problema 6: Plugin opensearch-datasource no instalado

**Causa:** Grafana solo tiene instalado el plugin `elasticsearch` (v12.4.2), no el plugin específico de OpenSearch.

**Solución:** Usar el datasource de tipo `elasticsearch` que es compatible con la API de OpenSearch. Ajustar `esVersion` a `7.10.0`.

### Problema 7: Tabla “Estado de Usuarios” mostrando columnas internas

Las métricas de Prometheus incluyen labels internos (`__name__`, `cliente`, `instance`, `job`) que aparecían como columnas en la tabla.

**Solución:** Usar la transformación `organize` para excluirlas:

```json
{
  "excludeByName": {
    "__name__": true,
    "cliente": true,
    "instance": true,
    "job": true,
    "Time": true
  }
}
```

---

## 6. Verificación completa

### Estado de todos los componentes del dashboard

```bash
pct exec 101 -- bash -c "
echo '=== LDAP EXPORTER ==='
systemctl is-active ldap-exporter
curl -s http://localhost:9300/metrics | head -10

echo '=== PROMETHEUS TARGETS ==='
curl -s http://172.20.0.2:9090/api/v1/targets | python3 -c\"
import sys, json
d = json.load(sys.stdin)
for t in d['data']['activeTargets']:
    job = t['labels']['job']
    health = t['health']
    print(f'{job:30} | {health}')
\"

echo '=== GRAFANA DATASOURCES ==='
curl -s -u cyntia:- http://172.20.0.4:3000/api/datasources | python3 -c\"
import sys, json
for d in json.load(sys.stdin):
    print(f'id={d[\\\"id\\\"]} | uid={d[\\\"uid\\\"]} | {d[\\\"name\\\"]} | {d[\\\"type\\\"]}')
\"

echo '=== DASHBOARD MEDTRANS ==='
curl -s -u cyntia:-\
  http://172.20.0.4:3000/api/dashboards/uid/medtrans-node | python3 -c\"
import sys, json
d = json.load(sys.stdin)
panels = [p for p in d['dashboard']['panels'] if p.get('type') != 'row']
print(f'Dashboard: {d[\\\"dashboard\\\"][\\\"title\\\"]}')
print(f'Paneles activos: {len(panels)}')
\"

echo '=== OPENSEARCH INDICES DISPONIBLES ==='
docker exec grafana sh -c 'curl -sk -u \
  https://172.21.0.2:9200/_cat/indices?v' | grep wazuh-alerts |\
  awk '{print\$3,\$7}' | sort | tail -5

echo '=== RED GRAFANA ==='
docker inspect grafana --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'
"
```

### Accesos del dashboard

| URL | Descripción |
| --- | --- |
| `http://100.92.243.96:3000/d/medtrans-node` | Dashboard completo MedTrans |
| `http://100.92.243.96:3000/d/cyntia-security` | Panel de seguridad SOC interno |
| `http://100.92.243.96:9300/metrics` | Métricas ldap_exporter (desde Tailscale) |