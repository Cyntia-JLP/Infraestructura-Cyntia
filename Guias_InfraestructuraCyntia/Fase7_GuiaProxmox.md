# Guía Proxmox - Fase 7

**Grafana + Prometheus: Monitorización de Infraestructura**

---

## 1. Contexto y objetivos

Grafana y Prometheus son los dos componentes encargados de la **monitorización de infraestructura** en Cyntia. Mientras que Wazuh se ocupa de los eventos de seguridad, Grafana y Prometheus cubren las métricas del sistema: CPU, RAM, disco y red de cada contenedor y máquina.

Según el diagrama del proyecto, ambos servicios se despliegan dentro de `lxc-soc-core` junto a Wazuh, compartiendo el mismo entorno Docker. Para no interferir con el compose de Wazuh ya funcional, se crea un **compose separado** en `/opt/cyntia-monitoring/`.

El stack tiene tres componentes:

- **Prometheus**: motor de recopilación de métricas. Consulta periódicamente a los exporters y almacena los datos en una base de datos de series temporales.
- **Node Exporter**: agente ligero que expone las métricas del sistema operativo (CPU, RAM, disco, red) en formato Prometheus.
- **Grafana**: interfaz de visualización. Consulta Prometheus como fuente de datos y muestra dashboards interactivos.

---

## 2. Verificación del estado previo

Antes de añadir cualquier componente nuevo, siempre verificamos que la infraestructura existente está operativa para no introducir problemas sobre una base inestable.

```bash
# Verificar que todos los LXC están corriendo
pct list

# Verificar que Wazuh sigue funcionando
pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose ps"

# Verificar el estado del cluster Proxmox
pvecm status
```

**Por qué es importante:** Si Wazuh o el cluster están caídos antes de empezar y luego aparece un problema, no sabemos si lo causamos nosotros o ya existía.

---

## 3. Despliegue del stack de monitorización

### 3.1. Estructura de directorios

Entramos en lxc-soc-core y creamos un directorio independiente para el nuevo stack:

```bash
pct exec 101 -- bash
mkdir -p /opt/cyntia-monitoring
```

**Por qué un directorio separado:** Mantener el compose de Grafana/Prometheus separado del de Wazuh permite reiniciar o modificar uno sin afectar al otro. Es una buena práctica de gestión de servicios.

### 3.2. Docker Compose con red fija

Creamos el `docker-compose.yml` con una **red personalizada de subred fija**. Esto es crítico porque Docker asigna IPs dinámicamente y cambian en cada reinicio, lo que rompería las configuraciones que dependen de ellas.

```bash
cat > /opt/cyntia-monitoring/docker-compose.yml << 'EOF'
version: '3.8'

networks:
  monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: always
    networks:
      monitoring:
        ipv4_address: 172.20.0.2
    volumes:
      - /opt/cyntia-monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: always
    networks:
      monitoring:
        ipv4_address: 172.20.0.3
    ports:
      - "9100:9100"

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: always
    networks:
      monitoring:
        ipv4_address: 172.20.0.4
    environment:
      - GF_SECURITY_ADMIN_USER=-
      - GF_SECURITY_ADMIN_PASSWORD=-
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"

volumes:
  prometheus_data:
  grafana_data:
EOF
```

**Asignación de IPs fijas en la red `172.20.0.0/24`:**

| Contenedor | IP fija |
| --- | --- |
| Prometheus | 172.20.0.2 |
| Node Exporter | 172.20.0.3 |
| Grafana | 172.20.0.4 |

**Por qué IPs fijas:** Sin IPs fijas, cada vez que se reinicia el LXC o se recrea un contenedor Docker, las IPs cambian. Esto rompe el `prometheus.yml` y el relay de socat. Con una subred fija y `ipv4_address` definido en el compose, las IPs son siempre las mismas independientemente de cuántas veces se reinicie.

### 3.3. Configuración de Prometheus

```bash
cat > /opt/cyntia-monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 30s
  scrape_timeout: 25s
  evaluation_interval: 30s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['172.20.0.2:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['172.20.0.3:9100']
        labels:
          instance: 'lxc-soc-core'
EOF
```

**Por qué `scrape_timeout: 25s` y `scrape_interval: 30s`:** En el entorno del proyecto, el primer scrape dentro de un LXC tarda más de lo habitual debido a la carga del sistema. Con el timeout por defecto de 10 segundos fallaba continuamente. Aumentar el timeout a 25 segundos resuelve el problema sin sacrificar la frecuencia de actualización.

**Por qué usar IPs en lugar de `localhost`:** Prometheus corre dentro de un contenedor Docker. `localhost` dentro del contenedor se refiere al propio contenedor, no al host ni a otros contenedores. Hay que usar las IPs de la red Docker para que los contenedores se comuniquen entre sí.

### 3.4. Arranque del stack

```bash
cd /opt/cyntia-monitoring
docker compose up -d
```

Verificamos que los tres contenedores están corriendo:

```bash
docker compose ps
```

---

## 4. Acceso remoto via Tailscale

### 4.1. Reglas nftables

El acceso externo a Grafana llega por Tailscale (interfaz `tailscale0`). Hay que añadir una regla DNAT en el host Proxmox para redirigir el tráfico entrante al puerto 3000 de lxc-soc-core.

En `/etc/nftables.conf`, en el bloque `chain prerouting` de `table ip nat`:

```
# Grafana
iifname "tailscale0" tcp dport 3000 dnat to 192.168.20.3:13000
# Prometheus (opcional, para acceso directo)
iifname "tailscale0" tcp dport 9090 dnat to 192.168.20.3:9090
```

```bash
systemctl restart nftables
```

**Por qué el puerto 13000 y no directamente el 3000:** Docker dentro de un LXC no privilegiado en Proxmox tiene un problema conocido: aunque expone los puertos con `ports:`, las conexiones externas que llegan al LXC son rechazadas por las reglas iptables internas de Docker. La solución es usar `socat` como relay dentro del LXC, igual que se hizo para los puertos de Wazuh.

### 4.2. Relay socat dentro de lxc-soc-core

`socat` escucha en `192.168.20.3:13000` (IP del LXC en VLAN 20, accesible desde el host) y reenvía las conexiones al contenedor Grafana en `172.20.0.4:3000`.

```bash
pct exec 101 -- bash -c "cat > /etc/systemd/system/grafana-docker-relay.service << 'EOF'
[Unit]
Description=Grafana Docker relay
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:13000,fork TCP:172.20.0.4:3000
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable grafana-docker-relay && systemctl start grafana-docker-relay"
```

El flujo completo de acceso es:

```
Navegador → 100.92.243.96:3000 (Tailscale)
  → DNAT nftables → 192.168.20.3:13000
  → socat relay (dentro de lxc-soc-core)
  → 172.20.0.4:3000 (contenedor Grafana)
```

---

## 5. Configuración de Grafana

### 5.1. Credenciales de acceso

**Nota importante:** La variable de entorno `GF_SECURITY_ADMIN_PASSWORD` solo se aplica la primera vez que se crea el volumen de Grafana. Si el contenedor ya existe y se cambia la contraseña en el compose, no tiene efecto. Para cambiarla después de la primera inicialización hay que usar:

```bash
# Parar Grafana primero (la BD debe estar libre)
docker stop grafana
# Borrar el volumen y recrear (única forma fiable)
docker compose rm -f grafana
docker volume rm cyntia-monitoring_grafana_data
docker compose up -d grafana
```

### 5.2. Añadir Prometheus como fuente de datos

Como la UI de Grafana tiene problemas cargando plugins desde internet en este entorno, se añade el datasource directamente via API REST:

```bash
curl -X POST http://192.168.20.3:13000/api/datasources \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic$(echo -n '-' | base64)" \
  -d '{
    "name": "Prometheus",
    "type": "prometheus",
    "url": "http://172.20.0.2:9090",
    "access": "proxy",
    "isDefault": true
  }'
```

**Por qué la autenticación con cabecera `Authorization: Basic`:** La contraseña contiene el carácter `@`, que curl interpreta como separador de credenciales en la URL. Para evitarlo, se usa la cabecera HTTP de autenticación básica con las credenciales en base64.

**Por qué `"access": "proxy"`:** En modo proxy, Grafana hace las peticiones a Prometheus desde el servidor (backend), no desde el navegador del cliente. Esto es necesario porque Prometheus no es accesible directamente desde el navegador del usuario, solo desde dentro del LXC.

Si hay que actualizar el datasource (por ejemplo, si cambia la IP de Prometheus):

```bash
curl -X PUT http://192.168.20.3:13000/api/datasources/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic$(echo -n '-' | base64)" \
  -d '{"name":"Prometheus","type":"prometheus","url":"http://172.20.0.2:9090","access":"proxy","isDefault":true}'
```

---

## 6. Solución de problemas de red Docker

### 6.1. El problema de las IPs dinámicas

Docker asigna IPs a los contenedores dinámicamente dentro de la subred del bridge. Cada vez que se recrea un contenedor o se reinicia el LXC, las IPs pueden cambiar. Esto provoca que `prometheus.yml` apunte a IPs incorrectas y los scrapers fallen.

**Solución implementada:** Red Docker personalizada con subred fija (`172.20.0.0/24`) y `ipv4_address` definido para cada contenedor en el compose. Así las IPs son siempre las mismas.

### 6.2. El problema del scrape timeout

Con la configuración por defecto (`scrape_timeout: 10s`), Prometheus fallaba con `context deadline exceeded` al intentar scrapear Node Exporter. El scrape tardaba más de 20 segundos la primera vez.

**Solución:** Aumentar `scrape_timeout` a 25s y `scrape_interval` a 30s en `prometheus.yml`.

### 6.3. Verificación de conectividad entre contenedores

Para comprobar que los contenedores Docker se comunican entre sí:

```bash
# Verificar que Prometheus puede alcanzar Node Exporter
docker exec prometheus wget -q -O- --timeout=3 http://172.20.0.3:9100/metrics | head -3

# Verificar el estado de los targets en Prometheus
curl -s 'http://172.20.0.2:9090/api/v1/targets' | grep '"health"'
```

Los targets deben mostrar `"health":"up"` para estar funcionando correctamente.

---

## 7. Configuración de Prometheus

### 7.1. Verificar que los targets están activos

```bash
pct exec 101 -- bash -c "curl -s 'http://172.20.0.2:9090/api/v1/targets'"
```

La respuesta debe mostrar `"health":"up"` para ambos jobs:

- `prometheus` → `172.20.0.2:9090`
- `node-exporter` → `172.20.0.3:9100` con label `instance: lxc-soc-core`

### 7.2. Consulta de prueba

```bash
pct exec 101 -- bash -c "curl -s 'http://172.20.0.2:9090/api/v1/query?query=up'"
```

Debe devolver `"value": [timestamp, "1"]` para cada target activo.

---

## 8. Dashboard de infraestructura

### 8.1. Importar Node Exporter Full (ID 1860)

El dashboard oficial de Node Exporter Full (ID 1860 en Grafana.com) es el más completo para monitorización de infraestructura Linux. Incluye más de 200 paneles con métricas de CPU, memoria, disco, red, procesos y más.

Como la UI de Grafana no puede cargar el catálogo de plugins por limitaciones de red, se importa via script Python para evitar el límite de longitud de argumentos de bash:

```bash
# Descargar el JSON del dashboard
curl -s https://grafana.com/api/dashboards/1860/revisions/latest/download \
  -o /tmp/node-exporter-dashboard.json

# Importarlo via API con Python
python3 << 'EOF'
import json, urllib.request, base64

with open('/tmp/node-exporter-dashboard.json') as f:
    dashboard = json.load(f)

payload = json.dumps({
    "dashboard": dashboard,
    "overwrite": True,
    "inputs": [{"name": "DS_PROMETHEUS", "type": "datasource",
                "pluginId": "prometheus", "value": "Prometheus"}],
    "folderId": 0
}).encode()

creds = base64.b64encode(b'cyntia:-').decode()
req = urllib.request.Request(
    'http://192.168.20.3:13000/api/dashboards/import',
    data=payload,
    headers={'Content-Type': 'application/json',
             'Authorization': f'Basic {creds}'}
)
resp = urllib.request.urlopen(req)
print(resp.read().decode())
EOF
```

**Por qué Python y no curl:** El JSON del dashboard pesa 482KB. Bash no puede pasar argumentos de ese tamaño a `curl` directamente (límite del sistema). Python gestiona el fichero en memoria y lo envía sin este problema.

### 8.2. Acceso al dashboard

```
http://100.92.243.96:3000/d/rYdddlPWk/node-exporter-full
```

El dashboard muestra en tiempo real:
- Uso de CPU por core
- Uso de memoria RAM y swap
- I/O de disco (lectura/escritura)
- Tráfico de red (entrada/salida)
- Carga del sistema (load average)
- Temperatura (si el hardware lo soporta)

---

## 9. Estado final

### Servicios corriendo en lxc-soc-core

| Servicio | IP fija | Puerto | Función |
| --- | --- | --- | --- |
| Prometheus | 172.20.0.2 | 9090 | Motor de recopilación de métricas |
| Node Exporter | 172.20.0.3 | 9100 | Expone métricas del sistema |
| Grafana | 172.20.0.4 | 3000 | Visualización de dashboards |

### Acceso externo

| Servicio | URL de acceso |
| --- | --- |
| Grafana | http://100.92.243.96:3000 |
| Dashboard | http://100.92.243.96:3000/d/rYdddlPWk/node-exporter-full |

### Relay socat activo en lxc-soc-core

| Servicio | Escucha | Reenvía a |
| --- | --- | --- |
| grafana-docker-relay | 192.168.20.3:13000 | 172.20.0.4:3000 |

### Resumen de lo conseguido

- ✅ Prometheus recopilando métricas cada 30 segundos
- ✅ Node Exporter exponiendo métricas de lxc-soc-core
- ✅ Grafana accesible vía Tailscale con usuario `cyntia`
- ✅ Datasource Prometheus configurado y funcionando
- ✅ Dashboard Node Exporter Full importado y mostrando métricas en tiempo real
- ✅ Red Docker con IPs fijas para evitar problemas en reboots
- ✅ Relay socat habilitado como servicio systemd con autostart

### Tabla de errores y soluciones

| Error | Causa | Solución |
| --- | --- | --- |
| `context deadline exceeded` | Timeout de scrape demasiado corto | Aumentar `scrape_timeout` a 25s |
| IPs Docker cambian en cada reboot | Docker asigna IPs dinámicamente | Red personalizada con `ipv4_address` fija |
| Conexión rechazada al puerto 3000 desde fuera del LXC | Docker en LXC no privilegiado bloquea conexiones externas | Relay socat en puerto 13000 |
| `Argument list too long` en curl | JSON de 482KB supera límite de args de bash | Importar el dashboard con Python |
| `GF_SECURITY_ADMIN_PASSWORD` no se aplica | Variable solo funciona en la primera inicialización | Borrar volumen y recrear el contenedor |
| `Cannot resolve host: f4n4` en curl | El `@` de la contraseña confunde la URL | Usar cabecera `Authorization: Basic` con base64 |
