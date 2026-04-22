# Guía Proxmox - Fase 5

**Suricata IDS: Instalación, Configuración e Integración con Wazuh**

## Introducción

Suricata es el sistema de detección de intrusiones de red (IDS) del proyecto Cyntia. Su función es analizar **en tiempo real todo el tráfico** que circula entre las zonas de red (DMZ, VLAN 10, VLAN 20) buscando patrones de ataque conocidos mediante firmas.

A diferencia de Wazuh, que analiza eventos en los sistemas (logs, integridad de ficheros), Suricata trabaja a nivel de red capturando y analizando paquetes. Ambas capas se complementan: Wazuh detecta lo que pasa dentro de los sistemas, Suricata detecta lo que pasa en la red.

**Contenedor:** lxc-soc-core (VMID 101, IP 192.168.20.3)
**Interfaz de escucha:** eth0 (equivalente a vmbr0 del host dentro del LXC)

---

## Verificación previa del estado de Wazuh

Antes de instalar Suricata, verificamos que el stack Wazuh estaba completamente operativo:

```bash
pct exec 101 -- bash -c "docker compose -f /opt/wazuh-docker/single-node/docker-compose.yml ps"
```

Los tres contenedores deben aparecer en estado `Up`:
- `single-node-wazuh.manager-1`
- `single-node-wazuh.indexer-1`
- `single-node-wazuh.dashboard-1`

---

## Instalación de Suricata

Entramos en lxc-soc-core e instalamos Suricata junto con su herramienta de actualización de reglas:

```bash
pct exec 101 -- bash
apt-get update && apt-get install -y suricata suricata-update
```

**Por qué `suricata-update`:** Es la herramienta oficial para descargar y mantener actualizados los conjuntos de reglas (rulesets). El más importante es **ET Open** (Emerging Threats Open), que contiene más de 49.000 firmas de ataques conocidos actualizadas continuamente por la comunidad.

Verificamos la instalación:

```bash
suricata -V
```

---

## Configuración de Suricata

### Paso 1 — Descargar las reglas ET Open

```bash
suricata-update
```

Este comando descarga las reglas en `/var/lib/suricata/rules/suricata.rules`.

### Paso 2 — Configurar la interfaz de red

Editamos el fichero principal de configuración:

```bash
nano /etc/suricata/suricata.yaml
```

**Interfaz de captura (af-packet):**

```yaml
af-packet:
-interface: eth0
cluster-id:99
cluster-type: cluster_flow
defrag:yes
use-mmap:yes
tpacket-v3:yes
```

> ⚠️ **Importante:** Dentro del LXC la interfaz se llama `eth0`, no `vmbr0`. Este es un error común — vmbr0 solo existe en el host Proxmox, no dentro de los contenedores.
> 

**Ruta de las reglas:**

Suricata por defecto busca las reglas en `/etc/suricata/rules/`, pero `suricata-update` las guarda en `/var/lib/suricata/rules/`. Hay que corregir la ruta:

```bash
sed -i 's|- suricata.rules|- /var/lib/suricata/rules/suricata.rules|' /etc/suricata/suricata.yaml
```

### Paso 3 — Arrancar y habilitar Suricata

```bash
systemctl enable suricata
systemctl start suricata
```

### Paso 4 — Verificar que las reglas están cargadas

```bash
grep -i "signatures processed" /var/log/suricata/suricata.log | tail -3
```

Resultado esperado:

```
25/3/2026 -- 22:23:46 - <Info> - 49215 signatures processed. 1272 are IP-only rules...
```

**49.215 reglas cargadas** es el resultado correcto con ET Open completo.

---

## Integración con Wazuh

### ¿Por qué integrar Suricata con Wazuh?

Suricata genera alertas en su propio formato en `/var/log/suricata/eve.json`. Para que estas alertas aparezcan en el dashboard de Wazuh y se correlacionen con otros eventos del sistema, hay que decirle al Wazuh Manager que monitorice ese fichero.

### Paso 1 — Montar el directorio de logs en el contenedor Docker

El Wazuh Manager corre en Docker, pero el fichero `eve.json` está en el LXC (fuera del contenedor). Hay que montar el directorio como volumen en el `docker-compose.yml`:

```bash
nano /opt/wazuh-docker/single-node/docker-compose.yml
```

En la sección `volumes:` del servicio `wazuh.manager` añadir:

```yaml
- /var/log/suricata:/var/log/suricata:ro
```

El `:ro` significa que el contenedor solo puede leer (read-only), no modificar los logs originales.

### Paso 2 — Configurar el Wazuh Manager para leer el eve.json

El fichero de configuración principal del manager es `wazuh_manager.conf`. Añadir al final, dentro del último bloque `<ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

> ⚠️ **Importante:** Wazuh usa múltiples bloques `<ossec_config>` en el mismo fichero, lo cual es válido para Wazuh pero no es XML estándar. Nunca añadir un bloque `<ossec_config>` nuevo fuera del existente — hay que insertar el `<localfile>` dentro del bloque existente.
> 

### Paso 3 — Sincronizar la configuración

El fichero `wazuh_manager.conf` se monta en el contenedor como `/wazuh-config-mount/etc/ossec.conf`. Hay que copiar su contenido al fichero que usa Wazuh internamente:

```bash
docker exec single-node-wazuh.manager-1 bash -c "cat /wazuh-config-mount/etc/ossec.conf > /var/ossec/etc/ossec.conf"
```

Y reiniciar el manager:

```bash
cd /opt/wazuh-docker/single-node
docker compose up -d --no-deps wazuh.manager
```

---

## Resolución de problemas encontrados

### Problema 1: `rules_loaded: 0`

**Síntoma:** Suricata arranca pero no detecta ninguna alerta.

**Causa:** La ruta de las reglas en `suricata.yaml` apuntaba a `/etc/suricata/rules/suricata.rules` pero las reglas descargadas por `suricata-update` están en `/var/lib/suricata/rules/suricata.rules`.

**Solución:**

```bash
sed -i 's|- suricata.rules|- /var/lib/suricata/rules/suricata.rules|' /etc/suricata/suricata.yaml
systemctl restart suricata
```

### Problema 2: Wazuh daemons no arrancan (ossec.conf corrupto)

**Síntoma:** `wazuh-analysisd` falla con `Configuration error at 'etc/ossec.conf': (line 0)`.

**Causa:** El volumen Docker persistente `single-node_wazuh_etc` tenía el `ossec.conf` en estado corrupto tras múltiples reinicios y modificaciones. El volumen sobreescribía el fichero correcto en cada arranque.

**Solución:** Eliminar todos los volúmenes de Wazuh (excepto el del indexer que contiene las alertas) y dejar que el contenedor los recree desde cero:

```bash
docker compose down
docker volume rm single-node_wazuh_etc single-node_wazuh_logs single-node_wazuh_queue \
  single-node_wazuh_var_multigroups single-node_wazuh_integrations \
  single-node_wazuh_active_response single-node_wazuh_agentless single-node_wazuh_wodles
docker compose up -d
```

### Problema 3: `ar.conf` no encontrado al arrancar

**Síntoma:** `wazuh-analysisd: ERROR: Could not open file 'etc/shared/ar.conf'`

**Causa:** Al recrear los volúmenes, el directorio `/var/ossec/etc/shared/` no existía y el script de arranque del contenedor fallaba antes de poder crearlo.

**Solución:** Crear un script de entrypoint que se ejecuta automáticamente antes del arranque de Wazuh:

```bash
docker exec single-node-wazuh.manager-1 bash -c \
  'mkdir -p /entrypoint-scripts && printf "%s\n" "#!/bin/bash" \
  "mkdir -p /var/ossec/etc/shared/default" \
  "touch /var/ossec/etc/shared/ar.conf" \
  "chown wazuh:wazuh /var/ossec/etc/shared/ar.conf" \
  "cat /wazuh-config-mount/etc/ossec.conf > /var/ossec/etc/ossec.conf" \
  > /entrypoint-scripts/01-fix-ar.sh && chmod +x /entrypoint-scripts/01-fix-ar.sh'
```

El directorio `/entrypoint-scripts/` es leído automáticamente por el init del contenedor antes de arrancar los servicios de Wazuh.

---

## Verificación final

### Verificar que Suricata detecta ataques

Desde el host cyntia, ejecutar un escaneo de vulnerabilidades:

```bash
nmap -sS --script vuln 192.168.20.3
```

Verificar que Suricata genera alertas:

```bash
tail -f /var/log/suricata/fast.log
```

Resultado esperado:

```
[1:2024364:4] ET SCAN Possible Nmap User-Agent Observed [Priority: 1]
```

### Verificar que las alertas llegan a Wazuh

```bash
docker exec single-node-wazuh.manager-1 grep -c "suricata" /var/ossec/logs/alerts/alerts.json
```

**Resultado obtenido: 2.287.902 alertas de Suricata procesadas por Wazuh.**

### Verificar todos los daemons de Wazuh activos

```bash
docker exec single-node-wazuh.manager-1 ps aux | grep -E "analysisd|remoted|logcollector" | grep -v grep
```

Deben aparecer los tres procesos corriendo.

---

## Estado final

| Componente | Estado | Detalle |
| --- | --- | --- |
| Suricata | ✅ Activo | 49.215 reglas ET Open cargadas |
| eve.json | ✅ Creciendo | ~11.000+ líneas por hora |
| Wazuh analysisd | ✅ Activo | Procesando alertas Suricata |
| Wazuh logcollector | ✅ Activo | Monitorizando eve.json |
| Alertas en dashboard | ✅ Visibles | Grupo `ids/suricata` |

---

## Configuración persistente para reboots

Para que Suricata arranque automáticamente:

```bash
systemctl enable suricata
```

Para que el entrypoint script persista en Wazuh, está guardado dentro del contenedor. Si se hace `docker compose down && up`, hay que volver a ejecutar el script de creación del entrypoint.
