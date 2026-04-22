# Guía Proxmox - Fase 8

**Infraestructura fase 8: Estabilización, Optimización y Diagnóstico del Sistema**

---

## Introducción

Una vez desplegado el stack completo (Wazuh, Suricata, OpenCanary, Grafana, Prometheus, cluster Proxmox), el siguiente paso crítico es **estabilizar el sistema**: garantizar que todos los servicios arrancan correctamente tras un reinicio, que los recursos están bien repartidos, y que disponemos de herramientas para diagnosticar problemas rápidamente.

Este documento cubre cuatro grandes bloques:
1. Reconexión del agente Wazuh del honeypot
2. IPs fijas para contenedores Docker de Wazuh
3. Acceso al dashboard de Wazuh y Grafana desde el navegador
4. Diagnóstico y optimización de recursos

---

## Parte 1 · Verificación del estado inicial del sistema

Antes de cualquier intervención, verificamos el estado completo del sistema:

```bash
pct list
qm list
pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose ps"
pct exec 101 -- bash -c "cd /opt/cyntia-monitoring && docker compose ps"
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
pvecm status
```

---

## Parte 2 · Reconexión del agente Wazuh (lxc-honeypot)

### Diagnóstico

El agente 003 (lxc-honeypot) aparecía como `Disconnected`. Los relays socat estaban activos pero la conexión se cerraba inmediatamente — problema de clave de agente desincronizada. Además, la IP del contenedor Docker del manager había cambiado tras un reinicio del stack.

### Solución 1: actualizar relay a IP correcta

```bash
# Verificar IP actual del manager
pct exec 101 -- bash -c "docker inspect single-node-wazuh.manager-1 | grep IPAddress"

# Actualizar el relay
pct exec 101 -- bash -c "sed -i 's|TCP:172.18.0.4:1514|TCP:172.21.0.4:1514|'\
  /etc/systemd/system/wazuh-docker-relay.service &&\
  systemctl daemon-reload && systemctl restart wazuh-docker-relay"
```

### Solución 2: reimportar clave del agente

```bash
# Exportar clave desde el manager
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -e 003"

# Importar en el honeypot (confirmar con 'y')
pct exec 103 -- bash -c "/var/ossec/bin/manage_agents -i <CLAVE_EXPORTADA>"

# Reiniciar agente
pct exec 103 -- bash -c "/var/ossec/bin/wazuh-control restart"
sleep 30

# Verificar
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
```

---

## Parte 3 · IPs fijas para contenedores Docker de Wazuh

### Por qué es necesario

Por defecto, Docker asigna IPs dinámicamente. Cada reinicio del stack puede cambiar las IPs, rompiendo los relays socat.

### Añadir red fija en docker-compose.yml

```bash
cd /opt/wazuh-docker/single-node

# Añadir IPs fijas a cada servicio con Python
python3 << 'EOF'
content = open('docker-compose.yml').read()
content = content.replace(
    'wazuh.manager:\n    image:',
    'wazuh.manager:\n    networks:\n      cyntia-wazuh:\n        ipv4_address: 172.21.0.4\n    image:'
)
content = content.replace(
    'wazuh.indexer:\n    image:',
    'wazuh.indexer:\n    networks:\n      cyntia-wazuh:\n        ipv4_address: 172.21.0.2\n    image:'
)
content = content.replace(
    'wazuh.dashboard:\n    image:',
    'wazuh.dashboard:\n    networks:\n      cyntia-wazuh:\n        ipv4_address: 172.21.0.3\n    image:'
)
open('docker-compose.yml', 'w').write(content)
print("OK")
EOF

# Añadir definición de red al final
cat >> docker-compose.yml << 'EOF'

networks:
  cyntia-wazuh:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
EOF

# Aplicar
docker compose down && docker compose up -d
```

### IPs asignadas permanentemente

| Contenedor | IP fija |
| --- | --- |
| wazuh.indexer | 172.21.0.2 |
| wazuh.dashboard | 172.21.0.3 |
| wazuh.manager | 172.21.0.4 |

### Actualizar todos los relays

```bash
# Relay agente (1514)
pct exec 101 -- bash -c "sed -i 's|TCP:172.18.0.4:1514|TCP:172.21.0.4:1514|'\
  /etc/systemd/system/wazuh-docker-relay.service"

# Relay enrollment (1515)
pct exec 101 -- bash -c "sed -i 's|TCP:172.18.0.2:1515|TCP:172.21.0.4:1515|'\
  /etc/systemd/system/wazuh-docker-relay-enroll.service"

# Relay dashboard (443)
pct exec 101 -- bash -c "sed -i 's|TCP:.*:443|TCP:172.21.0.3:443|'\
  /etc/systemd/system/wazuh-dashboard-relay.service"

pct exec 101 -- bash -c "systemctl daemon-reload &&\
  systemctl restart wazuh-docker-relay wazuh-docker-relay-enroll wazuh-dashboard-relay"
```

---

## Parte 4 · Acceso al dashboard desde el navegador

### Relay del dashboard (socat dentro del LXC)

```bash
pct exec 101 -- bash -c "cat > /etc/systemd/system/wazuh-dashboard-relay.service << 'EOF'
[Unit]
Description=Wazuh Dashboard relay
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:10443,fork TCP:172.21.0.3:443
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable wazuh-dashboard-relay && systemctl start wazuh-dashboard-relay"
```

### Regla DNAT en nftables

En `/etc/nftables.conf`:

```
iifname "tailscale0" tcp dport 443 dnat to 192.168.20.3:443
```

Aplicar:

```bash
systemctl restart nftables
```

### URLs de acceso

| Servicio | URL | Usuario |
| --- | --- | --- |
| Wazuh | https://100.92.243.96 | cyntia |
| Grafana | http://100.92.243.96:3000 | cyntia |

> En Chrome: si aparece advertencia de certificado, escribir `thisisunsafe` directamente en la página.
> 

---

## Parte 5 · Corrección del arranque tras reboot

### Problema: pve-cluster falla — faltaba ‘cyntia’ en /etc/hosts

```bash
# Añadir la entrada
sed -i 's/192.168.3.100 proxmox.cyntia.local proxmox/192.168.3.100 cyntia proxmox.cyntia.local proxmox/' /etc/hosts

# Reiniciar
systemctl restart pve-cluster
systemctl status pve-cluster --no-pager | head -5
```

### Script de arranque ordenado

```bash
cat > /usr/local/bin/cyntia-start.sh << 'EOF'
#!/bin/bash
export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin
systemctl start pve-cluster
sleep 5
pct start 100 && sleep 10   # PiHole primero (DNS)
pct start 101 && sleep 30   # SOC core (el más pesado)
pct start 102 && sleep 5
pct start 103 && sleep 5
pct start 104 && sleep 5
# Wazuh en orden: indexer → manager → dashboard
pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.indexer"
sleep 90
pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.manager"
sleep 30
pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.dashboard"
sleep 120
pct exec 101 -- bash -c "cd /opt/cyntia-monitoring && docker compose up -d"
EOF
chmod +x /usr/local/bin/cyntia-start.sh
```

### Servicio systemd para arranque automático

```bash
cat > /etc/systemd/system/cyntia-start.service << 'EOF'
[Unit]
Description=Cyntia startup script
After=network.target tailscaled.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cyntia-start.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cyntia-start.service
```

---

## Parte 6 · Optimización de recursos

Con 8GB de RAM y todo el stack corriendo, la gestión de memoria es crítica.

### Heap de OpenSearch (indexer) — causa principal de lentitud

```yaml
# En docker-compose.yml, servicio wazuh.indexer:
environment:
-"OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

### Límites de memoria por contenedor

```bash
# Wazuh manager
pct exec 101 -- bash -c "docker update --memory=1g --memory-swap=1g single-node-wazuh.manager-1"

# Grafana
pct exec 101 -- bash -c "docker update --memory=256m --memory-swap=256m grafana"
```

### Reducir uso de swap

```bash
echo "vm.swappiness=10" >> /etc/sysctl.conf
sysctl -p
```

### Limitar CPU de Suricata

```bash
pct exec 101 -- bash -c "systemctl set-property suricata CPUQuota=25% && systemctl restart suricata"
```

### Rotación de alerts.json

```bash
# Rotar manualmente cuando supere los 3M de líneas
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1\
  truncate -s 0 /var/ossec/logs/alerts/alerts.json"

# Configurar logrotate automático
cat > /etc/logrotate.d/wazuh-alerts << 'EOF'
/var/ossec/logs/alerts/alerts.json {
    daily
    rotate 7
    size 50M
    compress
    missingok
    notifempty
}
EOF
```

---

## Parte 7 · Script de diagnóstico cyntia-check

```bash
# Instalar
mv cyntia-check.sh /usr/local/bin/cyntia-check
chmod +x /usr/local/bin/cyntia-check

# Ejecutar
cyntia-check
```

**Secciones del script:**

| Sección | Qué comprueba |
| --- | --- |
| 1. Sistema host | RAM, CPU, disco, swap |
| 2. Cluster | pve-cluster, quorum |
| 3. Contenedores | Estado de cada LXC y VM |
| 4. Servicios host | nftables, fail2ban, tailscale, relays, NFS |
| 5. Docker | Estado y memoria de cada contenedor |
| 6. Agentes Wazuh | Activos/desconectados, tamaño alerts.json |
| 7. OpenCanary | Estado del honeypot |
| 8. Backups | vzdump, BorgBackup, cron |
| 9. Red | VLANs, ping entre contenedores, nftables |
| 10. Recomendaciones | Acciones automáticas según el estado |

---

## Estado final tras optimizaciones

| Métrica | Antes | Después |
| --- | --- | --- |
| RAM usada | 4.4GB (56%) | 2.5GB (31%) |
| Swap en uso | 2.9GB | 288MB |
| Carga CPU media | 7.5 | 0.7 |
| Indexer CPU | 172% | 0.3% |
| alerts.json | 1.27M líneas | rotado |
| Agentes activos | 1/2 | 2/2 |
| Dashboard accesible | No | Sí |
