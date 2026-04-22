#!/bin/bash
# =============================================================================
# cyntia-start.sh — Arranque ordenado de la plataforma · Proyecto Cyntia
# =============================================================================
# Propósito:
#   Garantiza que todos los componentes de la plataforma SOC/SIEM arrancan
#   en el orden correcto tras un reinicio del host Proxmox.
#
#   El problema que resuelve: si todos los LXC y servicios Docker arrancan
#   a la vez, OpenSearch (Wazuh indexer) no estará listo cuando el manager
#   intente conectarse, y el manager no estará listo cuando el dashboard
#   intente conectarse. Los sleeps garantizan ese orden.
#
#   En la práctica, los LXC arrancan solos gracias a "onboot: 1" en su
#   configuración de Proxmox, y Docker tiene "restart: always" en todos los
#   contenedores. Este script actúa como red de seguridad en caso de que
#   algún componente no haya arrancado correctamente.
#
# Ubicación:  /usr/local/bin/cyntia-start.sh (en el host Proxmox)
# Servicio:   cyntia-start.service (oneshot, habilitado en systemd)
# Ejecución:  Automática al arrancar el host, después de network y tailscale
# =============================================================================

export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin

# --- Asegurar que el cluster PVE está activo ---------------------------------
# pve-cluster gestiona la configuración compartida entre cyntia y cyntia-backup.
# Si no está activo, los comandos pct fallarán.
systemctl start pve-cluster
sleep 5

# --- Arranque de contenedores LXC en orden -----------------------------------
# El orden importa: PiHole (DNS) primero para que el resto pueda resolver nombres.
# lxc-soc-core necesita más tiempo porque Docker debe arrancar OpenSearch
# antes de que Wazuh manager intente conectarse.

pct start 100   # lxc-pihole     — DNS interno (cyntia.local). Debe ser el primero.
sleep 10

pct start 101   # lxc-soc-core   — Stack SOC principal (Wazuh + Suricata + Grafana)
sleep 30        # 30s para que Docker y los bridges de red estén listos

pct start 102   # lxc-web-cyntia — Portal web PHP/MySQL (DMZ)
sleep 5

pct start 103   # lxc-honeypot   — OpenCanary honeypot
sleep 5

pct start 104   # lxc-backup     — BorgBackup
sleep 5

pct start 201   # lxc-ldap       — OpenLDAP + LAM (cliente MedTrans Ibérica)
sleep 5

# --- Arranque ordenado del stack Wazuh en Docker -----------------------------
# Los tres componentes deben arrancarse por separado y en orden:
#   1. wazuh.indexer  — OpenSearch, base de datos de alertas. Es el más lento.
#   2. wazuh.manager  — Recibe logs de agentes y aplica reglas. Necesita indexer listo.
#   3. wazuh.dashboard — Interfaz web. Necesita manager e indexer listos.
#
# Si se lanzaran todos a la vez con "docker compose up -d", el manager
# intentaría conectar a OpenSearch antes de que estuviera listo y fallaría.

pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.indexer"
sleep 90        # OpenSearch necesita ~90s para inicializar índices y estar listo

pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.manager"
sleep 30        # El manager necesita ~30s para cargar reglas y conectar al indexer

pct exec 101 -- bash -c "cd /opt/wazuh-docker/single-node && docker compose up -d wazuh.dashboard"
sleep 120       # El dashboard necesita ~2min para cargar plugins y conectar

# --- Arranque del stack de monitorización ------------------------------------
# Grafana + Prometheus + Node Exporter. Se arrancan juntos porque no tienen
# dependencias de orden entre sí.

pct exec 101 -- bash -c "cd /opt/cyntia-monitoring && docker compose up -d"
