#!/bin/bash
# =============================================================================
# nftables-relay.sh — Relay de comandos nftables · Proyecto Cyntia
# =============================================================================
# Propósito:
#   Permite que los playbooks de respuesta automática de Wazuh (que corren
#   dentro del contenedor Docker en lxc-soc-core, VLAN20) puedan modificar
#   las reglas de nftables del host Proxmox sin tener acceso SSH directo a él.
#
#   El problema que resuelve:
#   Los playbooks (block_ip.py, isolate_host.py) necesitan bloquear IPs en
#   el firewall del host. Sin embargo, el contenedor Docker no puede ejecutar
#   comandos nft en el host por razones de seguridad y aislamiento.
#
#   La solución — cadena de relay:
#   [Docker Wazuh] → socat → [lxc-soc-core:7777] → socat → [host:7777]
#                                                              ↓
#                                                    nftables-relay.sh
#                                                              ↓
#                                                    nft (ejecutado en host)
#
#   El relay escucha en 192.168.20.1:7777 (IP del host en VLAN20) y acepta
#   únicamente dos comandos permitidos:
#   - "nft add element inet filter blocked_ips { IP }" → bloquea una IP 24h
#   - "nft delete element inet filter blocked_ips { IP }" → libera una IP
#
#   Cualquier otro comando es ignorado, lo que limita la superficie de ataque.
#
# Ubicación:  /usr/local/bin/nftables-relay.sh (en el host Proxmox)
# Servicio:   nftables-relay.service (systemd, activo permanentemente)
# Escucha:    192.168.20.1:7777 (solo accesible desde VLAN20)
# Log:        /var/log/cyntia-blocks.log
# =============================================================================

while true; do
    # Esperar una conexión TCP en el puerto 7777 de la interfaz VLAN20.
    # -T5: timeout de 5 segundos sin datos para evitar conexiones colgadas.
    # reuseaddr: permite reutilizar el puerto inmediatamente tras cerrar.
    # Lee el comando enviado y lo guarda en CMD.
    CMD=$(socat -T5 TCP-LISTEN:7777,bind=192.168.20.1,reuseaddr -)

    # --- Comando: bloquear IP ------------------------------------------------
    # Si el comando es "nft add element inet filter blocked_ips { IP }",
    # extrae la IP con grep y la añade al set blocked_ips de nftables.
    # El set tiene timeout 24h configurado — la IP se desbloquea sola
    # tras 24 horas sin necesidad de intervención manual.
    # Solo se procesan IPs en formato IPv4 válido (regex \d+\.\d+\.\d+\.\d+).

    if echo "$CMD" | grep -q "^nft add element inet filter blocked_ips"; then
        IP=$(echo "$CMD" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [ -n "$IP" ]; then
            nft add element inet filter blocked_ips { $IP timeout 24h }
            echo "[$(date)] IP bloqueada: $IP" >> /var/log/cyntia-blocks.log
        fi

    # --- Comando: liberar IP --------------------------------------------------
    # Si el comando es "nft delete element inet filter blocked_ips { IP }",
    # extrae la IP y la elimina del set manualmente antes del timeout.
    # Usado por isolate_host.py con el flag --release, o para desbloqueos
    # manuales durante pruebas o falsos positivos.

    elif echo "$CMD" | grep -q "^nft delete element inet filter blocked_ips"; then
        IP=$(echo "$CMD" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
        if [ -n "$IP" ]; then
            nft delete element inet filter blocked_ips { $IP }
            echo "[$(date)] IP liberada: $IP" >> /var/log/cyntia-blocks.log
        fi

    # --- Cualquier otro comando: ignorado ------------------------------------
    # No se ejecuta nada más. Esto evita que un atacante que comprometiera
    # el contenedor Docker pudiera ejecutar comandos arbitrarios en el host.

    fi
done
