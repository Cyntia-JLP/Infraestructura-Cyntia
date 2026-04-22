#!/usr/bin/env python3
"""
=========================================================
PLAYBOOK: block_ip.py
PROYECTO: Cyntia SOC - Plataforma SIEM para PYMEs
=========================================================
FUNCIÓN:
    Bloquea automáticamente una IP maliciosa en el firewall
    del host Proxmox añadiéndola al set 'blocked_ips' de nftables.
    La IP queda bloqueada durante 24 horas y luego se desbloquea sola.

ACTIVACIÓN:
    Wazuh lo ejecuta automáticamente cuando se disparan las
    reglas de OpenCanary: 100201 (SSH), 100203 (MySQL), 100204 (HTTP)

FLUJO:
    Wazuh detecta alerta → lee IP del JSON → envía comando
    via socat al relay del host → el relay ejecuta nft add element

UBICACIÓN:
    - Script principal: /opt/cyntia-playbooks/block_ip.py (lxc-soc-core)
    - Copia en Wazuh:   /var/ossec/active-response/bin/block_ip.py
    - Log de salida:    /var/ossec/logs/active-responses.log
    - Log del host:     /var/log/cyntia-blocks.log
=========================================================
"""

import sys
import json
import subprocess
import datetime
import os


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

# Fichero donde se registran todas las acciones del playbook.
# Wazuh lo monitoriza automáticamente al estar en logs/
LOG_FILE = "/var/ossec/logs/active-responses.log"

# IP y puerto donde escucha el relay nftables en el host Proxmox.
# El relay recibe comandos nft y los ejecuta con privilegios de root.
RELAY_HOST = "192.168.20.1"
RELAY_PORT = 7777

# IPs de red privada que NUNCA deben bloquearse para evitar
# romper la comunicación interna del proyecto
PRIVATE_RANGES = ["192.168.", "10.", "172.", "127."]


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def log(msg):
    """
    Escribe un mensaje en el fichero de log con timestamp.
    Todos los playbooks usan el mismo formato para que sea
    fácil correlacionar eventos en Wazuh.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [block_ip] {msg}\n")


def is_private_ip(ip):
    """
    Comprueba si una IP pertenece a un rango privado.
    Nunca bloqueamos IPs privadas porque son equipos internos
    del proyecto (contenedores, VMs, etc.)
    """
    return any(ip.startswith(rango) for rango in PRIVATE_RANGES)


def block_ip(ip):
    """
    Envía el comando de bloqueo al relay nftables del host.

    El flujo es:
      1. Construye el comando nft en texto plano
      2. Lo envía via socat al relay que escucha en 192.168.20.1:7777
      3. El relay valida el comando y ejecuta: nft add element inet filter blocked_ips { IP timeout 24h }
      4. La IP queda en el set y nftables la bloquea automáticamente

    Retorna True si el bloqueo fue exitoso, False si hubo error.
    """
    try:
        # Construir el comando que recibirá el relay
        cmd = f"nft add element inet filter blocked_ips {{ {ip} }}"

        # Enviar el comando al relay via socat.
        # socat actúa como cliente TCP: lee de stdin (-) y envía a la IP:puerto
        result = subprocess.run(
            ["socat", "-", f"TCP:{RELAY_HOST}:{RELAY_PORT}"],
            input=cmd.encode(),       # el comando como bytes
            capture_output=True,      # capturar stdout y stderr
            timeout=5                 # máximo 5 segundos de espera
        )

        log(f"IP bloqueada: {ip}")
        return True

    except subprocess.TimeoutExpired:
        log(f"ERROR bloqueando {ip}: timeout - ¿está el relay activo?")
        return False
    except Exception as e:
        log(f"ERROR bloqueando {ip}: {e}")
        return False


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────

def main():
    """
    Punto de entrada del playbook.

    Wazuh pasa el JSON completo de la alerta por stdin.
    El script lo lee, extrae la IP de origen y la bloquea.

    El JSON de Wazuh tiene esta estructura:
    {
        "rule": {"id": "100201", "level": 12, ...},
        "agent": {"name": "lxc-honeypot", ...},
        "data": {"srcip": "1.2.3.4", "srcuser": "root", ...}
    }
    """
    # Leer el JSON de la alerta desde stdin (lo inyecta Wazuh)
    input_data = sys.stdin.read()

    try:
        alert = json.loads(input_data)

        # Intentar extraer la IP de origen del campo data.
        # Wazuh usa distintos nombres según el tipo de log,
        # por eso probamos varios campos en orden de prioridad.
        ip = (alert.get("data", {}).get("srcip") or
              alert.get("data", {}).get("src_ip") or
              alert.get("data", {}).get("src_host"))

        # Si no hay IP no podemos hacer nada
        if not ip:
            log("No se encontró IP en la alerta - campos srcip/src_ip/src_host vacíos")
            sys.exit(1)

        # Proteger IPs privadas (equipos internos del proyecto)
        if is_private_ip(ip):
            log(f"IP privada ignorada (no se bloquea): {ip}")
            sys.exit(0)

        # Todo correcto: proceder con el bloqueo
        log(f"Alerta recibida - Bloqueando IP: {ip}")
        block_ip(ip)

    except json.JSONDecodeError:
        # Esto no debería pasar si Wazuh envía el JSON correctamente
        log(f"Error parseando JSON de Wazuh: {input_data[:100]}")
        sys.exit(1)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()
