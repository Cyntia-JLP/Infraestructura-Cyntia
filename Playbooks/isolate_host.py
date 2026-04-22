#!/usr/bin/env python3
"""
=========================================================
PLAYBOOK: isolate_host.py
PROYECTO: Cyntia SOC - Plataforma SIEM para PYMEs
=========================================================
FUNCIÓN:
    Aísla un dispositivo comprometido de la red bloqueando
    su IP en el firewall nftables del host Proxmox.
    A diferencia de block_ip.py (que bloquea IPs externas),
    este playbook actúa sobre equipos INTERNOS de la red del cliente.

DIFERENCIA CON disable_ldap_user.py:
    - disable_ldap_user → actúa sobre la IDENTIDAD del usuario
    - isolate_host      → actúa sobre el DISPOSITIVO en la red
    En un ataque real se usan AMBOS: se deshabilita al usuario Y
    se aísla su equipo para contener el incidente completamente.

ACTIVACIÓN:
    Wazuh lo ejecuta con las reglas: 100201, 100202, 100203
    Actúa sobre la IP del agente que generó la alerta.

MODO MANUAL (liberación):
    python3 isolate_host.py --release <IP>
    Solo el equipo SOC puede liberar un host aislado.

IPs PROTEGIDAS (nunca se aíslan):
    - 192.168.20.x → VLAN SOC (lxc-soc-core, lxc-honeypot, etc.)
    - 192.168.3.1  → Gateway del taller
    - 127.x        → Loopback

UBICACIÓN:
    - Script principal: /opt/cyntia-playbooks/isolate_host.py
    - Copia en Wazuh:   /var/ossec/active-response/bin/isolate_host.py
    - Log de salida:    /var/ossec/logs/active-responses.log
    - Log del host:     /var/log/cyntia-blocks.log
=========================================================
"""

import sys
import json
import datetime
import subprocess


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

# Fichero de log compartido con todos los playbooks
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Relay nftables en el host Proxmox.
# Escucha comandos y los ejecuta con privilegios de root.
RELAY_HOST = "192.168.20.1"
RELAY_PORT = 7777

# IPs que NUNCA deben aislarse para no romper el propio SOC.
# Si se aislara una IP de VLAN20, el propio Wazuh podría quedar incomunicado.
PROTECTED_IPS = [
    "192.168.20.",   # VLAN SOC - todos los contenedores de seguridad
    "192.168.3.1",   # Gateway del taller
    "127.",          # Loopback
]


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def log(msg):
    """
    Escribe un mensaje en el fichero de log con timestamp.
    Prefija con [isolate_host] para distinguirlo de otros playbooks.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [isolate_host] {msg}\n")


def is_protected(ip):
    """
    Verifica si una IP está en la lista de protegidas.
    Nunca aislamos equipos del propio SOC.
    """
    return any(ip.startswith(p) for p in PROTECTED_IPS)


def send_nft_command(cmd):
    """
    Envía un comando nftables al relay del host via socat.

    El relay (nftables-relay.service) escucha en 192.168.20.1:7777
    y solo acepta dos tipos de comandos:
      - "nft add element inet filter blocked_ips { IP }" → bloquear
      - "nft delete element inet filter blocked_ips { IP }" → liberar

    Retorna True si el comando se envió correctamente.
    """
    try:
        result = subprocess.run(
            ["socat", "-", f"TCP:{RELAY_HOST}:{RELAY_PORT}"],
            input=cmd.encode(),
            capture_output=True,
            timeout=5
        )
        return True
    except subprocess.TimeoutExpired:
        log(f"ERROR: timeout enviando comando al relay nftables")
        return False
    except Exception as e:
        log(f"ERROR enviando comando nft: {e}")
        return False


# ─────────────────────────────────────────────
# OPERACIONES PRINCIPALES
# ─────────────────────────────────────────────

def isolate_host(ip):
    """
    Aísla un host añadiendo su IP al set blocked_ips de nftables.

    El set blocked_ips tiene timeout de 24h — si el equipo SOC
    olvida liberar el host, se liberará automáticamente al día siguiente.

    El aislamiento bloquea TODO el tráfico del host:
    - No puede conectarse a ningún servicio de la red
    - No puede enviar datos al exterior
    - El equipo queda en cuarentena hasta que se libere manualmente
    """
    # Construir el comando para añadir la IP al set del firewall
    cmd = f"nft add element inet filter blocked_ips {{ {ip} timeout 24h }}"

    ok = send_nft_command(cmd)
    if ok:
        log(f"Host aislado: {ip}")
        log(f"Para desaislar: python3 isolate_host.py --release {ip}")
        return True
    else:
        log(f"ERROR: no se pudo aislar el host {ip}")
        return False


def release_host(ip):
    """
    Libera un host previamente aislado eliminando su IP del set.

    SOLO debe ejecutarse cuando:
    1. El incidente ha sido investigado y resuelto
    2. El equipo (formateado o limpio) puede volver a la red
    3. Se ha verificado que no hay más amenazas activas

    Esta acción es manual e irreversible en el momento — el host
    vuelve a tener acceso completo a la red inmediatamente.
    """
    # Construir el comando para eliminar la IP del set
    cmd = f"nft delete element inet filter blocked_ips {{ {ip} }}"

    ok = send_nft_command(cmd)
    if ok:
        log(f"Host liberado: {ip}")
        return True
    else:
        log(f"ERROR: no se pudo liberar el host {ip}")
        return False


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────

def main():
    """
    Punto de entrada del playbook.

    MODO AUTOMÁTICO (Wazuh):
        Lee el JSON de la alerta por stdin.
        Extrae la IP del agente comprometido y la aísla.

    MODO MANUAL (equipo SOC):
        python3 isolate_host.py --release <IP>
        Libera un host previamente aislado.
    """
    # ── Modo liberación manual ───────────────────────────────────
    if len(sys.argv) == 3 and sys.argv[1] == "--release":
        ip = sys.argv[2]
        log(f"Liberación manual solicitada para: {ip}")
        release_host(ip)
        return

    # ── Modo automático desde Wazuh ──────────────────────────────
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        # La IP del host comprometido puede venir de dos sitios:
        # - agent.ip: IP del agente Wazuh que reportó la alerta
        # - data.srcip: IP origen del ataque detectado
        ip = (alert.get("agent", {}).get("ip") or
              alert.get("data", {}).get("srcip"))

        # Si el agente se registró con IP "any", no podemos aislar
        if not ip or ip == "any":
            log("No se encontró IP válida en la alerta (ip='any' no es aislable)")
            sys.exit(1)

        # Proteger IPs del propio SOC
        if is_protected(ip):
            log(f"IP protegida, no se aísla: {ip}")
            sys.exit(0)

        log(f"Alerta recibida - Aislando host: {ip}")
        isolate_host(ip)

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()
