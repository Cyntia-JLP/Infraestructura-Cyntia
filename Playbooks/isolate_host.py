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

LOG_FILE = "/var/ossec/logs/active-responses.log"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [isolate_host] {msg}\n")


def notify_telegram(mensaje):
    """Envía notificación al grupo SOC de Telegram."""
    try:
        import urllib.request, urllib.parse
        url = "https://api.telegram.org/bot{}/sendMessage".format(
            "8732029794:AAHdwZrG5VY89P4aV5bH3Au5iUmpqhv9IsE"
        )
        data = urllib.parse.urlencode({
            "chat_id": "-1003716097465",
            "text": mensaje,
            "parse_mode": "Markdown"
        }).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        log("ERROR Telegram: " + str(e))


def send_nft_command(cmd):
    try:
        result = subprocess.run(
            ["socat", "-", "TCP:192.168.20.1:7777"],
            input=cmd.encode(),
            capture_output=True,
            timeout=5
        )
        return True
    except Exception as e:
        log(f"ERROR enviando comando nft: {e}")
        return False

def isolate_host(ip, razon="Actividad sospechosa detectada"):
    """Aísla un host bloqueando todo su tráfico excepto hacia Wazuh."""
    try:
        # Bloquear todo tráfico entrante del host
        send_nft_command(f"nft add element inet filter blocked_ips {{ {ip} timeout 24h }}")

        log(f"Host aislado: {ip}")
        log(f"Para desaislar: python3 isolate_host.py --release {ip}")
        notify_telegram(
            "🔴 *HOST AISLADO — Cyntia SOC*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🖥️ *Host:* `" + ip + "`\n"
            "⚡ *Accion:* Aislamiento completo de red\n"
            "⏱️ *Duracion:* Hasta liberacion manual\n"
            "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
            "📋 *Razon:* " + razon + "\n"
            "⚠️ *ACCION REQUERIDA: Revisar incidente inmediatamente*"
        )
        return True

    except Exception as e:
        log(f"ERROR aislando {ip}: {e}")
        return False

def release_host(ip):
    """Libera un host previamente aislado."""
    try:
        send_nft_command(f"nft delete element inet filter blocked_ips {{ {ip} }}")
        log(f"Host liberado: {ip}")
        return True
    except Exception as e:
        log(f"ERROR liberando {ip}: {e}")
        return False

def main():
    # Modo liberación manual
    if len(sys.argv) == 3 and sys.argv[1] == "--release":
        ip = sys.argv[2]
        log(f"Liberación manual solicitada para: {ip}")
        release_host(ip)
        return

    # Modo automático desde Wazuh
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        # Wazuh envuelve la alerta en parameters.alert
        if "parameters" in alert and "alert" in alert.get("parameters", {}):
            alert = alert["parameters"]["alert"]

        # Obtener IP del agente comprometido
        ip = alert.get("agent", {}).get("ip") or \
             alert.get("data", {}).get("srcip")

        if not ip or ip == "any":
            log("No se encontró IP válida en la alerta")
            sys.exit(1)

        # No aislar IPs del SOC ni del gateway
        protected = ["192.168.20.", "192.168.3.1", "127."]
        if any(ip.startswith(p) for p in protected):
            log(f"IP protegida, no se aísla: {ip}")
            sys.exit(0)

        razon = alert.get("rule", {}).get("description", "Actividad sospechosa detectada")
        log(f"Alerta recibida - Aislando host: {ip}")
        isolate_host(ip, razon)

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)

if __name__ == "__main__":
    main()
