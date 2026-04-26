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

#!/usr/bin/env python3

import sys
import json
import subprocess
import datetime
import os

LOG_FILE = "/var/ossec/logs/active-responses.log"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [block_ip] {msg}\n")


def notify_telegram(ip):
    try:
        import urllib.request, urllib.parse, datetime
        url = "https://api.telegram.org/bot8732029794:AAHdwZrG5VY89P4aV5bH3Au5iUmpqhv9IsE/sendMessage"
        msg = (
            "🔒 *IP BLOQUEADA — Cyntia SOC*\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📍 *IP:* `" + ip + "`\n"
            "⏱️ *Duracion:* 24 horas\n"
            "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
                        "🔑 *Accion:* Bloqueada en nftables"
        )
        data = urllib.parse.urlencode({"chat_id": "-1003716097465", "text": msg, "parse_mode": "Markdown"}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
    except Exception as e:
        log("ERROR Telegram: " + str(e))


def block_ip(ip):
    try:
        # Añadir IP a nftables via socat al host
        cmd = f"nft add element inet filter blocked_ips {{ {ip} }}"
        result = subprocess.run(
            ["socat", "-", "TCP:192.168.20.1:7777"],
            input=cmd.encode(),
            capture_output=True,
            timeout=5
        )
        log(f"IP bloqueada: {ip}")
        notify_telegram(ip)
        return True
    except Exception as e:
        log(f"ERROR bloqueando {ip}: {e}")
        return False

def main():
    # Wazuh pasa el JSON del evento por stdin
    input_data = sys.stdin.read()
    
    try:
        alert = json.loads(input_data)
        if "parameters" in alert and "alert" in alert.get("parameters", {}):
            alert = alert["parameters"]["alert"]
        ip = alert.get("data", {}).get("srcip") or \
             alert.get("data", {}).get("src_ip") or \
             alert.get("data", {}).get("src_host")
        
        if not ip:
            log("No se encontró IP en la alerta")
            sys.exit(1)
        
        # No bloquear IPs privadas
        private = ["192.168.", "10.", "172.", "127."]
        if any(ip.startswith(p) for p in private):
            log(f"IP privada ignorada: {ip}")
            sys.exit(0)
        
        log(f"Alerta recibida - Bloqueando IP: {ip}")
        block_ip(ip)
        
    except json.JSONDecodeError:
        log(f"Error parseando JSON: {input_data[:100]}")
        sys.exit(1)

if __name__ == "__main__":
    main()
