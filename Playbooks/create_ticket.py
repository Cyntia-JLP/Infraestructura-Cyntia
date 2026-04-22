#!/usr/bin/env python3
"""
=========================================================
PLAYBOOK: create_ticket.py
PROYECTO: Cyntia SOC - Plataforma SIEM para PYMEs
=========================================================
FUNCIÓN:
    Genera un ticket de incidencia formal cada vez que Wazuh
    detecta una alerta de los grupos OpenCanary o honeypot.
    El ticket se guarda en formato JSON localmente y se envía
    una notificación al grupo de Telegram del equipo SOC.

    Es el playbook de NOTIFICACIÓN — se ejecuta en TODAS las
    alertas de nivel alto para que el equipo esté siempre informado,
    independientemente de si otros playbooks actúan o no.

ACTIVACIÓN:
    Wazuh lo ejecuta con TODAS las reglas de OpenCanary: 100200-100206
    Es el playbook con mayor cobertura de reglas del proyecto.

SALIDAS:
    1. Fichero JSON en /opt/cyntia-playbooks/tickets/TKT-YYYYMMDD-HHMMSS.json
    2. Mensaje en el grupo de Telegram del equipo SOC

INTEGRACIÓN FUTURA:
    Los tickets JSON pueden ser leídos por el portal web PHP/MySQL
    para mostrarlos en el panel del cliente. También pueden insertarse
    directamente en la base de datos MySQL via webhook.

TELEGRAM:
    Bot: @cyntia_soc_bot
    Grupo: Cyntia SOC Alertas (Paula + Jeet + Laura)
    Chat ID: -1003716097465

UBICACIÓN:
    - Script principal: /opt/cyntia-playbooks/create_ticket.py
    - Copia en Wazuh:   /var/ossec/active-response/bin/create_ticket.py
    - Tickets:          /opt/cyntia-playbooks/tickets/
    - Log de salida:    /var/ossec/logs/active-responses.log
=========================================================
"""

import sys
import json
import datetime
import subprocess
import urllib.request
import urllib.parse
import os


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

# Fichero de log compartido con todos los playbooks
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Directorio donde se guardan los tickets en formato JSON.
# En el futuro el portal web puede leer estos ficheros
# o se pueden insertar directamente en MySQL.
TICKETS_DIR = "/opt/cyntia-playbooks/tickets"

# Credenciales del bot de Telegram.
# El token identifica al bot, el Chat ID identifica al grupo.
# IMPORTANTE: en producción mover a variables de entorno (.env)
TELEGRAM_BOT_TOKEN = "8732029794:AAHdwZrG5VY89P4aV5bH3Au5iUmpqhv9IsE"
TELEGRAM_CHAT_ID   = "-1003716097465"


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def log(msg):
    """
    Escribe un mensaje en el fichero de log con timestamp.
    Prefija con [create_ticket] para distinguirlo de otros playbooks.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [create_ticket] {msg}\n")


def send_telegram(message):
    """
    Envía un mensaje al grupo de Telegram del equipo SOC.

    Usa la API HTTP de Telegram que no requiere librerías externas,
    solo urllib que viene incluido en Python por defecto.

    El mensaje se envía en formato HTML para poder usar negritas
    y otros estilos que mejoran la legibilidad en móvil.

    Retorna True si el mensaje se envió correctamente, False si hubo error.
    """
    try:
        # Endpoint de la API de Telegram para enviar mensajes
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

        # Parámetros del mensaje codificados como form data
        data = urllib.parse.urlencode({
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       message,
            "parse_mode": "HTML"   # permite usar <b>, <i>, etc. en el mensaje
        }).encode()

        # Hacer la petición HTTP POST a la API de Telegram
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)

        log("Notificación Telegram enviada")
        return True

    except Exception as e:
        # No interrumpimos el playbook si Telegram falla —
        # el ticket se guarda igualmente en JSON
        log(f"ERROR enviando Telegram: {e}")
        return False


# ─────────────────────────────────────────────
# OPERACIÓN PRINCIPAL
# ─────────────────────────────────────────────

def create_ticket(alert):
    """
    Crea un ticket de incidencia a partir del JSON de alerta de Wazuh.

    El ticket recoge todos los datos relevantes del incidente:
    - Identificador único (TKT-YYYYMMDD-HHMMSS)
    - Regla que lo disparó y su descripción
    - Severidad (nivel Wazuh 1-15)
    - Agente afectado (nombre e IP)
    - IP y usuario de origen del ataque
    - Timestamp del incidente

    El ticket se guarda en JSON y se notifica por Telegram.

    Retorna el ID del ticket creado.
    """
    # Extraer datos de la alerta con valores por defecto seguros
    timestamp   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule_id     = alert.get("rule",  {}).get("id",          "N/A")
    rule_desc   = alert.get("rule",  {}).get("description", "Sin descripción")
    rule_level  = alert.get("rule",  {}).get("level",       "N/A")
    agent_name  = alert.get("agent", {}).get("name",        "N/A")
    agent_ip    = alert.get("agent", {}).get("ip",          "N/A")
    src_ip      = alert.get("data",  {}).get("srcip",       "N/A")
    src_user    = alert.get("data",  {}).get("srcuser",     "N/A")

    # Generar ID único basado en la fecha y hora exacta
    # Formato: TKT-20260416-181506
    ticket_id = datetime.datetime.now().strftime("TKT-%Y%m%d-%H%M%S")

    # Crear el directorio de tickets si no existe
    os.makedirs(TICKETS_DIR, exist_ok=True)

    # ── Construir el objeto ticket ───────────────────────────────
    ticket = {
        "id":          ticket_id,
        "timestamp":   timestamp,
        "status":      "abierto",     # estado inicial siempre es 'abierto'
        "rule_id":     rule_id,
        "description": rule_desc,
        "severity":    rule_level,
        "agent":       agent_name,
        "agent_ip":    agent_ip,
        "src_ip":      src_ip,
        "src_user":    src_user,
        "raw_alert":   alert          # alerta completa para análisis forense
    }

    # ── Guardar ticket como fichero JSON ─────────────────────────
    ticket_path = os.path.join(TICKETS_DIR, f"{ticket_id}.json")
    with open(ticket_path, "w") as f:
        json.dump(ticket, f, indent=2, ensure_ascii=False)

    log(f"Ticket creado: {ticket_id} | Regla: {rule_id} | Agente: {agent_name} | IP: {src_ip}")

    # ── Enviar notificación a Telegram ───────────────────────────
    # El mensaje usa HTML para dar formato visual en la app de Telegram.
    # Los emojis ayudan a identificar rápidamente el tipo de información
    # cuando llega la notificación en el móvil.
    mensaje = f"""🚨 <b>NUEVA INCIDENCIA - Cyntia SOC</b>

🎫 <b>Ticket:</b> {ticket_id}
⚠️ <b>Severidad:</b> {rule_level}
📋 <b>Descripción:</b> {rule_desc}
🖥️ <b>Agente:</b> {agent_name} ({agent_ip})
🌐 <b>IP origen:</b> {src_ip}
👤 <b>Usuario:</b> {src_user}
🕐 <b>Hora:</b> {timestamp}

Revisa el panel de Wazuh para más detalles."""

    send_telegram(mensaje)
    return ticket_id


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────

def main():
    """
    Punto de entrada del playbook.

    Lee el JSON de la alerta de Wazuh por stdin,
    crea el ticket y envía la notificación Telegram.

    Solo tiene modo automático (activado por Wazuh).
    No tiene modo manual porque crear tickets manualmente
    se haría directamente desde el portal web.
    """
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        log("Alerta recibida - Creando ticket")
        ticket_id = create_ticket(alert)
        log(f"Ticket {ticket_id} procesado correctamente")

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()
