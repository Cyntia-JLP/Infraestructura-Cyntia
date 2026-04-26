#!/usr/bin/env python3
import sys, json, datetime, urllib.request, urllib.parse

BOT_TOKEN = "-"
CHAT_ID   = "-"

ICONOS = {
    "100201":"🚨","100202":"🚨","100203":"🔴",
    "100204":"⚠️","100205":"⚠️","100206":"🍯","100200":"🍯",
    "5710":"🔨","5712":"🔨","5763":"🔨","2502":"🔨",
    "5901":"👤","5902":"👤",
}

DESCRIPCIONES = {
    "100200":"Actividad detectada en honeypot",
    "100201":"Conexion SSH al honeypot",
    "100202":"Intento de login SSH con credenciales en honeypot",
    "100203":"LOGIN SSH COMPLETADO - INTRUSION CRITICA",
    "100204":"Peticion HTTP al honeypot",
    "100205":"Conexion MySQL al honeypot",
    "100206":"Actividad generica en honeypot",
    "5710":"Multiples intentos SSH fallidos (brute force)",
    "5712":"Ataque SSH por fuerza bruta detectado",
    "5763":"Posible ataque SSH detectado",
    "2502":"Multiples autenticaciones fallidas",
    "5901":"Nuevo usuario creado en el sistema",
    "5902":"Nuevo grupo creado en el sistema",
}

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("/var/ossec/logs/active-responses.log", "a") as f:
        f.write("[" + ts + "] [notify_telegram] " + msg + "\n")

def send_telegram(message):
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
        log("Mensaje enviado OK")
    except Exception as e:
        log("ERROR enviando: " + str(e))

def main():
    try:
        raw = json.loads(sys.stdin.read())
    except Exception as e:
        log("ERROR parseando JSON: " + str(e))
        sys.exit(1)

    # Wazuh puede enviar el alert directo o envuelto en parameters.alert
    if "parameters" in raw and "alert" in raw.get("parameters", {}):
        alert = raw["parameters"]["alert"]
    else:
        alert = raw

    rule_id   = str(alert.get("rule", {}).get("id", ""))
    level     = str(alert.get("rule", {}).get("level", 0))
    desc      = alert.get("rule", {}).get("description", "Alerta")
    agente    = alert.get("agent", {}).get("name", "desconocido")
    timestamp = str(alert.get("timestamp", ""))[:19].replace("T", " ")
    data      = alert.get("data", {})

    src_ip   = data.get("src_host") or data.get("srcip") or data.get("src_ip") or "desconocida"
    dst_host = str(data.get("dst_host", ""))
    dst_port = str(data.get("dst_port", ""))

    icono       = ICONOS.get(rule_id, "⚠️")
    descripcion = DESCRIPCIONES.get(rule_id, desc)

    lineas = [
        icono + " *ALERTA CYNTIA SOC*",
        "━━━━━━━━━━━━━━━━━━━━",
        "📋 *Descripcion:* " + descripcion,
        "🎯 *Nivel:* " + level + "/15",
        "🖥️ *Agente:* " + agente,
        "🕐 *Hora:* " + timestamp,
    ]

    if src_ip and src_ip != "desconocida":
        lineas.append("📍 *IP origen:* `" + src_ip + "`")

    if dst_host and dst_port:
        lineas.append("🎯 *Destino:* " + dst_host + ":" + dst_port)
    elif dst_port:
        lineas.append("🎯 *Puerto:* " + dst_port)

    lineas.append("🔑 *Regla:* #" + rule_id)

    if rule_id == "100203":
        lineas.append("\n🔴 *ACCION REQUERIDA: Revisar honeypot inmediatamente*")

    log("Procesando regla=" + rule_id + " agente=" + agente + " src=" + src_ip)
    send_telegram("\n".join(lineas))

if __name__ == "__main__":
    main()