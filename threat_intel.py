#!/usr/bin/env python3
"""
=========================================================
PLAYBOOK: threat_intel.py
PROYECTO: Cyntia SOC - Plataforma SIEM para PYMEs
=========================================================
FUNCIÓN:
    Enriquece una alerta consultando dos fuentes externas de
    Threat Intelligence para determinar si la IP de origen es
    conocida como maliciosa a nivel global.

    Si cualquiera de las dos fuentes confirma la amenaza,
    activa block_ip.py automáticamente para bloquear la IP.

FUENTES DE THREAT INTELLIGENCE:
    1. AbuseIPDB  → base de datos colaborativa de IPs maliciosas
                    Score 0-100% | Umbral: >= 50% = maliciosa
    2. AlienVault OTX → plataforma de indicadores de compromiso (IoCs)
                        Pulsos > 0 = IP en campañas conocidas

LÓGICA DE VEREDICTO:
    - AbuseIPDB score >= 50% → MALICIOSA
    - OTX pulses > 0         → MALICIOSA
    - Ninguna confirma       → LIMPIA (no se toma acción)
    Usar dos fuentes reduce los falsos positivos.

ACTIVACIÓN:
    Wazuh lo ejecuta con TODAS las reglas de OpenCanary: 100200-100206
    Se ejecuta ANTES de decidir si bloquear — añade contexto inteligente.

SALIDAS:
    - Log en /var/ossec/logs/active-responses.log
    - Informe JSON en /opt/cyntia-playbooks/threat_reports/
    - Si maliciosa: activa block_ip.py automáticamente

UBICACIÓN:
    - Script principal: /opt/cyntia-playbooks/threat_intel.py
    - Copia en Wazuh:   /var/ossec/active-response/bin/threat_intel.py
    - Informes:         /opt/cyntia-playbooks/threat_reports/
    - Log de salida:    /var/ossec/logs/active-responses.log
=========================================================
"""

import sys
import json
import datetime
import urllib.request
import urllib.parse
import subprocess
import os


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────

# Fichero de log compartido con todos los playbooks
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Directorio donde se guardan los informes de análisis de IPs
REPORTS_DIR = "/opt/cyntia-playbooks/threat_reports"

# API Key de AbuseIPDB — cuenta gratuita, 1000 consultas/día
# https://www.abuseipdb.com → Account → API
ABUSEIPDB_KEY = "de01301e6c25260c2835cc8c4998210f0e2543912d270711a3a92010f9e2b390d9c738bc171a27a5"

# API Key de AlienVault OTX — cuenta gratuita, sin límite de consultas
# https://otx.alienvault.com → Settings → API Key
OTX_KEY = "6c6a0ea44d3e79dbaa25f895476abad7f5a1fe4212aee86816398e36a34c8ff6"

# Umbral de AbuseIPDB para considerar una IP maliciosa (0-100%)
ABUSE_THRESHOLD = 50

# IPs privadas que no tienen sentido consultar en bases de datos públicas
PRIVATE_RANGES = ["192.168.", "10.", "172.", "127."]


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def log(msg):
    """
    Escribe un mensaje en el fichero de log con timestamp.
    Prefija con [threat_intel] para distinguirlo de otros playbooks.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [threat_intel] {msg}\n")


def is_private_ip(ip):
    """
    Verifica si una IP es privada.
    Las IPs privadas no están en bases de datos públicas de amenazas.
    """
    return any(ip.startswith(r) for r in PRIVATE_RANGES)


# ─────────────────────────────────────────────
# CONSULTAS A FUENTES EXTERNAS
# ─────────────────────────────────────────────

def check_abuseipdb(ip):
    """
    Consulta la API de AbuseIPDB para obtener el historial de abuso de la IP.

    AbuseIPDB es una base de datos colaborativa donde administradores
    de red de todo el mundo reportan IPs que han realizado actividad maliciosa.
    Cada reporte incluye la categoría (SSH brute force, DDoS, spam, etc.)

    Parámetros de la consulta:
    - ipAddress: la IP a analizar
    - maxAgeInDays=90: solo reportes de los últimos 90 días

    Campos que devuelve y usamos:
    - abuseConfidenceScore: 0-100%, porcentaje de confianza de que sea maliciosa
    - totalReports: número total de reportes recibidos
    - countryCode: país de origen de la IP
    - isp: proveedor de internet de la IP

    Retorna un dict con los datos, o None si la consulta falla.
    """
    try:
        # Construir la URL con los parámetros de consulta
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

        req = urllib.request.Request(url)
        # La API requiere la API key en el header "Key"
        req.add_header("Key", ABUSEIPDB_KEY)
        # Indicamos que esperamos JSON como respuesta
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # Extraer los campos relevantes del objeto data
        result  = data.get("data", {})
        score   = result.get("abuseConfidenceScore", 0)
        reports = result.get("totalReports", 0)
        country = result.get("countryCode", "N/A")
        isp     = result.get("isp", "N/A")

        log(f"AbuseIPDB [{ip}] score={score}% reports={reports} country={country} isp={isp}")

        return {
            "source":    "AbuseIPDB",
            "score":     score,
            "reports":   reports,
            "country":   country,
            "isp":       isp,
            # Se considera maliciosa si supera el umbral definido
            "malicious": score >= ABUSE_THRESHOLD
        }

    except Exception as e:
        log(f"ERROR AbuseIPDB: {e}")
        return None  # la consulta falló, no podemos dar veredicto


def check_otx(ip):
    """
    Consulta la API de AlienVault OTX (Open Threat Exchange).

    OTX es una plataforma donde investigadores de seguridad de todo el mundo
    publican 'pulsos' — colecciones de Indicadores de Compromiso (IoCs)
    agrupados por campaña, malware o actor de amenaza.

    Si una IP aparece en uno o más pulsos, significa que ha sido
    asociada a actividad maliciosa conocida (C2, botnet, scanner, etc.)

    Campos que devuelve y usamos:
    - pulse_info.count: número de pulsos que incluyen esta IP
    - reputation: puntuación de reputación (negativa = maliciosa)

    Retorna un dict con los datos, o None si la consulta falla.
    """
    try:
        # Endpoint para obtener información general de una IPv4
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

        req = urllib.request.Request(url)
        # OTX usa el header X-OTX-API-KEY para autenticación
        req.add_header("X-OTX-API-KEY", OTX_KEY)

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # Extraer número de pulsos y reputación
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        reputation  = data.get("reputation", 0)

        log(f"OTX [{ip}] pulses={pulse_count} reputation={reputation}")

        return {
            "source":     "OTX",
            "pulses":     pulse_count,
            "reputation": reputation,
            # Si aparece en algún pulso, la IP está en campañas conocidas
            "malicious":  pulse_count > 0
        }

    except Exception as e:
        # Timeout frecuente con OTX — no es crítico, continuamos con AbuseIPDB
        log(f"ERROR OTX: {e}")
        return None


# ─────────────────────────────────────────────
# ANÁLISIS Y VEREDICTO
# ─────────────────────────────────────────────

def analyze_ip(ip):
    """
    Consulta ambas fuentes y combina los resultados en un veredicto final.

    Estrategia de veredicto combinado:
    - Si CUALQUIER fuente dice que es maliciosa → MALICIOSA
    - Solo si AMBAS dicen limpia (o fallan) → LIMPIA

    Esto prioriza la seguridad sobre los falsos negativos:
    mejor bloquear una IP legítima (falso positivo) que dejar
    pasar una maliciosa (falso negativo).

    Retorna un dict completo con el veredicto y los datos de ambas fuentes.
    """
    log(f"Analizando IP: {ip}")

    # Consultar ambas fuentes en secuencia
    abuse = check_abuseipdb(ip)
    otx   = check_otx(ip)

    # Determinar veredicto final combinando ambas fuentes
    is_malicious = False
    if abuse and abuse["malicious"]:
        is_malicious = True
    if otx and otx["malicious"]:
        is_malicious = True

    verdict = "MALICIOSA" if is_malicious else "LIMPIA"
    log(f"Veredicto [{ip}]: {verdict}")

    return {
        "ip":        ip,
        "malicious": is_malicious,
        "verdict":   verdict,
        "abuseipdb": abuse,
        "otx":       otx
    }


def save_report(ip, result):
    """
    Guarda el informe completo del análisis en formato JSON.

    Los informes se nombran con IP y timestamp para poder
    recuperar el histórico de análisis de una IP concreta.

    Ejemplo: /opt/cyntia-playbooks/threat_reports/185.220.101.1-20260419-204434.json
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(REPORTS_DIR, f"{ip}-{timestamp}.json")

    with open(path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    log(f"Informe guardado: {path}")


def trigger_block_ip(ip):
    """
    Activa el playbook block_ip.py para bloquear la IP maliciosa.

    En lugar de duplicar la lógica de bloqueo, reutilizamos el
    playbook existente pasándole el JSON que espera por stdin.
    Así toda la lógica de bloqueo está en un solo lugar.
    """
    log(f"IP maliciosa confirmada - activando block_ip para {ip}")

    # Construir el JSON que espera block_ip.py
    payload = json.dumps({"data": {"srcip": ip}}).encode()

    subprocess.run(
        ["python3", "/opt/cyntia-playbooks/block_ip.py"],
        input=payload,
        timeout=10
    )


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────

def main():
    """
    Punto de entrada del playbook.

    Lee el JSON de la alerta de Wazuh por stdin.
    Extrae la IP, la analiza con ambas fuentes de TI
    y actúa en consecuencia si es maliciosa.

    Flujo completo:
    1. Leer alerta de Wazuh
    2. Extraer IP de origen
    3. Validar que no es privada
    4. Consultar AbuseIPDB
    5. Consultar OTX
    6. Determinar veredicto
    7. Si maliciosa → activar block_ip.py
    8. Guardar informe JSON
    """
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        # Extraer IP de los campos posibles de la alerta
        ip = (alert.get("data", {}).get("srcip") or
              alert.get("data", {}).get("src_ip") or
              alert.get("data", {}).get("src_host"))

        if not ip:
            log("No se encontró IP en la alerta")
            sys.exit(1)

        # Las IPs privadas no tienen sentido consultarlas en TI públicas
        if is_private_ip(ip):
            log(f"IP privada, no se analiza con TI: {ip}")
            sys.exit(0)

        # Analizar la IP con ambas fuentes
        result = analyze_ip(ip)

        # Si es maliciosa, bloquearla inmediatamente
        if result["malicious"]:
            trigger_block_ip(ip)

        # Guardar el informe independientemente del veredicto
        save_report(ip, result)

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()
