#!/usr/bin/env python3
"""
=========================================================
PLAYBOOK: disable_ldap_user.py
PROYECTO: Cyntia SOC - Plataforma SIEM para PYMEs
=========================================================
FUNCIÓN:
    Aísla completamente a un usuario de OpenLDAP cuando se detecta
    actividad sospechosa asociada a su cuenta. El aislamiento
    aplica tres capas de bloqueo simultáneas:

    1. loginShell → /bin/false  : impide login en sistemas Linux
    2. Contraseña aleatoria     : invalida credenciales en todos los servicios
    3. Grupo 'disabled'         : trazabilidad y auditoría del aislamiento

    También incluye modo --enable para reactivar el usuario manualmente
    cuando el incidente esté resuelto.

ACTIVACIÓN:
    Wazuh lo ejecuta automáticamente con las reglas:
    100201 (SSH honeypot), 100202 (conexión honeypot), 100203 (MySQL honeypot)

DEPENDENCIAS:
    - ldap-utils instalado en lxc-soc-core (ldapsearch, ldapmodify)
    - Conectividad entre lxc-soc-core (VLAN20) y lxc-ldap (VLAN10)

UBICACIÓN:
    - Script principal: /opt/cyntia-playbooks/disable_ldap_user.py
    - Copia en Wazuh:   /var/ossec/active-response/bin/disable_ldap_user.py
    - Log de salida:    /var/ossec/logs/active-responses.log
    - Servidor LDAP:    lxc-ldap (192.168.10.2)
    - Panel gestión:    http://100.92.243.96:8080/lam

NOTAS:
    Tras reactivar un usuario, es OBLIGATORIO cambiar su contraseña
    manualmente desde LAM porque el script la invalidó con un valor
    aleatorio imposible de recuperar.
=========================================================
"""

import sys
import json
import datetime
import subprocess
import secrets
import string

LOG_FILE = "/var/ossec/logs/active-responses.log"
LDAP_HOST = "-"
LDAP_BASE = "-"
LDAP_ADMIN = "-"
LDAP_PASS = "-"

def log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [disable_ldap_user] {msg}\n")


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


def ldap_search(username):
    """Busca el DN del usuario en LDAP."""
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}",
        "-D", LDAP_ADMIN,
        "-w", LDAP_PASS,
        "-b", LDAP_BASE,
        f"(uid={username})",
        "dn"
    ], capture_output=True, text=True, timeout=10)

    for line in result.stdout.splitlines():
        if line.startswith("dn:"):
            return line.split("dn: ")[1].strip()
    return None

def random_password(length=32):
    """Genera una contraseña aleatoria imposible de adivinar."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def ldap_modify(ldif):
    """Ejecuta un ldapmodify con el LDIF dado."""
    result = subprocess.run([
        "ldapmodify", "-x",
        "-H", f"ldap://{LDAP_HOST}",
        "-D", LDAP_ADMIN,
        "-w", LDAP_PASS
    ], input=ldif.encode(), capture_output=True, timeout=10)
    return result.returncode == 0, result.stderr.decode()

def get_hashed_password(password):
    """Genera hash SHA para LDAP usando Python puro."""
    import hashlib
    import base64
    import os
    salt = os.urandom(4)
    sha = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(sha + salt).decode()

def ensure_disabled_group():
    """Crea el grupo 'disabled' si no existe."""
    check = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}",
        "-D", LDAP_ADMIN,
        "-w", LDAP_PASS,
        "-b", LDAP_BASE,
        "(cn=disabled)",
        "dn"
    ], capture_output=True, text=True, timeout=10)

    if "dn:" not in check.stdout:
        ldif = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
objectClass: groupOfNames
cn: disabled
description: Usuarios deshabilitados por Cyntia SOC
member: cn=admin,{LDAP_BASE}"""
        subprocess.run([
            "ldapadd", "-x",
            "-H", f"ldap://{LDAP_HOST}",
            "-D", LDAP_ADMIN,
            "-w", LDAP_PASS
        ], input=ldif.encode(), capture_output=True, timeout=10)
        log("Grupo 'disabled' creado")

def disable_user(username, razon="Actividad sospechosa detectada"):
    """Deshabilita completamente un usuario LDAP."""
    dn = ldap_search(username)
    if not dn:
        log(f"Usuario no encontrado: {username}")
        return False

    # 1. Cambiar loginShell a /bin/false
    ldif_shell = f"""dn: {dn}
changetype: modify
replace: loginShell
loginShell: /bin/false"""

    ok, err = ldap_modify(ldif_shell)
    if ok:
        log(f"loginShell bloqueado para: {username}")
    else:
        log(f"ERROR bloqueando shell de {username}: {err}")

    # 2. Cambiar contraseña por una aleatoria
    new_pass = random_password()
    hashed = get_hashed_password(new_pass)

    ldif_pass = f"""dn: {dn}
changetype: modify
replace: userPassword
userPassword: {hashed}"""

    ok, err = ldap_modify(ldif_pass)
    if ok:
        log(f"Contraseña invalidada para: {username}")
    else:
        log(f"ERROR invalidando contraseña de {username}: {err}")

    # 3. Añadir al grupo disabled
    ensure_disabled_group()
    ldif_group = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
changetype: modify
add: member
member: {dn}"""

    ok, err = ldap_modify(ldif_group)
    if ok:
        log(f"Usuario {username} añadido al grupo 'disabled'")
    else:
        log(f"AVISO grupo disabled: {err}")

    log(f"AISLAMIENTO COMPLETO: {username} ({dn})")
    log(f"Para reactivar: python3 disable_ldap_user.py --enable {username}")
    notify_telegram(
        "👤 *USUARIO DESHABILITADO — Cyntia SOC*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🏢 *Cliente:* MedTrans Iberica S.L.\n"
        "👤 *Usuario:* `" + username + "`\n"
        "⚡ *Accion:* Shell /bin/false + contrasena invalidada\n"
        "🕐 *Hora:* " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
        "📋 *Razon:* " + razon + "\n"
        "⚠️ *Revisar si es falso positivo*"
    )
    return True

def enable_user(username):
    """Reactiva un usuario previamente deshabilitado."""
    dn = ldap_search(username)
    if not dn:
        log(f"Usuario no encontrado: {username}")
        return False

    # 1. Restaurar loginShell a /bin/bash
    ldif_shell = f"""dn: {dn}
changetype: modify
replace: loginShell
loginShell: /bin/bash"""

    ok, err = ldap_modify(ldif_shell)
    if ok:
        log(f"loginShell restaurado para: {username}")
    else:
        log(f"ERROR restaurando shell de {username}: {err}")

    # 2. Eliminar del grupo disabled
    ldif_group = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
changetype: modify
delete: member
member: {dn}"""

    ok, err = ldap_modify(ldif_group)
    if ok:
        log(f"Usuario {username} eliminado del grupo 'disabled'")

    log(f"REACTIVACION COMPLETA: {username}")
    log(f"IMPORTANTE: Cambia la contraseña manualmente desde LAM")
    return True

def main():
    # Modo reactivación manual
    if len(sys.argv) == 3 and sys.argv[1] == "--enable":
        username = sys.argv[2]
        log(f"Reactivación manual solicitada para: {username}")
        enable_user(username)
        return

    # Modo automático desde Wazuh
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        # Wazuh envuelve la alerta en parameters.alert
        if "parameters" in alert and "alert" in alert.get("parameters", {}):
            alert = alert["parameters"]["alert"]

        username = alert.get("data", {}).get("srcuser") or \
                   alert.get("data", {}).get("dstuser") or \
                   alert.get("data", {}).get("uid")

        if not username:
            log("No se encontró usuario en la alerta")
            sys.exit(1)

        razon = alert.get("rule", {}).get("description", "Actividad sospechosa detectada")
        log(f"Alerta recibida - Aislando usuario: {username}")
        disable_user(username, razon)

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)

if __name__ == "__main__":
    main()
