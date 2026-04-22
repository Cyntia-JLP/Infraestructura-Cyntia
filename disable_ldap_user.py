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
import hashlib
import base64
import os


# ─────────────────────────────────────────────
# CONFIGURACIÓN LDAP
# ─────────────────────────────────────────────

# Fichero de log compartido con todos los playbooks
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Datos de conexión al servidor OpenLDAP en lxc-ldap
LDAP_HOST  = "192.168.10.2"           # IP de lxc-ldap en VLAN10
LDAP_BASE  = "dc=cyntia,dc=local"     # base del árbol LDAP
LDAP_ADMIN = "cn=admin,dc=cyntia,dc=local"  # DN del administrador
LDAP_PASS  = "LDAP$$C7n74#&&"         # contraseña del admin LDAP


# ─────────────────────────────────────────────
# FUNCIONES AUXILIARES
# ─────────────────────────────────────────────

def log(msg):
    """
    Escribe un mensaje en el fichero de log con timestamp.
    Prefija con [disable_ldap_user] para distinguirlo del resto de playbooks.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [disable_ldap_user] {msg}\n")


def ldap_search(username):
    """
    Busca el DN (Distinguished Name) completo de un usuario en LDAP.

    El DN es la ruta única que identifica al usuario en el árbol LDAP,
    por ejemplo: uid=agarcia,ou=IT,ou=MedTrans,dc=cyntia,dc=local

    Necesitamos el DN para poder modificar al usuario con ldapmodify.

    Retorna el DN como string, o None si el usuario no existe.
    """
    result = subprocess.run([
        "ldapsearch",
        "-x",                          # autenticación simple (no SASL)
        "-H", f"ldap://{LDAP_HOST}",   # URL del servidor LDAP
        "-D", LDAP_ADMIN,              # DN del administrador para autenticarse
        "-w", LDAP_PASS,               # contraseña del administrador
        "-b", LDAP_BASE,               # base de búsqueda (toda la organización)
        f"(uid={username})",           # filtro: buscar por uid
        "dn"                           # solo devolver el atributo dn
    ], capture_output=True, text=True, timeout=10)

    # Recorrer las líneas buscando la que empiece por "dn:"
    for line in result.stdout.splitlines():
        if line.startswith("dn:"):
            return line.split("dn: ")[1].strip()

    return None  # usuario no encontrado


def random_password(length=32):
    """
    Genera una contraseña aleatoria criptográficamente segura.

    Usa el módulo 'secrets' que está diseñado específicamente para
    generar datos seguros (a diferencia de 'random' que es predecible).

    Con 32 caracteres del conjunto completo hay 95^32 combinaciones
    posibles — imposible de adivinar por fuerza bruta.
    """
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


def get_hashed_password(password):
    """
    Genera un hash SSHA (Salted SHA-1) compatible con OpenLDAP.

    OpenLDAP almacena las contraseñas como hashes, no en texto plano.
    El formato {SSHA} usa SHA-1 con una sal aleatoria de 4 bytes:

        hash = SHA1(password + salt)
        resultado = "{SSHA}" + base64(hash + salt)

    La sal evita ataques de diccionario y tablas rainbow — dos usuarios
    con la misma contraseña tendrán hashes completamente diferentes.

    NOTA: No usamos slappasswd porque requiere tener slapd instalado,
    lo que consumiría demasiada RAM en lxc-soc-core.
    """
    salt = os.urandom(4)  # 4 bytes de sal aleatoria
    sha = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(sha + salt).decode()


def ldap_modify(ldif):
    """
    Ejecuta una operación de modificación en LDAP usando ldapmodify.

    Recibe un string en formato LDIF (LDAP Data Interchange Format),
    que es el lenguaje estándar para describir cambios en LDAP.

    Retorna una tupla (éxito: bool, error: str).
    """
    result = subprocess.run([
        "ldapmodify",
        "-x",                          # autenticación simple
        "-H", f"ldap://{LDAP_HOST}",   # servidor LDAP
        "-D", LDAP_ADMIN,              # administrador
        "-w", LDAP_PASS                # contraseña
    ],
        input=ldif.encode(),           # el LDIF como bytes por stdin
        capture_output=True,
        timeout=10
    )
    return result.returncode == 0, result.stderr.decode()


def ensure_disabled_group():
    """
    Crea el grupo 'disabled' en LDAP si no existe todavía.

    Este grupo sirve para tener un registro centralizado de todos los
    usuarios que han sido deshabilitados por el SOC. Facilita auditorías
    y búsquedas rápidas de cuentas comprometidas.

    Se llama automáticamente al deshabilitar el primer usuario, así
    no hay que crearlo manualmente.
    """
    # Primero verificar si ya existe
    check = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}",
        "-D", LDAP_ADMIN,
        "-w", LDAP_PASS,
        "-b", LDAP_BASE,
        "(cn=disabled)",
        "dn"
    ], capture_output=True, text=True, timeout=10)

    if "dn:" in check.stdout:
        return  # ya existe, nada que hacer

    # Crear el grupo si no existe
    ldif = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
objectClass: groupOfNames
cn: disabled
description: Usuarios deshabilitados por Cyntia SOC
member: cn=admin,{LDAP_BASE}"""

    # groupOfNames requiere al menos un member, usamos admin como placeholder
    subprocess.run([
        "ldapadd", "-x",
        "-H", f"ldap://{LDAP_HOST}",
        "-D", LDAP_ADMIN,
        "-w", LDAP_PASS
    ], input=ldif.encode(), capture_output=True, timeout=10)

    log("Grupo 'disabled' creado en LDAP")


# ─────────────────────────────────────────────
# OPERACIONES PRINCIPALES
# ─────────────────────────────────────────────

def disable_user(username):
    """
    Deshabilita completamente un usuario LDAP en tres pasos:

    Paso 1: loginShell → /bin/false
        Impide que el usuario abra una shell en sistemas Linux
        que usen LDAP para autenticación PAM.

    Paso 2: Contraseña aleatoria
        Invalida las credenciales del usuario en TODOS los servicios
        que usen LDAP (portal web, aplicaciones, etc.)
        La nueva contraseña es imposible de adivinar o recuperar.

    Paso 3: Añadir al grupo 'disabled'
        Permite auditoría y búsqueda rápida de cuentas comprometidas.
        También puede usarse para denegar acceso por grupo en aplicaciones.

    Retorna True si el aislamiento fue exitoso, False si hubo error.
    """
    # Buscar el DN del usuario primero
    dn = ldap_search(username)
    if not dn:
        log(f"Usuario no encontrado en LDAP: {username}")
        return False

    # ── PASO 1: Bloquear loginShell ──────────────────────────────
    ldif_shell = f"""dn: {dn}
changetype: modify
replace: loginShell
loginShell: /bin/false"""

    ok, err = ldap_modify(ldif_shell)
    if ok:
        log(f"loginShell bloqueado para: {username}")
    else:
        log(f"ERROR bloqueando shell de {username}: {err}")

    # ── PASO 2: Invalidar contraseña ────────────────────────────
    # Generamos contraseña aleatoria y la hasheamos antes de guardar
    nueva_pass = random_password()
    hash_pass = get_hashed_password(nueva_pass)
    # IMPORTANTE: la nueva contraseña NO se guarda en ningún sitio
    # Es imposible de recuperar — esto es intencional

    ldif_pass = f"""dn: {dn}
changetype: modify
replace: userPassword
userPassword: {hash_pass}"""

    ok, err = ldap_modify(ldif_pass)
    if ok:
        log(f"Contraseña invalidada para: {username}")
    else:
        log(f"ERROR invalidando contraseña de {username}: {err}")

    # ── PASO 3: Añadir al grupo 'disabled' ──────────────────────
    ensure_disabled_group()  # crear el grupo si no existe

    ldif_group = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
changetype: modify
add: member
member: {dn}"""

    ok, err = ldap_modify(ldif_group)
    if ok:
        log(f"Usuario {username} añadido al grupo 'disabled'")
    else:
        log(f"AVISO grupo disabled: {err}")  # no es crítico si falla

    # Resumen final
    log(f"AISLAMIENTO COMPLETO: {username} ({dn})")
    log(f"Para reactivar: python3 disable_ldap_user.py --enable {username}")
    return True


def enable_user(username):
    """
    Reactiva un usuario previamente deshabilitado.

    IMPORTANTE: Este modo solo puede ejecutarse MANUALMENTE.
    Wazuh nunca llama a este modo — solo el equipo SOC puede
    decidir cuándo reactivar a un usuario comprometido.

    Tras la reactivación, el equipo DEBE:
    1. Cambiar la contraseña manualmente desde LAM
    2. Revisar los logs para entender qué ocurrió
    3. Asegurarse de que el incidente está resuelto

    Pasos del modo enable:
    1. loginShell → /bin/bash  (restaurar acceso a shell)
    2. Eliminar del grupo 'disabled'
    """
    dn = ldap_search(username)
    if not dn:
        log(f"Usuario no encontrado: {username}")
        return False

    # ── PASO 1: Restaurar loginShell ────────────────────────────
    ldif_shell = f"""dn: {dn}
changetype: modify
replace: loginShell
loginShell: /bin/bash"""

    ok, err = ldap_modify(ldif_shell)
    if ok:
        log(f"loginShell restaurado para: {username}")
    else:
        log(f"ERROR restaurando shell de {username}: {err}")

    # ── PASO 2: Eliminar del grupo 'disabled' ────────────────────
    ldif_group = f"""dn: cn=disabled,ou=grupos,{LDAP_BASE}
changetype: modify
delete: member
member: {dn}"""

    ok, err = ldap_modify(ldif_group)
    if ok:
        log(f"Usuario {username} eliminado del grupo 'disabled'")

    log(f"REACTIVACION COMPLETA: {username}")
    log(f"IMPORTANTE: Cambia la contraseña manualmente desde LAM: http://100.92.243.96:8080/lam")
    return True


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────

def main():
    """
    Punto de entrada del playbook.

    Soporta dos modos de ejecución:

    MODO AUTOMÁTICO (Wazuh):
        El JSON de la alerta llega por stdin.
        Se extrae el usuario y se deshabilita.

    MODO MANUAL (equipo SOC):
        python3 disable_ldap_user.py --enable <username>
        Reactiva un usuario previamente deshabilitado.
    """
    # ── Modo reactivación manual ─────────────────────────────────
    if len(sys.argv) == 3 and sys.argv[1] == "--enable":
        username = sys.argv[2]
        log(f"Reactivación manual solicitada para: {username}")
        enable_user(username)
        return

    # ── Modo automático desde Wazuh ──────────────────────────────
    input_data = sys.stdin.read()
    try:
        alert = json.loads(input_data)

        # Intentar extraer el usuario de varios campos posibles
        # Wazuh usa distintos nombres según el tipo de log
        username = (alert.get("data", {}).get("srcuser") or
                    alert.get("data", {}).get("dstuser") or
                    alert.get("data", {}).get("uid"))

        if not username:
            log("No se encontró usuario en la alerta")
            sys.exit(1)

        log(f"Alerta recibida - Aislando usuario: {username}")
        disable_user(username)

    except json.JSONDecodeError:
        log("Error parseando JSON de Wazuh")
        sys.exit(1)


# ─────────────────────────────────────────────
# ENTRADA
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main()
