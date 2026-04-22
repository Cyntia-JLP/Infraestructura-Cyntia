#!/bin/bash
# =============================================================================
# ldap_monitor.sh — Monitor periódico LDAP · Proyecto Cyntia SOC/SIEM
# =============================================================================
# Propósito:
#   Simula la monitorización continua que un SOC gestionado haría sobre el
#   servidor de directorio de un cliente (MedTrans Ibérica S.L.).
#
#   Ejecuta consultas LDAP cada 10 minutos desde lxc-soc-core (VLAN20)
#   hacia lxc-ldap (VLAN10), lo que produce tres efectos simultáneos:
#
#   1. Suricata detecta tráfico real en eth1 (interfaz VLAN10) y lo registra
#      en eve.json como flows TCP hacia puerto 389 (LDAP).
#
#   2. OpenLDAP registra cada consulta en slapd.log, que el agente Wazuh 006
#      reenvía al manager para su análisis.
#
#   3. El intento de autenticación fallida intencionado (paso 4) puede
#      disparar la regla Wazuh 2502 y activar los playbooks block_ip
#      y create_ticket si se repite suficientes veces.
#
# Ubicación: /opt/cyntia-playbooks/ldap_monitor.sh (dentro de lxc-soc-core)
# Cron:      */10 * * * * /opt/cyntia-playbooks/ldap_monitor.sh
# Log:       /opt/cyntia-playbooks/ldap_monitor.log (máx 500 líneas, rotación automática)
# =============================================================================

# --- Configuración -----------------------------------------------------------

LDAP_HOST="192.168.10.2"                          # IP de lxc-ldap (VLAN10)
LDAP_ADMIN="cn=admin,dc=cyntia,dc=local"          # Usuario administrador LDAP
LDAP_PASS='-'                        # Contraseña admin LDAP
LDAP_BASE="dc=cyntia,dc=local"                    # Base DN del directorio
MEDTRANS_BASE="ou=MedTrans,dc=cyntia,dc=local"    # OU raíz del cliente
DISABLED_GROUP="cn=disabled,ou=grupos,dc=cyntia,dc=local"  # Grupo de usuarios bloqueados

LOG="/opt/cyntia-playbooks/ldap_monitor.log"      # Fichero de log
MAX_LINES=500                                      # Líneas máximas antes de rotar

# --- Función de log ----------------------------------------------------------

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

# --- Rotación automática del log ---------------------------------------------
# Si el log supera MAX_LINES, conserva solo las últimas 100 líneas.
# Evita que el fichero crezca indefinidamente sin necesitar logrotate.

if [ -f "$LOG" ] && [ $(wc -l < "$LOG") -gt $MAX_LINES ]; then
    tail -100 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# =============================================================================
# INICIO DE VERIFICACIÓN
# =============================================================================

log "=== Inicio verificacion MedTrans ==="

# --- Paso 1: Contar usuarios activos -----------------------------------------
# Consulta todos los objetos inetOrgPerson bajo la OU de MedTrans.
# Un SOC real usaría esto para detectar altas inesperadas de usuarios.
# Esta consulta genera tráfico LDAP visible en Suricata (eth1, VLAN10).

USERS=$(ldapsearch -x -H ldap://$LDAP_HOST \
  -D "$LDAP_ADMIN" -w "$LDAP_PASS" \
  -b "$MEDTRANS_BASE" \
  "(objectClass=inetOrgPerson)" uid 2>/dev/null | grep -c "^uid:")
log "Usuarios activos en MedTrans: $USERS"

# --- Paso 2: Verificar usuarios deshabilitados --------------------------------
# Consulta el grupo 'disabled'. Si el playbook disable_ldap_user.py ha
# actuado sobre algún usuario, aparecerá aquí como miembro del grupo.
# Útil para detectar si hubo respuesta automática reciente.

DISABLED=$(ldapsearch -x -H ldap://$LDAP_HOST \
  -D "$LDAP_ADMIN" -w "$LDAP_PASS" \
  -b "$DISABLED_GROUP" \
  "(objectClass=*)" member 2>/dev/null | grep -c "^member:")
log "Usuarios en grupo disabled: $DISABLED"

# Alerta si hay usuarios deshabilitados (indica que un playbook actuó)
if [ "$DISABLED" -gt 0 ]; then
    log "AVISO: Hay $DISABLED usuario(s) deshabilitado(s) - revisar incidencias"
fi

# --- Paso 3: Verificar cuenta de servicio wazuh-reader -----------------------
# Comprueba que la cuenta de servicio usada por Wazuh para consultar
# el directorio sigue activa y con credenciales válidas.
# Si falla, significa que alguien modificó esa cuenta en LDAP.

ldapsearch -x -H ldap://$LDAP_HOST \
  -D "uid=wazuh-reader,ou=servicios,dc=cyntia,dc=local" \
  -w '-' \
  -b "$LDAP_BASE" "(objectClass=*)" dn \
  > /dev/null 2>&1

if [ $? -eq 0 ]; then
    log "wazuh-reader auth: OK"
else
    log "ALERTA: wazuh-reader auth FALLIDA - cuenta de servicio comprometida"
fi

# --- Paso 4: Intento de autenticación fallida intencionado -------------------
# Simula un intento de acceso con un usuario inexistente.
# Esto genera una entrada en slapd.log que Wazuh procesa como auth fallida.
# Si se acumulan suficientes fallos (regla 2502), activa block_ip y
# create_ticket automáticamente como respuesta al posible ataque.
# El fallo aquí es ESPERADO y forma parte del comportamiento diseñado.

ldapsearch -x -H ldap://$LDAP_HOST \
  -D "uid=monitor-check,ou=servicios,dc=cyntia,dc=local" \
  -w "wrongpassword" \
  -b "$LDAP_BASE" "(objectClass=*)" dn \
  > /dev/null 2>&1
log "Auth check completado (fallo esperado para generacion de eventos)"

# =============================================================================
# FIN DE VERIFICACIÓN
# =============================================================================

log "=== Fin verificacion ==="
