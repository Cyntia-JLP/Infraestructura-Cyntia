#!/bin/bash
# =============================================================================
# cyntia-backup.sh — Backup automatizado de la plataforma · Proyecto Cyntia
# =============================================================================
# Propósito:
#   Realiza copias de seguridad diarias de todos los elementos críticos de la
#   plataforma que NO están cubiertos por vzdump (que hace backup de los LXC
#   completos a nivel de sistema de ficheros).
#
#   Este script complementa a vzdump cubriendo:
#   - Configuraciones del host Proxmox (nftables, red, corosync)
#   - Datos de aplicación que cambian frecuentemente (LDAP, PiHole, Wazuh)
#   - Exportación del directorio LDAP en formato LDIF (portable y legible)
#
#   Los backups se almacenan en el nodo secundario (cyntia-backup) montado
#   por NFS en /mnt/backup-nfs, con dos niveles de redundancia:
#   - Ficheros individuales con fecha: para restauración rápida de un dato
#   - Repositorio BorgBackup: para historial, deduplicación y compresión
#
# Ubicación:  /usr/local/bin/cyntia-backup.sh (en el host Proxmox)
# Cron:       0 2 * * * /usr/local/bin/cyntia-backup.sh (cada noche a las 2AM)
# Log:        /var/log/cyntia-backup.log
# Destino:    /mnt/backup-nfs/ (NFS desde cyntia-backup, 192.168.3.101)
# Email:      jlp170617@gmail.com (resumen tras cada ejecución via Postfix)
# =============================================================================

export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin

# Passphrase del repositorio BorgBackup (cifrado AES-256)
export BORG_PASSPHRASE='-'

REPO=/mnt/backup-nfs/borg          # Repositorio BorgBackup en nodo secundario
DATE=$(date +%Y-%m-%d)             # Fecha del backup (YYYY-MM-DD)
LOG=/var/log/cyntia-backup.log     # Log de la ejecución

# Asegurar que el directorio del repositorio existe
mkdir -p /mnt/backup-nfs/borg

echo "=== Backup iniciado: $(date) ===" >> $LOG

# --- Backup 1: Configuraciones críticas del host -----------------------------
# Guarda en BorgBackup los ficheros de configuración del host Proxmox que,
# si se pierden tras un fallo de disco, impedirían restaurar el sistema:
#   - nftables.conf: todas las reglas de red, VLANs, NAT y set blocked_ips
#   - interfaces: configuración de red de Proxmox (bridges, VLANs)
#   - hosts: resolución de nombres local (necesario para pve-cluster)
#   - corosync.conf: configuración del cluster de 2 nodos
#
# El nombre del archivo en Borg incluye la fecha para identificar el snapshot.
# BorgBackup deduplica bloques idénticos entre snapshots, por lo que ocupa
# muy poco espacio adicional cada día.

borg create --stats $REPO::configs-$DATE \
    /etc/nftables.conf \
    /etc/network/interfaces \
    /etc/hosts \
    /etc/pve/corosync.conf \
    2>> $LOG

# --- Backup 2: PiHole --------------------------------------------------------
# PiHole guarda su configuración (listas de bloqueo, DNS custom, whitelist)
# en /etc/pihole/ dentro del contenedor lxc-pihole (VMID 100).
# Se comprime en un tar.gz dentro del contenedor, se descarga al host
# y se guarda con fecha. Si PiHole falla, se puede restaurar en minutos.

pct exec 100 -- bash -c "tar czf /tmp/pihole-backup.tar.gz /etc/pihole/ 2>/dev/null"
pct pull 100 /tmp/pihole-backup.tar.gz /mnt/backup-nfs/pihole-$DATE.tar.gz
pct exec 100 -- rm -f /tmp/pihole-backup.tar.gz
echo "PiHole backup: OK" >> $LOG

# --- Backup 3: OpenLDAP ------------------------------------------------------
# slapcat exporta el directorio LDAP completo en formato LDIF estándar.
# Este formato es portable: se puede importar en cualquier servidor LDAP
# independientemente de la versión o distribución.
# Incluye todos los usuarios, grupos, OUs y atributos de MedTrans Ibérica.
# El fichero .ldif es legible como texto plano, útil para auditoría.

pct exec 201 -- bash -c "slapcat > /tmp/ldap-backup.ldif"
pct pull 201 /tmp/ldap-backup.ldif /mnt/backup-nfs/ldap-$DATE.ldif
pct exec 201 -- bash -c "rm -f /tmp/ldap-backup.ldif"
echo "LDAP backup: OK" >> $LOG

# --- Backup 4: Wazuh (configuraciones) ---------------------------------------
# Guarda todo el directorio /opt/wazuh-docker/single-node/ que contiene:
#   - docker-compose.yml: definición del stack Docker
#   - ossec.conf / wazuh_manager.conf: reglas, active-responses, localfiles
#   - Certificados SSL del cluster Wazuh
#   - Config del indexer y dashboard
#
# NOTA: Los datos de alertas históricas están en volúmenes Docker y los
# cubre vzdump. Este backup es solo de configuración para restauración rápida.

pct exec 101 -- bash -c "tar czf /tmp/wazuh-backup.tar.gz /opt/wazuh-docker/single-node/ 2>/dev/null"
pct pull 101 /tmp/wazuh-backup.tar.gz /mnt/backup-nfs/wazuh-$DATE.tar.gz
pct exec 101 -- rm -f /tmp/wazuh-backup.tar.gz
echo "Wazuh backup: OK" >> $LOG

echo "=== Backup finalizado: $(date) ===" >> $LOG

# --- Retención BorgBackup ----------------------------------------------------
# Aplica política de retención al repositorio Borg:
#   - keep-daily=7:  conserva 1 snapshot por día durante 7 días
#   - keep-weekly=4: conserva 1 snapshot por semana durante 4 semanas
# Los snapshots más antiguos se eliminan automáticamente.
# Los bloques de datos huérfanos (sin referencias) también se limpian.

borg prune --keep-daily=7 --keep-weekly=4 $REPO >> $LOG 2>&1

# --- Notificación por email --------------------------------------------------
# Envía el contenido del log al email configurado usando Postfix con relay
# de Gmail. Permite saber cada mañana si el backup fue exitoso o hubo errores.

mail -s "Backup Cyntia BorgBackup - $DATE" jlp170617@gmail.com < $LOG
