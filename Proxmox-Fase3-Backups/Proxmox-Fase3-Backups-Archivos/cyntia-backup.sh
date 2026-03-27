#!/bin/bash
# /usr/local/bin/cyntia-backup.sh — cyntia (nodo principal)
# Script de backup granular con BorgBackup
# Ejecutado automáticamente cada noche a las 2:00 AM via cron
# Hace backup de: configs del host, PiHole y Wazuh
# Envía notificación por email al finalizar

# PATH explícito necesario porque cron usa un PATH mínimo
# que no incluye /usr/sbin/ donde vive el comando pct de Proxmox
export PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin

export BORG_PASSPHRASE='Cyntia#B0rg$2026'
REPO=/mnt/backup-nfs/borg
DATE=$(date +%Y-%m-%d)
LOG=/var/log/cyntia-backup.log

# Asegurar que el directorio del repositorio existe
mkdir -p /mnt/backup-nfs/borg

# Limpiar log de ejecuciones anteriores (solo conservar la última)
> $LOG

echo "=== Backup iniciado: $(date) ===" >> $LOG

# ── Configuraciones críticas del host ─────────────────────────────────────────
# Incluye: firewall (nftables), red (interfaces), resolución (hosts),
# configuración del cluster (corosync)
borg create --stats $REPO::configs-$DATE \
    /etc/nftables.conf \
    /etc/network/interfaces \
    /etc/hosts \
    /etc/pve/corosync.conf \
    2>> $LOG

# ── PiHole (LXC 100) ──────────────────────────────────────────────────────────
# Los LXC con almacenamiento LVM no tienen su rootfs accesible desde el host.
# Solución: crear el tar dentro del contenedor con pct exec,
# extraerlo al NFS con pct pull, y limpiar el temporal.
pct exec 100 -- bash -c "tar czf /tmp/pihole-backup.tar.gz /etc/pihole/ 2>/dev/null"
pct pull 100 /tmp/pihole-backup.tar.gz /mnt/backup-nfs/pihole-$DATE.tar.gz
pct exec 100 -- rm -f /tmp/pihole-backup.tar.gz
echo "PiHole backup: OK" >> $LOG

# ── Wazuh (LXC 101) ───────────────────────────────────────────────────────────
# Incluye docker-compose.yml, configuraciones y certificados del stack SOC
pct exec 101 -- bash -c "tar czf /tmp/wazuh-backup.tar.gz /opt/wazuh-docker/single-node/ 2>/dev/null"
pct pull 101 /tmp/wazuh-backup.tar.gz /mnt/backup-nfs/wazuh-$DATE.tar.gz
pct exec 101 -- rm -f /tmp/wazuh-backup.tar.gz
echo "Wazuh backup: OK" >> $LOG

echo "=== Backup finalizado: $(date) ===" >> $LOG

# ── Retención ─────────────────────────────────────────────────────────────────
# Conservar 7 backups diarios + 4 semanales, eliminar los más antiguos
borg prune --keep-daily=7 --keep-weekly=4 $REPO >> $LOG 2>&1

# ── Notificación por email ────────────────────────────────────────────────────
mail -s "Backup Cyntia BorgBackup - $DATE" jlp170617@gmail.com < $LOG
