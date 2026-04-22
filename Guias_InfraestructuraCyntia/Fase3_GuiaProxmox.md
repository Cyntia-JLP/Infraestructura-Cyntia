# Guía Proxmox - Fase 3

**Infraestructura fase 3: Sistema de Backups y Cluster Proxmox**

---

## 1. Preparación del segundo nodo

El segundo PC (PC 18) se configuró como nodo de backup del cluster. Se instaló Proxmox VE 8.2.2 desde USB con la siguiente configuración:

- **IP:** 192.168.3.101
- **Gateway:** 192.168.3.1
- **DNS:** 1.1.1.1
- **Hostname:** cyntia-backup.cyntia.local

Tras la instalación, desde consola física se ajustaron el hostname y los hosts:

```bash
hostnamectl set-hostname cyntia-backup

nano /etc/hosts
```

Contenido de `/etc/hosts`:

```
127.0.0.1       localhost
192.168.3.101   cyntia-backup.cyntia.local cyntia-backup
```

```bash
systemctl restart networking
```

---

## 2. Instalación de Tailscale en cyntia-backup

Como cyntia-backup no tiene acceso directo a internet, se copiaron los paquetes desde cyntia:

```bash
# En cyntia
scp /var/cache/apt/archives/tailscale_1.96.2_amd64.deb \
    /var/cache/apt/archives/tailscale-archive-keyring_1.35.181_all.deb \
    root@192.168.3.101:/tmp/
```

```bash
# En cyntia-backup
dpkg -i /tmp/tailscale-archive-keyring_1.35.181_all.deb
dpkg -i /tmp/tailscale_1.96.2_amd64.deb
systemctl enable --now tailscaled
tailscale up --reset
```

Autenticarse con la cuenta jlp170617@gmail.com en el enlace que aparece. La IP asignada fue **100.106.127.17**.

Acceso remoto a cyntia-backup desde casa mediante jump SSH:

```bash
ssh -J root@100.92.243.96 root@192.168.3.101
```

---

## 3. Creación del cluster Proxmox

El cluster permite gestionar ambos nodos desde una sola WebUI y enviar los backups al nodo secundario.

### 3.1 Crear el cluster en cyntia

```bash
# En cyntia
systemctl start pve-cluster
pvecm create cyntia-cluster
```

### 3.2 Unir cyntia-backup al cluster

```bash
# En cyntia-backup
pvecm add 192.168.3.100 --fingerprint 6D:B4:19:30:A7:79:BB:6C:A2:27:24:44:4A:68:C5:2D:AC:1A:20:25:83:9A:94:21:EE:53:5B:89:97:AE:25:8D
```

### 3.3 Corrección de la configuración de corosync

Se editó el fichero de corosync en cyntia-backup para que usara las IPs locales:

```bash
# En cyntia-backup
systemctl stop pve-cluster
systemctl stop corosync
nano /etc/corosync/corosync.conf
```

Cambios en el fichero:
- `ring0_addr` del nodo cyntia: `192.168.3.100`
- `ring0_addr` del nodo cyntia-backup: `192.168.3.101`
- `config_version: 3`

```bash
systemctl start corosync
systemctl start pve-cluster
```

### 3.4 Configuración two_node

Para que si un nodo cae el otro siga operativo sin bloquearse:

```bash
# En cyntia
nano /etc/corosync/corosync.conf
```

Sección quorum:

```
quorum {
  provider: corosync_votequorum
  two_node: 1
}
```

```bash
# Reiniciar corosync en ambos nodos
systemctl restart corosync

# En cyntia-backup también
systemctl restart corosync
```

Verificación:

```bash
pvecm status
```

Resultado esperado:

```
Nodes:    2
Quorate:  Yes
Flags:    Quorate 2Node
```

### 3.5 Autostart de servicios y contenedores

```bash
# En cyntia
systemctl enable pve-cluster corosync pveproxy
pct set 100 --onboot 1
pct set 101 --onboot 1
pct set 102 --onboot 1
pct set 103 --onboot 1
pct set 104 --onboot 1

# En cyntia-backup
systemctl enable pve-cluster corosync pveproxy
```

---

## 4. Configuración NFS

NFS permite que cyntia escriba los backups directamente en el disco de cyntia-backup como si fuera local.

### 4.1 Servidor NFS en cyntia-backup

```bash
# En cyntia-backup
apt-get install nfs-kernel-server -y
echo "/var/lib/vz/dump 192.168.3.100(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
exportfs -ra
systemctl enable --now nfs-kernel-server
mkdir -p /var/lock/pve-manager
```

### 4.2 Cliente NFS en cyntia

```bash
# En cyntia
apt-get install nfs-common -y
mkdir -p /mnt/backup-nfs
mkdir -p /var/lock/pve-manager

# Mount permanente en fstab
nano /etc/fstab
```

Añadir al final de fstab:

```
192.168.3.101:/var/lib/vz/dump /mnt/backup-nfs nfs defaults,_netdev 0 0
```

```bash
mount -a
df -h | grep backup-nfs
```

El parámetro `_netdev` hace que el sistema espere a que la red esté disponible antes de montar, evitando errores en el arranque.

---

## 5. Backups completos con vzdump

vzdump hace snapshots completos de todos los LXC y VMs y los guarda en cyntia-backup.

### 5.1 Añadir el storage en la WebUI

Acceder a `https://192.168.3.100:8006`:

- **Datacenter → Storage → Add → Directory**
- ID: `backup-node`
- Directory: `/mnt/backup-nfs`
- Node: `All`
- Content: `VZDump backup file`

### 5.2 Crear el job de backup

- **Datacenter → Backup → Add**
- Node: `cyntia`
- Storage: `backup-node`
- Schedule: `02:00`
- Mode: `Snapshot`
- Compression: `ZSTD`
- Keep Last: `7`
- Send email to: `jlp170617@gmail.com`
- Send email: `Always`

### 5.3 Verificación manual

```bash
# En cyntia
vzdump --all --compress zstd --storage backup-node --mode snapshot
```

Verificar que los ficheros llegan a cyntia-backup:

```bash
ls -lh /var/lib/vz/dump/
```

---

## 6. Backups granulares con BorgBackup

BorgBackup complementa a vzdump con backups cifrados y deduplicados de los datos más críticos: configuraciones del host, PiHole y Wazuh.

### 6.1 Instalación y creación del repositorio

```bash
# En cyntia
apt-get install borgbackup -y
borg init --encryption=repokey /mnt/backup-nfs/borg
# Passphrase: -
```

### 6.2 Script de backup

```bash
nano /usr/local/bin/cyntia-backup.sh
```

Contenido:

```bash
#!/bin/bash

export BORG_PASSPHRASE= -
REPO=/mnt/backup-nfs/borg
DATE=$(date +%Y-%m-%d)
LOG=/var/log/cyntia-backup.log

mkdir -p /mnt/backup-nfs/borg

echo "=== Backup iniciado:$(date) ===" >> $LOG

# Configuraciones críticas del host
borg create --stats $REPO::configs-$DATE \
    /etc/nftables.conf \
    /etc/network/interfaces \
    /etc/hosts \
    /etc/pve/corosync.conf \
    2>> $LOG

# PiHole
pct exec 100 -- bash -c "tar czf /tmp/pihole-backup.tar.gz /etc/pihole/ 2>/dev/null"
pct pull 100 /tmp/pihole-backup.tar.gz /mnt/backup-nfs/pihole-$DATE.tar.gz
pct exec 100 -- rm -f /tmp/pihole-backup.tar.gz
echo "PiHole backup: OK" >> $LOG

# Wazuh
pct exec 101 -- bash -c "tar czf /tmp/wazuh-backup.tar.gz /opt/wazuh-docker/single-node/ 2>/dev/null"
pct pull 101 /tmp/wazuh-backup.tar.gz /mnt/backup-nfs/wazuh-$DATE.tar.gz
pct exec 101 -- rm -f /tmp/wazuh-backup.tar.gz
echo "Wazuh backup: OK" >> $LOG

echo "=== Backup finalizado:$(date) ===" >> $LOG

# Retención: 7 diarios, 4 semanales
borg prune --keep-daily=7 --keep-weekly=4 $REPO >> $LOG 2>&1

# Notificación por email
mail -s "Backup Cyntia -$DATE" jlp170617@gmail.com < $LOG
```

```bash
chmod +x /usr/local/bin/cyntia-backup.sh
```

### 6.3 Cron para ejecución automática

```bash
crontab -e
```

Añadir:

```
0 2 * * * /usr/local/bin/cyntia-backup.sh
```

---

## 7. Notificaciones por email

Postfix actúa como agente de envío usando Gmail como relay.

### 7.1 Instalación

```bash
# En cyntia
apt-get install postfix mailutils libsasl2-modules -y
# Seleccionar: Internet Site, nombre de dominio: cyntia
```

### 7.2 Configuración de Postfix

```bash
nano /etc/postfix/main.cf
```

Añadir al final (asegurarse de que `relayhost` solo aparece una vez):

```
relayhost = [smtp.gmail.com]:587
smtp_use_tls = yes
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
```

### 7.3 App Password de Gmail

Crear una App Password en `https://myaccount.google.com/apppasswords` con nombre `Proxmox`. Copiar el código de 16 caracteres.

```bash
nano /etc/postfix/sasl_passwd
```

Contenido (sin espacios en la contraseña):

```
[smtp.gmail.com]:587 jlp170617@gmail.com:XXXXXXXXXXXXXXXX
```

```bash
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd.db

echo "root: jlp170617@gmail.com" >> /etc/aliases
newaliases
systemctl restart postfix
```

### 7.4 Verificación

```bash
echo "Test backup Cyntia" | mail -s "Test Proxmox" jlp170617@gmail.com
```

---

## 8. Verificación final

```bash
# Cluster
pvecm status

# NFS
df -h | grep backup-nfs

# Contenedores
pct list

# Wazuh
pct exec 101 -- docker compose -f /opt/wazuh-docker/single-node/docker-compose.yml ps

# Backups en cyntia-backup
ssh -J root@100.92.243.96 root@192.168.3.101 "ls -lh /var/lib/vz/dump/"

# Cron
crontab -l
```

---

## Resumen de la infraestructura de backups

| Componente | Detalle |
| --- | --- |
| Nodo principal | cyntia - 192.168.3.100 - PVE 8.2.2 |
| Nodo backup | cyntia-backup - 192.168.3.101 - PVE 8.2.2 |
| Tailscale cyntia | 100.92.243.96 |
| Tailscale cyntia-backup | 100.106.127.17 |
| NFS mount | 192.168.3.101:/var/lib/vz/dump → /mnt/backup-nfs |
| vzdump schedule | 02:00 daily, retención 7 días |
| BorgBackup repo | /mnt/backup-nfs/borg |
| Script backup | /usr/local/bin/cyntia-backup.sh |
| Log backup | /var/log/cyntia-backup.log |
| Cron | 0 2 * * * |
| Email notificaciones | jlp170617@gmail.com |

[Guía de Recuperación y Migración de Backups](https://www.notion.so/Gu-a-de-Recuperaci-n-y-Migraci-n-de-Backups-33c4b40cb67980dfbc9cc4c5dbdc1814?pvs=21)
