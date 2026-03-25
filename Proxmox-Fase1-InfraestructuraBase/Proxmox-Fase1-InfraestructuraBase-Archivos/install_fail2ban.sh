#!/bin/bash
# =============================================================================
# Cyntia - Instalacion y configuracion de fail2ban en el host Proxmox
# Ejecutar desde el host Proxmox como root
# =============================================================================

set -e

echo "=== Instalacion de fail2ban ==="
echo ""

# -----------------------------------------------------------------------------
# Instalar fail2ban
# -----------------------------------------------------------------------------
echo "[*] Instalando fail2ban..."
apt-get update -qq
apt-get install fail2ban -y > /dev/null 2>&1
echo "[+] fail2ban instalado"

# -----------------------------------------------------------------------------
# Crear configuracion
# IMPORTANTE: usar backend=systemd porque Debian 12 no usa /var/log/auth.log
# -----------------------------------------------------------------------------
echo "[*] Creando configuracion..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Tiempo que la IP permanece baneada
bantime = 1h

# Ventana de tiempo para contar fallos
findtime = 10m

# Numero de fallos permitidos antes de banear
maxretry = 5

[sshd]
enabled = true
port = ssh
# Usar systemd porque Debian 12 no tiene /var/log/auth.log
backend = systemd
maxretry = 3
EOF
echo "[+] Configuracion creada"

# -----------------------------------------------------------------------------
# Habilitar e iniciar
# -----------------------------------------------------------------------------
echo "[*] Habilitando servicio..."
systemctl enable fail2ban
systemctl start fail2ban
echo "[+] Servicio habilitado e iniciado"

# -----------------------------------------------------------------------------
# Verificacion
# -----------------------------------------------------------------------------
echo ""
echo "=== Verificacion ==="
systemctl is-active fail2ban > /dev/null 2>&1 && echo "[+] fail2ban: activo" || echo "[!] fail2ban: INACTIVO"
echo ""
echo "Estado de las jails:"
fail2ban-client status
echo ""
echo "Estado de la jail sshd:"
fail2ban-client status sshd
