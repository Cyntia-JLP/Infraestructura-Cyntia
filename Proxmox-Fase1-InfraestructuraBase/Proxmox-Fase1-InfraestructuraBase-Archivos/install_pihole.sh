#!/bin/bash
# =============================================================================
# Cyntia - Instalacion de PiHole en lxc-pihole (100)
# Ejecutar DENTRO del contenedor lxc-pihole
# Acceso: pct exec 100 -- bash, luego ejecutar este script
# =============================================================================

set -e

echo "=== Instalacion de PiHole en lxc-pihole ==="
echo ""

# -----------------------------------------------------------------------------
# Instalar dependencias
# -----------------------------------------------------------------------------
echo "[*] Instalando dependencias..."
apt-get update -qq
apt-get install -y curl > /dev/null 2>&1
echo "[+] Dependencias instaladas"

# -----------------------------------------------------------------------------
# Configurar IP estatica (requerida por PiHole)
# -----------------------------------------------------------------------------
echo "[*] Configurando red estatica..."
cat > /etc/network/interfaces << 'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.20.2
    netmask 255.255.255.0
    gateway 192.168.20.1
EOF
systemctl restart networking
echo "[+] Red configurada: 192.168.20.2/24"

# -----------------------------------------------------------------------------
# Crear configuracion previa para instalacion desatendida
# -----------------------------------------------------------------------------
echo "[*] Creando configuracion previa de PiHole..."
mkdir -p /etc/pihole

cat > /etc/pihole/setupVars.conf << 'EOF'
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=192.168.20.2/24
IPV6_ADDRESS=
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=false
DNS_BOGUS_PRIV=false
DNSMASQ_LISTENING=all
WEBPASSWORD=
BLOCKING_ENABLED=true
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=8.8.8.8
EOF
echo "[+] Configuracion previa creada"

# -----------------------------------------------------------------------------
# Instalar PiHole en modo desatendido
# -----------------------------------------------------------------------------
echo "[*] Instalando PiHole (modo desatendido)..."
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
echo "[+] PiHole instalado"

# -----------------------------------------------------------------------------
# Anadir PATH para usar pihole desde la sesion actual
# -----------------------------------------------------------------------------
export PATH=$PATH:/usr/local/bin
echo 'export PATH=$PATH:/usr/local/bin' >> /root/.bashrc

# -----------------------------------------------------------------------------
# Anadir registros DNS locales del proyecto
# -----------------------------------------------------------------------------
echo "[*] Configurando registros DNS de cyntia.local..."
cat >> /etc/pihole/hosts << 'EOF'

# Registros DNS internos del proyecto Cyntia
192.168.20.2    pihole.cyntia.local
192.168.20.3    soc.cyntia.local
192.168.20.3    grafana.cyntia.local
192.168.50.2    app.cyntia.local
EOF

# Reiniciar FTL para aplicar los nuevos registros
systemctl restart pihole-FTL
echo "[+] Registros DNS configurados"

# -----------------------------------------------------------------------------
# Verificacion
# -----------------------------------------------------------------------------
echo ""
echo "=== Verificacion ==="
systemctl is-active pihole-FTL > /dev/null 2>&1 && echo "[+] pihole-FTL: activo" || echo "[!] pihole-FTL: INACTIVO"

echo ""
echo "=== Instalacion completada ==="
echo ""
echo "IMPORTANTE: Establece la contrasena del panel web con:"
echo "  pihole setpassword"
echo ""
echo "Panel web accesible en: http://192.168.20.2/admin"
echo "Una vez configurado, ejecuta update_dns_to_pihole.sh en el host Proxmox"
