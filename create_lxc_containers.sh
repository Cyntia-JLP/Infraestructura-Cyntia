#!/bin/bash
# =============================================================================
# Cyntia - Script de creacion de contenedores LXC
# Ejecutar desde el host Proxmox como root
# =============================================================================

set -e

echo "=== Cyntia - Creacion de contenedores LXC ==="
echo ""

# -----------------------------------------------------------------------------
# Verificar que las plantillas existen
# -----------------------------------------------------------------------------
echo "[*] Verificando plantillas..."

DEBIAN_TPL="local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst"
UBUNTU_TPL="local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst"

if ! pveam list local | grep -q "debian-12-standard_12.12"; then
    echo "[!] Descargando plantilla Debian 12..."
    pveam download local debian-12-standard_12.12-1_amd64.tar.zst
fi

if ! pveam list local | grep -q "ubuntu-22.04-standard"; then
    echo "[!] Descargando plantilla Ubuntu 22.04..."
    pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst
fi

echo "[+] Plantillas verificadas"
echo ""

# -----------------------------------------------------------------------------
# LXC 100 - lxc-pihole (DNS interno, VLAN 20)
# -----------------------------------------------------------------------------
echo "[*] Creando lxc-pihole (100)..."
pct create 100 $DEBIAN_TPL \
  --hostname lxc-pihole \
  --memory 128 \
  --cores 1 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.2/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
echo "[+] lxc-pihole creado"

# -----------------------------------------------------------------------------
# LXC 101 - lxc-soc-core (Stack SOC completo, VLAN 20)
# Requiere nesting=1 para poder correr Docker dentro
# -----------------------------------------------------------------------------
echo "[*] Creando lxc-soc-core (101)..."
pct create 101 $UBUNTU_TPL \
  --hostname lxc-soc-core \
  --memory 3072 \
  --cores 2 \
  --rootfs local-lvm:60 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.3/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
echo "[+] lxc-soc-core creado"

# -----------------------------------------------------------------------------
# LXC 102 - lxc-web-cyntia (Portal web, DMZ)
# Unico contenedor en la DMZ (tag=50)
# -----------------------------------------------------------------------------
echo "[*] Creando lxc-web-cyntia (102)..."
pct create 102 $DEBIAN_TPL \
  --hostname lxc-web-cyntia \
  --memory 512 \
  --cores 1 \
  --rootfs local-lvm:25 \
  --net0 name=eth0,bridge=vmbr0,tag=50,ip=192.168.50.2/24,gw=192.168.50.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
echo "[+] lxc-web-cyntia creado"

# -----------------------------------------------------------------------------
# LXC 103 - lxc-honeypot (OpenCanary honeypots, VLAN 20)
# -----------------------------------------------------------------------------
echo "[*] Creando lxc-honeypot (103)..."
pct create 103 $DEBIAN_TPL \
  --hostname lxc-honeypot \
  --memory 256 \
  --cores 1 \
  --rootfs local-lvm:10 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.4/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
echo "[+] lxc-honeypot creado"

# -----------------------------------------------------------------------------
# LXC 104 - lxc-backup (BorgBackup, VLAN 20)
# -----------------------------------------------------------------------------
echo "[*] Creando lxc-backup (104)..."
pct create 104 $DEBIAN_TPL \
  --hostname lxc-backup \
  --memory 256 \
  --cores 1 \
  --rootfs local-lvm:60 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.5/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
echo "[+] lxc-backup creado"

# -----------------------------------------------------------------------------
# Establecer contrasenas
# Usar comillas simples para evitar interpretacion de caracteres especiales
# -----------------------------------------------------------------------------
echo ""
echo "[*] Estableciendo contrasenas..."
echo 'root:Ph!H0le#Cyn7ia$2026'  | pct exec 100 -- chpasswd
echo 'root:S0cC0re#Cyn7ia$2026'  | pct exec 101 -- chpasswd
echo 'root:W3bCyn7ia#DMZ$2026'   | pct exec 102 -- chpasswd
echo 'root:H0n3yP0t#Cyn7ia$2026' | pct exec 103 -- chpasswd
echo 'root:B4ckUp#Cyn7ia$2026'   | pct exec 104 -- chpasswd
echo "[+] Contrasenas establecidas"

# -----------------------------------------------------------------------------
# DNS temporal mientras PiHole no esta configurado
# -----------------------------------------------------------------------------
echo ""
echo "[*] Configurando DNS temporal (1.1.1.1)..."
pct exec 101 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 102 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 103 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 104 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
echo "[+] DNS temporal configurado"

# -----------------------------------------------------------------------------
# Verificacion final
# -----------------------------------------------------------------------------
echo ""
echo "=== Estado final de los contenedores ==="
pct list
echo ""
echo "=== Verificacion de conectividad ==="
echo "[*] Probando ping al gateway desde cada contenedor..."
pct exec 100 -- ping -c 1 -W 2 192.168.20.1 > /dev/null 2>&1 && echo "[+] lxc-pihole (100) OK" || echo "[!] lxc-pihole (100) FALLO"
pct exec 101 -- ping -c 1 -W 2 192.168.20.1 > /dev/null 2>&1 && echo "[+] lxc-soc-core (101) OK" || echo "[!] lxc-soc-core (101) FALLO"
pct exec 102 -- ping -c 1 -W 2 192.168.50.1 > /dev/null 2>&1 && echo "[+] lxc-web-cyntia (102) OK" || echo "[!] lxc-web-cyntia (102) FALLO"
pct exec 103 -- ping -c 1 -W 2 192.168.20.1 > /dev/null 2>&1 && echo "[+] lxc-honeypot (103) OK" || echo "[!] lxc-honeypot (103) FALLO"
pct exec 104 -- ping -c 1 -W 2 192.168.20.1 > /dev/null 2>&1 && echo "[+] lxc-backup (104) OK" || echo "[!] lxc-backup (104) FALLO"

echo ""
echo "=== Creacion de contenedores completada ==="
echo "Recuerda: una vez PiHole este configurado, ejecutar update_dns.sh"
