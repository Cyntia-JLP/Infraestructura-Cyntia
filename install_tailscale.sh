#!/bin/bash
# =============================================================================
# Cyntia - Instalacion de Tailscale en el host Proxmox
# Ejecutar desde el host Proxmox como root
# =============================================================================

set -e

echo "=== Instalacion de Tailscale en Proxmox ==="
echo ""

# -----------------------------------------------------------------------------
# Anadir repositorio oficial de Tailscale para Debian Bookworm
# -----------------------------------------------------------------------------
echo "[*] Anadiendo repositorio de Tailscale..."
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | \
    tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | \
    tee /etc/apt/sources.list.d/tailscale.list
echo "[+] Repositorio anadido"

# -----------------------------------------------------------------------------
# Instalar Tailscale
# -----------------------------------------------------------------------------
echo "[*] Instalando Tailscale..."
apt-get update -qq
apt-get install tailscale -y > /dev/null 2>&1
echo "[+] Tailscale instalado"

# -----------------------------------------------------------------------------
# Habilitar e iniciar el servicio
# -----------------------------------------------------------------------------
echo "[*] Habilitando servicio tailscaled..."
systemctl enable --now tailscaled
echo "[+] Servicio habilitado"

# -----------------------------------------------------------------------------
# Autenticar con Tailscale
# -----------------------------------------------------------------------------
echo ""
echo "=== Autenticacion requerida ==="
echo "[*] Iniciando autenticacion con Tailscale..."
echo ""
echo "Se abrira un enlace de autenticacion. Abrelo en el navegador"
echo "e inicia sesion con la cuenta del proyecto: jlp170617@gmail.com"
echo ""
tailscale up

# -----------------------------------------------------------------------------
# Mostrar IP asignada
# -----------------------------------------------------------------------------
echo ""
echo "=== Informacion de Tailscale ==="
echo "[+] IP Tailscale asignada:"
tailscale ip -4
echo ""
echo "Puedes conectarte desde cualquier lugar con:"
echo "  ssh root@\$(tailscale ip -4)"
echo "  https://\$(tailscale ip -4):8006"
echo ""
echo "RECUERDA: Instala Tailscale tambien en tus PCs del equipo"
echo "  Windows: https://tailscale.com/download/windows"
echo "  Linux:   curl -fsSL https://tailscale.com/install.sh | sh"
