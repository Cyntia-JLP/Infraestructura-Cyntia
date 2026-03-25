#!/bin/bash
# =============================================================================
# Cyntia - Creacion de VM Windows Server 2022
# Ejecutar desde el host Proxmox como root
# REQUISITOS:
#   - ISO de Windows Server 2022 subida en: local:iso/SERVER_EVAL_x64FRE_es-es.iso
#   - ISO de drivers VirtIO descargada (se descarga automaticamente si no existe)
# =============================================================================

set -e

WINDOWS_ISO="local:iso/SERVER_EVAL_x64FRE_es-es.iso"
VIRTIO_ISO="local:iso/virtio-win.iso"
VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
VIRTIO_PATH="/var/lib/vz/template/iso/virtio-win.iso"

echo "=== Cyntia - Creacion de VM Windows Server 2022 ==="
echo ""

# -----------------------------------------------------------------------------
# Verificar ISO de Windows
# -----------------------------------------------------------------------------
echo "[*] Verificando ISO de Windows Server 2022..."
if ! ls /var/lib/vz/template/iso/SERVER_EVAL_x64FRE_es-es.iso > /dev/null 2>&1; then
    echo "[!] ERROR: ISO de Windows no encontrada"
    echo "[!] Sube la ISO desde la WebUI: local (cyntia) -> ISO Images -> Upload"
    echo "[!] Descarga la ISO de evaluacion gratuita en:"
    echo "    https://www.microsoft.com/es-es/evalcenter/evaluate-windows-server-2022"
    exit 1
fi
echo "[+] ISO de Windows encontrada"

# -----------------------------------------------------------------------------
# Descargar ISO de drivers VirtIO si no existe
# -----------------------------------------------------------------------------
echo "[*] Verificando ISO de drivers VirtIO..."
if [ ! -f "$VIRTIO_PATH" ]; then
    echo "[*] Descargando drivers VirtIO (~600 MB)..."
    wget -q --show-progress -O "$VIRTIO_PATH" "$VIRTIO_URL"
    echo "[+] Drivers VirtIO descargados"
else
    echo "[+] Drivers VirtIO ya existen"
fi

# -----------------------------------------------------------------------------
# Crear la VM
# -----------------------------------------------------------------------------
echo "[*] Creando VM vm-windows-ad (200)..."
qm create 200 \
  --name vm-windows-ad \
  --memory 2048 \
  --cores 2 \
  --sockets 1 \
  --cdrom $WINDOWS_ISO \
  --scsi0 local-lvm:60 \
  --scsihw virtio-scsi-pci \
  --boot order=ide2 \
  --ostype win11 \
  --net0 virtio,bridge=vmbr0,tag=10 \
  --vga std \
  --machine q35 \
  --bios seabios
echo "[+] VM creada"

# Anadir ISO de VirtIO como segundo CDROM
echo "[*] Anadiendo ISO de drivers VirtIO como segundo CDROM..."
qm set 200 --ide3 $VIRTIO_ISO,media=cdrom
echo "[+] CDROM VirtIO anadido"

# -----------------------------------------------------------------------------
# Verificacion
# -----------------------------------------------------------------------------
echo ""
echo "=== Configuracion de la VM ==="
qm config 200
echo ""
echo "=== VM creada correctamente ==="
echo ""
echo "PROXIMOS PASOS:"
echo "1. Abrir la WebUI: https://192.168.3.100:8006"
echo "2. Ir a vm-windows-ad (200) -> Console -> Start"
echo "3. En la instalacion seleccionar:"
echo "   - Windows Server 2022 Standard (experiencia de escritorio)"
echo "   - Instalacion Personalizada"
echo "4. Si no aparece el disco, cargar driver VirtIO:"
echo "   - Cargar contr. -> Examinar -> D:\\vioscsi\\amd64\\2k22"
echo "5. Contrasena del Administrador: Adm!n#Cyntia2026"
