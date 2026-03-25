#!/bin/bash
# =============================================================================
# Cyntia - Actualizar DNS de todos los contenedores a PiHole
# Ejecutar desde el host Proxmox como root
# Ejecutar SOLO despues de que PiHole este correctamente configurado
# =============================================================================

PIHOLE_IP="192.168.20.2"

echo "=== Actualizando DNS a PiHole ($PIHOLE_IP) ==="
echo ""

# Verificar que PiHole responde antes de actualizar
echo "[*] Verificando que PiHole esta activo..."
if ! pct exec 100 -- bash -c "systemctl is-active pihole-FTL" > /dev/null 2>&1; then
    echo "[!] ERROR: PiHole no esta activo en lxc-pihole (100)"
    echo "[!] Configura PiHole antes de ejecutar este script"
    exit 1
fi
echo "[+] PiHole activo"

# Actualizar DNS en todos los contenedores
echo ""
echo "[*] Actualizando DNS en contenedores..."
for ID in 101 102 103 104; do
    pct exec $ID -- bash -c "echo 'nameserver $PIHOLE_IP' > /etc/resolv.conf"
    echo "[+] Contenedor $ID actualizado"
done

# Verificar resolucion DNS
echo ""
echo "=== Verificando resolucion DNS ==="
DOMINIOS=("soc.cyntia.local" "grafana.cyntia.local" "app.cyntia.local" "pihole.cyntia.local")

for DOMINIO in "${DOMINIOS[@]}"; do
    RESULTADO=$(pct exec 101 -- bash -c "nslookup $DOMINIO $PIHOLE_IP 2>/dev/null | grep 'Address:' | tail -1 | awk '{print \$2}'")
    if [ -n "$RESULTADO" ]; then
        echo "[+] $DOMINIO → $RESULTADO"
    else
        echo "[!] $DOMINIO → NO RESUELVE"
    fi
done

echo ""
echo "=== DNS actualizado correctamente ==="
