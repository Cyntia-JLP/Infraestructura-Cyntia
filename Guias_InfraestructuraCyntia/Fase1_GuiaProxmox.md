# Guía Proxmox - Fase 1

**Infraestructura base: Proxmox, VLANs, nftables, Tailscale, fail2ban, LXC, Windows Server y PiHole**

---

## 1. Proxmox VE 8 - Configuración inicial

Proxmox VE 8 es el hipervisor base del proyecto, instalado directamente sobre el hardware físico. Una vez instalado, lo primero es ajustar la IP a la red del taller y reparar el servicio de cluster para tener acceso a la WebUI.

### 1.1 Configurar la red

Editar el fichero de interfaces desde la consola física del equipo:

```bash
nano /etc/network/interfaces
```

```bash
auto lo
iface lo inet loopback

auto enp3s0
iface enp3s0 inet manual

auto vmbr0
iface vmbr0 inet static
        address 192.168.3.100/24
        gateway 192.168.3.1
        bridge-ports enp3s0
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
```

Editar el fichero hosts:

```bash
nano /etc/hosts
```

```bash
127.0.0.1       localhost
192.168.3.100   proxmox.cyntia.local proxmox
```

Aplicar cambios:

```bash
systemctl restart networking
```

### 1.2 Arrancar pve-cluster y regenerar certificados

Proxmox necesita el servicio `pve-cluster` activo para gestionar la WebUI y los certificados SSL:

```bash
systemctl start pve-cluster
systemctl enable pve-cluster
pvecm updatecerts --force
systemctl restart pveproxy
```

### 1.3 Cambiar contraseña de root

```bash
passwd root
```

Por motivos de seguridad.

### 1.4 Acceder a la WebUI

```
https://192.168.3.100:8006
```

> El navegador mostrará aviso de certificado autofirmado. Avanzado > Aceptar el riesgo.
> 

### 1.5 Cambiar el hostname

```bash
hostnamectl set-hostname cyntia
```

Si aparece un nodo antiguo en la WebUI, eliminarlo:

```bash
rm -rf /etc/pve/nodes/NOMBRE_ANTIGUO
systemctl restart pve-cluster
systemctl restart pveproxy
```

---

## 2. Red y VLANs

La red interna del proyecto se divide en tres zonas lógicas sobre un único bridge `vmbr0` con etiquetado 802.1Q. Cada zona tiene un nivel de acceso diferente según su función.

| VLAN | Subred | Función |
| --- | --- | --- |
| DMZ | 192.168.50.0/24 | Portal web, único punto expuesto a internet |
| VLAN 10 | 192.168.10.0/24 | Entorno Windows con Active Directory |
| VLAN 20 | 192.168.20.0/24 | SOC core - zona más protegida |

### 2.1 Añadir las VLANs al fichero de red

```bash
nano /etc/network/interfaces
```

Añadir al final del fichero existente:

```bash
# DMZ - Portal web
auto vmbr0.50
iface vmbr0.50 inet static
        address 192.168.50.1/24

# VLAN 10 - Producción (Windows AD)
auto vmbr0.10
iface vmbr0.10 inet static
        address 192.168.10.1/24

# VLAN 20 - SOC
auto vmbr0.20
iface vmbr0.20 inet static
        address 192.168.20.1/24
```

Aplicar:

```bash
systemctl restart networking
```

### 2.2 Activar IP forwarding

```bash
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
```

### 2.3 Verificar interfaces

```bash
ip addr show vmbr0.10
ip addr show vmbr0.20
ip addr show vmbr0.50
```

Las tres deben aparecer como `UP` con sus IPs asignadas.

---

## 3. nftables - Firewall y segmentación

nftables es el sistema de cortafuegos integrado en el kernel de Linux. Controla qué tráfico puede circular entre las zonas del proyecto, aplica NAT y protege el acceso administrativo. Corre directamente en el kernel sin consumir RAM adicional.

```bash
nano /etc/nftables.conf
```

Contenido completo:

```bash
#!/usr/sbin/nft -f
flush ruleset

table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Red del taller
        iifname "vmbr0" ip saddr 192.168.3.0/24 tcp dport 22 accept
        iifname "vmbr0" ip saddr 192.168.3.0/24 tcp dport 8006 accept

        # Tailscale
        iifname "tailscale0" tcp dport 22 accept
        iifname "tailscale0" tcp dport 8006 accept

        # Wazuh logs
        iifname "vmbr0.10" udp dport 1514 accept
        iifname "vmbr0.10" tcp dport 1514 accept
        iifname "vmbr0.50" tcp dport 1514 accept

        # DNS PiHole
        iifname "vmbr0.10" udp dport 53 accept
        iifname "vmbr0.10" tcp dport 53 accept
        iifname "vmbr0.20" udp dport 53 accept
        iifname "vmbr0.20" tcp dport 53 accept
        iifname "vmbr0.50" udp dport 53 accept
        iifname "vmbr0.50" tcp dport 53 accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        ct state established,related accept

        # DMZ → VLAN 20: API Wazuh y DNS
        iifname "vmbr0.50" oifname "vmbr0.20" tcp dport 55000 accept
        iifname "vmbr0.50" oifname "vmbr0.20" udp dport 53 accept
        iifname "vmbr0.50" oifname "vmbr0.20" tcp dport 53 accept

        # DMZ → internet
        iifname "vmbr0.50" oifname "vmbr0" accept

        # VLAN 10 → VLAN 20: logs Wazuh
        iifname "vmbr0.10" oifname "vmbr0.20" tcp dport 1514 accept
        iifname "vmbr0.10" oifname "vmbr0.20" udp dport 1514 accept

        # VLAN 10 → internet
        iifname "vmbr0.10" oifname "vmbr0" accept

        # VLAN 20 → VLAN 10: playbooks
        iifname "vmbr0.20" oifname "vmbr0.10" accept

        # VLAN 20 → internet
        iifname "vmbr0.20" oifname "vmbr0" accept

        # Tailscale → todas las VLANs
        iifname "tailscale0" oifname "vmbr0.20" accept
        iifname "tailscale0" oifname "vmbr0.10" accept
        iifname "tailscale0" oifname "vmbr0.50" accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table inet nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        ip saddr 192.168.50.0/24 oifname "vmbr0" masquerade
        ip saddr 192.168.10.0/24 oifname "vmbr0" masquerade
        ip saddr 192.168.20.0/24 oifname "vmbr0" masquerade
    }
}
```

Habilitar y aplicar:

```bash
systemctl enable nftables
systemctl restart nftables
```

---

## 4. Tailscale - Acceso remoto seguro

Tailscale crea una VPN mesh cifrada con WireGuard entre los dispositivos del equipo y el servidor. Permite administrar Proxmox desde cualquier lugar sin abrir puertos en el router del instituto.

### 4.1 Instalar en el servidor

```bash
curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg | \
  tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.tailscale-keyring.list | \
  tee /etc/apt/sources.list.d/tailscale.list

apt-get update
apt-get install tailscale -y
systemctl enable --now tailscaled
tailscale up
```

Abrir el enlace que muestra en el navegador y autenticarse con la cuenta.

### 4.2 Verificar IP asignada

```bash
tailscale ip -4
```

IP del proyecto: `100.92.243.96`.

### 4.3 Instalar en los PCs del equipo (Windows)

Descargar desde `https://tailscale.com/download/windows`, instalar y autenticarse con la misma cuenta.

### 4.4 Conectarse remotamente

```bash
# SSH
ssh root@100.92.243.96

# WebUI Proxmox
https://100.92.243.96:8006
```

---

## 5. fail2ban - Protección SSH

fail2ban monitoriza los logs del sistema y bloquea automáticamente las IPs que superen el número máximo de intentos fallidos de acceso. Protege contra ataques de fuerza bruta en SSH.

### 5.1 Instalar

```bash
apt-get install fail2ban -y
```

### 5.2 Configurar

```bash
nano /etc/fail2ban/jail.local
```

```bash
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
backend = systemd
maxretry = 3
```

### 5.3 Activar

```bash
systemctl enable fail2ban
systemctl start fail2ban
```

### 5.4 Verificar

```bash
fail2ban-client status
fail2ban-client status sshd
```

---

## 6. Plantillas LXC

Las plantillas son imágenes base que Proxmox usa para crear contenedores. Se descargan una vez y se reutilizan para crear múltiples contenedores.

```bash
pveam update
pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst
pveam download local debian-12-standard_12.12-1_amd64.tar.zst
```

Verificar:

```bash
pveam list local
```

---

## 7. Contenedores LXC

Los contenedores LXC comparten el kernel del host y consumen entre 300-500 MB menos de RAM por instancia que una VM equivalente. Se usan para todos los servicios excepto Windows Server.

### 7.1 Crear los contenedores

**lxc-pihole (100) - DNS interno**

```bash
pct create 100 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname lxc-pihole \
  --memory 128 \
  --cores 1 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.2/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
```

**lxc-soc-core (101) - Stack SOC completo**

```bash
pct create 101 local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst \
  --hostname lxc-soc-core \
  --memory 3072 \
  --cores 2 \
  --rootfs local-lvm:60 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.3/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
```

**lxc-web-cyntia (102) - Portal web en DMZ**

```bash
pct create 102 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname lxc-web-cyntia \
  --memory 512 \
  --cores 1 \
  --rootfs local-lvm:25 \
  --net0 name=eth0,bridge=vmbr0,tag=50,ip=192.168.50.2/24,gw=192.168.50.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
```

**lxc-honeypot (103) - Honeypots OpenCanary**

```bash
pct create 103 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname lxc-honeypot \
  --memory 256 \
  --cores 1 \
  --rootfs local-lvm:10 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.4/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
```

**lxc-backup (104) - Backups BorgBackup**

```bash
pct create 104 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname lxc-backup \
  --memory 256 \
  --cores 1 \
  --rootfs local-lvm:60 \
  --net0 name=eth0,bridge=vmbr0,tag=20,ip=192.168.20.5/24,gw=192.168.20.1 \
  --nameserver 1.1.1.1 \
  --unprivileged 1 \
  --start 1
```

### 7.2 Establecer contraseñas

```bash
echo 'root:-'  | pct exec 100 -- chpasswd
echo 'root:-'  | pct exec 101 -- chpasswd
echo 'root:-'   | pct exec 102 -- chpasswd
echo 'root:-' | pct exec 103 -- chpasswd
echo 'root:-'   | pct exec 104 -- chpasswd
```

### 7.3 DNS temporal

Mientras PiHole no esté configurado:

```bash
pct exec 101 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 102 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 103 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 104 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
```

---

## 8. VM Windows Server 2022

Windows Server requiere virtualización completa KVM al ser incompatible con el kernel Linux. Se usa para simular el entorno empresarial con Active Directory.

### 8.1 Obtener las ISOs

**Windows Server 2022** (evaluación gratuita 180 días):

```
https://www.microsoft.com/es-es/evalcenter/evaluate-windows-server-2022
```

Seleccionar ISO en Español 64 bits (~4.7 GB) y subirla desde la WebUI: `local (cyntia) → ISO Images → Upload`.

**Drivers VirtIO** (necesarios para que Windows detecte el disco):

```bash
wget -O /var/lib/vz/template/iso/virtio-win.iso \
  https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
```

### 8.2 Crear la VM

```bash
qm create 200 \
  --name vm-windows-ad \
  --memory 2048 \
  --cores 2 \
  --sockets 1 \
  --cdrom local:iso/SERVER_EVAL_x64FRE_es-es.iso \
  --scsi0 local-lvm:60 \
  --scsihw virtio-scsi-pci \
  --boot order=ide2 \
  --ostype win11 \
  --net0 virtio,bridge=vmbr0,tag=10 \
  --vga std \
  --machine q35 \
  --bios seabios

qm set 200 --ide3 local:iso/virtio-win.iso,media=cdrom
```

### 8.3 Instalar Windows

Desde la WebUI: `vm-windows-ad (200) → Console → Start`

Durante la instalación:
1. Seleccionar **Windows Server 2022 Standard Evaluation (experiencia de escritorio)**
2. Instalación **Personalizada**
3. En la pantalla de disco: clic en **Cargar contr. → Examinar**
4. Navegar al CDROM VirtIO: `D:\vioscsi\amd64\2k22`
5. Seleccionar **Red Hat VirtIO SCSI controller → Siguiente**
6. Seleccionar el disco de 60 GB y continuar

Al finalizar, establecer contraseña del Administrador.

### 8.4 Limpieza post-instalación

```bash
qm set 200 --delete unused0
```

---

## 9. PiHole — DNS interno

PiHole actúa como servidor DNS interno del entorno. Resuelve los subdominios del dominio `cyntia.local` para que todos los sistemas se comuniquen por nombre en lugar de por IP.

### 9.1 Preparar el contenedor

```bash
pct exec 100 -- bash
apt-get update && apt-get install curl -y
```

Configurar IP estática dentro del contenedor:

```bash
nano /etc/network/interfaces
```

```bash
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.20.2
    netmask 255.255.255.0
    gateway 192.168.20.1
```

```bash
systemctl restart networking
```

### 9.2 Instalar PiHole

Crear fichero de configuración previa para instalación desatendida:

```bash
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
```

Lanzar instalador:

```bash
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
```

### 9.3 Configurar contraseña del panel web

```bash
export PATH=$PATH:/usr/local/bin
pihole setpassword
```

### 9.4 Añadir registros DNS locales

```bash
cat >> /etc/pihole/hosts << 'EOF'
192.168.20.2 pihole.cyntia.local
192.168.20.3 soc.cyntia.local
192.168.20.3 grafana.cyntia.local
192.168.50.2 app.cyntia.local
EOF

systemctl restart pihole-FTL
```

### 9.5 Salir y actualizar DNS en todos los contenedores

```bash
exit

pct exec 101 -- bash -c "echo 'nameserver 192.168.20.2' > /etc/resolv.conf"
pct exec 102 -- bash -c "echo 'nameserver 192.168.20.2' > /etc/resolv.conf"
pct exec 103 -- bash -c "echo 'nameserver 192.168.20.2' > /etc/resolv.conf"
pct exec 104 -- bash -c "echo 'nameserver 192.168.20.2' > /etc/resolv.conf"
```

---

## 10. Verificación final

### Comprobar todos los servicios del host

```bash
systemctl status pve-cluster
systemctl status pveproxy
systemctl status nftables
systemctl status tailscaled
systemctl status fail2ban
```

### Comprobar todos los contenedores

```bash
pct list
```

Resultado esperado:

```
VMID  Status    Name
100   running   lxc-pihole
101   running   lxc-soc-core
102   running   lxc-web-cyntia
103   running   lxc-honeypot
104   running   lxc-backup
```

### Comprobar conectividad de red

```bash
pct exec 100 -- ping -c 2 192.168.20.1
pct exec 101 -- ping -c 2 192.168.20.1
pct exec 102 -- ping -c 2 192.168.50.1
pct exec 103 -- ping -c 2 192.168.20.1
pct exec 104 -- ping -c 2 192.168.20.1
```

### Comprobar internet desde contenedores

```bash
pct exec 100 -- ping -c 2 8.8.8.8
pct exec 101 -- ping -c 2 8.8.8.8
```

### Comprobar resolución DNS

```bash
pct exec 101 -- bash -c "nslookup soc.cyntia.local 192.168.20.2"
pct exec 101 -- bash -c "nslookup grafana.cyntia.local 192.168.20.2"
pct exec 102 -- bash -c "nslookup app.cyntia.local 192.168.20.2"
```

### Comprobar acceso Tailscale

```bash
ssh root@100.92.243.96
```

---

## Resumen de la infraestructura completada

| Componente | Detalle |
| --- | --- |
| Proxmox VE 8 | 192.168.3.100 / 100.92.243.96 (Tailscale) |
| VLAN DMZ | 192.168.50.0/24 |
| VLAN 10 Producción | 192.168.10.0/24 |
| VLAN 20 SOC | 192.168.20.0/24 |
| nftables | Segmentación completa + NAT |
| Tailscale | 100.92.243.96 |
| fail2ban | SSH protegido |
| lxc-pihole (100) | 192.168.20.2 |
| lxc-soc-core (101) | 192.168.20.3 |
| lxc-web-cyntia (102) | 192.168.50.2 |
| lxc-honeypot (103) | 192.168.20.4 |
| lxc-backup (104) | 192.168.20.5 |
| vm-windows-ad (200) | 192.168.10.10 (pendiente AD) |
| PiHole DNS | cyntia.local resolviendo |
