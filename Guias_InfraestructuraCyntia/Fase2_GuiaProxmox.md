# Guía Proxmox - Fase 2

**Infraestructura fase 2: Docker, host OpenSearch, certificados SSL, LXC Docker, stack Wazuh, Tailscale, acceso dashboard Wazuh**

---

## 1. Verificación del estado de la fase 1

Antes de comenzar cualquier trabajo nuevo, verificamos que toda la infraestructura desplegada en la Semana 1 sigue operativa. Esto nos garantiza una base estable antes de añadir nuevas capas.

Desde el host de Proxmox, conectados por SSH via Tailscale (`ssh root@100.92.243.96`):

```bash
# Estado de todos los contenedores y la VM
pct list
qm list

# Interfaces VLAN activas
ip addr show vmbr0.10
ip addr show vmbr0.20
ip addr show vmbr0.50

# Servicios críticos del host
systemctl status nftables --no-pager
systemctl status fail2ban --no-pager
systemctl status tailscaled --no-pager
systemctl status pve-cluster --no-pager

# Conectividad entre contenedores y sus gateways
pct exec 100 -- ping -c 2 192.168.20.1
pct exec 101 -- ping -c 2 192.168.20.1
pct exec 102 -- ping -c 2 192.168.50.1
pct exec 103 -- ping -c 2 192.168.20.1
pct exec 104 -- ping -c 2 192.168.20.1

# DNS interno funcionando
pct exec 101 -- bash -c "nslookup soc.cyntia.local 192.168.20.2"

# Acceso a internet desde los contenedores
pct exec 101 -- ping -c 2 8.8.8.8
```

**Estado verificado:**

| Componente | Estado |
| --- | --- |
| 5 contenedores LXC | running |
| VM Windows Server 2022 | running |
| VLANs 10, 20, DMZ | activas con IPs correctas |
| nftables, fail2ban, Tailscale, pve-cluster | activos |
| Conectividad entre contenedores | 0% packet loss |
| DNS PiHole (cyntia.local) | resolviendo |
| Acceso a internet | operativo |

---

## 2. Instalación de Docker en lxc-soc-core

`lxc-soc-core` (VMID 101) es el contenedor Ubuntu 22.04 que alojará todo el stack SOC. Docker nos permite desplegar Wazuh y todos sus componentes de forma organizada, con dependencias y redes internas definidas en un único fichero `docker-compose.yml`.

Entramos en el contenedor:

```bash
pct exec 101 -- bash
```

Instalamos Docker desde el repositorio oficial de Docker Inc.:

```bash
apt-get update && apt-get upgrade -y
apt-get install -y ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg]\
  https://download.docker.com/linux/ubuntu\
$(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Configuramos el daemon de Docker para el entorno LXC:

```bash
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "no-new-privileges": false
}
EOF

systemctl restart docker
```

Verificamos la instalación:

```bash
docker --version
docker compose version
```

Salimos del contenedor antes del siguiente paso:

```bash
exit
```

---

## 3. Configuración del host para OpenSearch

OpenSearch (el motor de indexación de Wazuh) requiere que el parámetro `vm.max_map_count` del kernel esté configurado a un mínimo de 262144. Este ajuste se aplica en el **host de Proxmox**, y afecta a todos los contenedores que corren sobre él.

```bash
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
sysctl -w vm.max_map_count=262144
```

Añadirlo a `/etc/sysctl.conf` garantiza que el valor persiste tras reinicios del host.

---

## 4. Configuración del LXC para Docker

Los contenedores LXC no privilegiados tienen restricciones de seguridad que por defecto impiden que Docker funcione correctamente dentro de ellos. Configuramos el contenedor 101 con los parámetros necesarios:

```bash
pct stop 101

cat > /etc/pve/lxc/101.conf << 'EOF'
arch: amd64
cores: 2
features: nesting=1
hostname: lxc-soc-core
memory: 3072
nameserver: 192.168.20.2
net0: name=eth0,bridge=vmbr0,gw=192.168.20.1,hwaddr=BC:24:11:C3:E1:C5,ip=192.168.20.3/24,tag=20,type=veth
ostype: ubuntu
rootfs: local-lvm:vm-101-disk-1,size=60G
swap: 512
unprivileged: 1
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
EOF

pct start 101
sleep 5
```

Las líneas añadidas hacen lo siguiente:
- `lxc.apparmor.profile: unconfined` → permite que Docker gestione sus propios perfiles de seguridad sin interferencia del host
- `lxc.cgroup2.devices.allow: a` → da acceso completo a dispositivos via cgroups v2, necesario para Docker
- `lxc.cap.drop:` → no elimina capacidades del kernel, que Docker necesita para gestionar redes y namespaces

---

## 5. Despliegue del stack Wazuh

Entramos de nuevo en el contenedor:

```bash
pct exec 101 -- bash
```

### 5.1 Clonar el repositorio oficial de Wazuh

Clonamos la versión v4.9.2, que incluye todos los ficheros de configuración, scripts y el `docker-compose.yml` ya preparados:

```bash
apt-get install -y git
cd /opt
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2 --depth=1
cd wazuh-docker/single-node
```

### 5.2 Generar los certificados SSL

Wazuh usa SSL mutuo entre sus componentes internos. Este comando genera una CA raíz propia y firma todos los certificados necesarios (manager, indexer, dashboard):

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Verificamos que se generaron correctamente:

```bash
ls config/wazuh_indexer_ssl_certs/
```

Deben aparecer los ficheros `.pem` y `-key.pem` para cada componente.

### 5.3 Adaptar el compose para el entorno LXC

Añadimos `security_opt: apparmor:unconfined` a los tres servicios del compose para que Docker no intente cargar perfiles AppArmor del host:

```bash
python3 << 'EOF'
content = open('docker-compose.yml').read()
content = content.replace(
    '    restart: always\n    ulimits:',
    '    restart: always\n    security_opt:\n      - apparmor:unconfined\n    ulimits:'
)
content = content.replace(
    '    restart: always\n    ports:\n      - "9200:9200"',
    '    restart: always\n    security_opt:\n      - apparmor:unconfined\n    ports:\n      - "9200:9200"'
)
content = content.replace(
    '    restart: always\n    ports:\n      - 443:5601',
    '    restart: always\n    security_opt:\n      - apparmor:unconfined\n    ports:\n      - 443:5601'
)
open('docker-compose.yml', 'w').write(content)
print("OK")
EOF
```

Eliminamos los bloques `ulimits` que son incompatibles con LXC no privilegiado:

```bash
python3 << 'EOF'
import re
content = open('docker-compose.yml').read()
content = re.sub(
    r'    ulimits:\n      memlock:\n        soft: -1\n        hard: -1\n      nofile:\n        soft: \d+\n        hard: \d+\n',
    '',
    content
)
open('docker-compose.yml', 'w').write(content)
print("OK")
EOF
```

### 5.4 Arrancar el stack

```bash
docker compose up -d
```

Docker descarga las imágenes de los tres servicios (~2GB) y los arranca. Verificamos el estado:

```bash
docker compose ps
```

Los tres servicios deben aparecer en estado `Up`:

```
single-node-wazuh.manager-1    Up
single-node-wazuh.indexer-1    Up
single-node-wazuh.dashboard-1  Up
```

---

## 6. Port forwarding via Tailscale

Para acceder al dashboard de Wazuh (que escucha en el puerto 443 del contenedor 192.168.20.3) desde Tailscale, añadimos reglas de DNAT en nftables del host.

El fichero `/etc/nftables.conf` completo y definitivo queda así:

```bash
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        iifname "vmbr0" ip saddr 192.168.3.0/24 tcp dport 22 accept
        iifname "vmbr0" ip saddr 192.168.3.0/24 tcp dport 8006 accept
        iifname "tailscale0" tcp dport 22 accept
        iifname "tailscale0" tcp dport 8006 accept
        iifname "vmbr0.10" udp dport 1514 accept
        iifname "vmbr0.10" tcp dport 1514 accept
        iifname "vmbr0.50" tcp dport 1514 accept
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
        iifname "vmbr0.50" oifname "vmbr0.20" tcp dport 55000 accept
        iifname "vmbr0.50" oifname "vmbr0" accept
        iifname "vmbr0.50" oifname "vmbr0.20" udp dport 53 accept
        iifname "vmbr0.50" oifname "vmbr0.20" tcp dport 53 accept
        iifname "vmbr0.10" oifname "vmbr0.20" tcp dport 1514 accept
        iifname "vmbr0.10" oifname "vmbr0.20" udp dport 1514 accept
        iifname "vmbr0.10" oifname "vmbr0" accept
        iifname "vmbr0.20" oifname "vmbr0.10" accept
        iifname "vmbr0.20" oifname "vmbr0" accept
        iifname "tailscale0" oifname "vmbr0.20" accept
        iifname "tailscale0" oifname "vmbr0.10" accept
        iifname "tailscale0" oifname "vmbr0.50" accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        iifname "tailscale0" tcp dport 443 dnat to 192.168.20.3:443
        iifname "tailscale0" tcp dport 55000 dnat to 192.168.20.3:55000
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        ip saddr 192.168.50.0/24 oifname "vmbr0" masquerade
        ip saddr 192.168.10.0/24 oifname "vmbr0" masquerade
        ip saddr 192.168.20.0/24 oifname "vmbr0" masquerade
    }
}
EOF

systemctl restart nftables
```

> **Nota:** la tabla NAT usa la familia `ip` (no `inet`) porque la operación `dnat` solo está disponible en IPv4.
> 

---

## 7. Acceso al dashboard de Wazuh

El dashboard tarda 2-3 minutos en estar listo la primera vez, mientras OpenSearch inicializa sus índices internos. Acceder desde el navegador:

```
https://100.92.243.96
```

El navegador mostrará un aviso de certificado autofirmado. En Chrome escribid `thisisunsafe` directamente en la página. En Firefox: **Avanzado → Aceptar riesgo y continuar**.

---

## 8. Gestión de usuarios

### 8.1 Crear el usuario cyntia

Desde el dashboard de Wazuh, con sesión iniciada:

1. **☰ → Security → Internal Users**
2. Clic en **Create internal user**
3. Rellenad los campos:
    - **Username:** `cyntia`
    - **Password:** -
    - **Backend role:** `admin`
4. Clic en **Create**
5. Cerrad sesión y verificad el acceso con las nuevas credenciales

### 8.2 Deshabilitar el usuario admin

Para eliminar el riesgo que supone el usuario genérico `admin` con contraseña conocida, le asignamos un hash inválido que hace imposible autenticarse con él. Desde lxc-soc-core:

```bash
pct exec 101 -- bash
cd /opt/wazuh-docker/single-node

python3 << 'EOF'
content = open('config/wazuh_indexer/internal_users.yml').read()
content = content.replace(
    'admin:\n  hash: "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"\n  reserved: true',
    'admin:\n  hash: "$2y$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n  reserved: false'
)
open('config/wazuh_indexer/internal_users.yml', 'w').write(content)
print("OK")
EOF

docker compose down
docker compose up -d
```

Tras el reinicio (esperar 3 minutos), acceder con `cyntia` para confirmar que todo funciona correctamente.

---

## Resumen de credenciales finales

| Servicio | URL de acceso | Usuario |
| --- | --- | --- |
| Wazuh Dashboard (Tailscale) | https://100.92.243.96 | `cyntia` |
| Wazuh Dashboard (VLAN 20) | https://192.168.20.3 | `cyntia` |
| Wazuh API REST | https://192.168.20.3:55000 | `wazuh-wui` |
| admin | - | deshabilitado |

## Resumen del estado al finalizar la Fase 2

| Componente | Estado |
| --- | --- |
| Docker Engine v29.3.0 en lxc-soc-core | ✅ |
| Wazuh Manager 4.9.2 | ✅ corriendo |
| Wazuh Indexer 4.9.2 (OpenSearch) | ✅ corriendo |
| Wazuh Dashboard 4.9.2 | ✅ accesible via Tailscale |
| Certificados SSL mutuos entre componentes | ✅ |
| Usuario cyntia con rol admin | ✅ |
| Usuario admin deshabilitado | ✅ |
| nftables actualizado con DNAT para Wazuh | ✅ |
