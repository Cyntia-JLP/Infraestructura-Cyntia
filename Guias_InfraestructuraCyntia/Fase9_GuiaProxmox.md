# Guía Proxmox - Fase 9

**Infraestructura fase 9: Migración Windows AD a OpenLDAP + LAM**

---

## Por qué migramos de Windows Server a OpenLDAP

Windows Server 2022 consumía 2GB de RAM fijos en un sistema con 8GB totales. OpenLDAP consume únicamente 200-300MB, libera recursos críticos y encaja perfectamente con el stack Linux. Los playbooks de respuesta automática son más simples sin PowerShell.

El cliente simulado es **MedTrans Ibérica S.L.**, empresa de transporte sanitario de Valencia con plan Enterprise contratado con Cyntia SOC.

---

## Parte 1 — Eliminación de Windows Server

### Verificar estado y eliminar la VM

```bash
qm list
qm status 200
qm stop 200
qm destroy 200 --destroy-unreferenced-disks 1 --purge 1
```

Los flags `--destroy-unreferenced-disks 1` y `--purge 1` eliminan volúmenes LVM y referencias en Proxmox.

### Eliminar ISOs (5.5GB liberados)

```bash
rm /var/lib/vz/template/iso/SERVER_EVAL_x64FRE_es-es.iso
rm /var/lib/vz/template/iso/virtio-win.iso
```

### Eliminar agente Windows de Wazuh

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -r 001"
```

---

## Parte 2 — Creación de lxc-ldap

El contenedor se crea en VLAN10 (192.168.10.0/24), la misma red donde estaba Windows Server.

```bash
pct create 201 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname lxc-ldap \
  --memory 512 \
  --cores 1 \
  --rootfs local-lvm:10 \
  --net0 name=eth0,bridge=vmbr0,tag=10,ip=192.168.10.2/24,gw=192.168.10.1 \
  --nameserver 192.168.20.2 \
  --unprivileged 1 \
  --start 1
```

### Configuración inicial

```bash
echo 'root:-' | pct exec 201 -- chpasswd
pct exec 201 -- bash -c "echo 'nameserver 1.1.1.1' > /etc/resolv.conf"
pct exec 201 -- bash -c "apt-get update && apt-get upgrade -y"
```

### Añadir DNS en PiHole

```bash
pct exec 100 -- bash -c "echo '192.168.10.2 ldap.cyntia.local' >> /etc/pihole/hosts"
pct exec 100 -- bash -c "/usr/local/bin/pihole restartdns"
```

---

## Parte 3 — Instalación de OpenLDAP

### Instalar dependencias

```bash
pct exec 201 -- bash -c "apt-get install -y slapd ldap-utils curl gpg rsyslog"
```

### Configurar el dominio cyntia.local

```bash
pct exec 201 -- bash
```

Dentro del contenedor:

```bash
debconf-set-selections << CONF
slapd slapd/domain string cyntia.local
slapd shared/organization string Cyntia
slapd slapd/password1 password -
slapd slapd/password2 password -
slapd slapd/backend string MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
CONF
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure slapd
```

### Verificar instalación

```bash
slapcat | head -10
# Debe mostrar: dn: dc=cyntia,dc=local
```

---

## Parte 4 — Estructura del directorio

### Unidades organizativas base

```bash
cat > /tmp/estructura.ldif << 'EOF'
dn: ou=usuarios,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: usuarios

dn: ou=grupos,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: grupos

dn: ou=servicios,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: servicios
EOF

ldapadd -x -D "cn=admin,dc=cyntia,dc=local" -w '-' -f /tmp/estructura.ldif
```

### Estructura MedTrans Iberica S.L.

```bash
cat > /tmp/medtrans.ldif << 'EOF'
dn: ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: MedTrans
description: MedTrans Iberica S.L. - Cliente Plan Enterprise

dn: ou=direccion,ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: direccion

dn: ou=IT,ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: IT

dn: ou=RRHH,ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: RRHH

dn: ou=operaciones,ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: operaciones

dn: ou=grupos,ou=MedTrans,dc=cyntia,dc=local
objectClass: organizationalUnit
ou: grupos
EOF

ldapadd -x -D "cn=admin,dc=cyntia,dc=local" -w '-' -f /tmp/medtrans.ldif
```

---

## Parte 5 — Usuarios y grupos

### Generar hashes de contraseñas

```bash
PW_DIR=$(slappasswd -s '-')
PW_IT=$(slappasswd -s '-')
PW_RRHH=$(slappasswd -s '-')
PW_OPS=$(slappasswd -s '-')
PW_WAZUH=$(slappasswd -s '-')
```

### Crear los 8 usuarios y usuario de servicio

```bash
cat > /tmp/usuarios.ldif << EOF
dn: uid=jmartinez,ou=direccion,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jmartinez
cn: Jose Martinez
sn: Martinez
givenName: Jose
mail: jmartinez@medtrans.es
title: CEO
uidNumber: 2001
gidNumber: 2001
homeDirectory: /home/jmartinez
loginShell: /bin/bash
userPassword:$PW_DIR

dn: uid=lsanchez,ou=direccion,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: lsanchez
cn: Laura Sanchez
sn: Sanchez
givenName: Laura
mail: lsanchez@medtrans.es
title: CFO
uidNumber: 2002
gidNumber: 2001
homeDirectory: /home/lsanchez
loginShell: /bin/bash
userPassword:$PW_DIR

dn: uid=agarcia,ou=IT,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: agarcia
cn: Ana Garcia
sn: Garcia
givenName: Ana
mail: agarcia@medtrans.es
title: SysAdmin
uidNumber: 2003
gidNumber: 2002
homeDirectory: /home/agarcia
loginShell: /bin/bash
userPassword:$PW_IT

dn: uid=rlopez,ou=IT,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: rlopez
cn: Roberto Lopez
sn: Lopez
givenName: Roberto
mail: rlopez@medtrans.es
title: IT Support
uidNumber: 2004
gidNumber: 2002
homeDirectory: /home/rlopez
loginShell: /bin/bash
userPassword:$PW_IT

dn: uid=mfernandez,ou=RRHH,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: mfernandez
cn: Maria Fernandez
sn: Fernandez
givenName: Maria
mail: mfernandez@medtrans.es
title: RRHH Manager
uidNumber: 2005
gidNumber: 2003
homeDirectory: /home/mfernandez
loginShell: /bin/bash
userPassword:$PW_RRHH

dn: uid=cnavarro,ou=RRHH,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: cnavarro
cn: Carlos Navarro
sn: Navarro
givenName: Carlos
mail: cnavarro@medtrans.es
title: RRHH Tecnico
uidNumber: 2006
gidNumber: 2003
homeDirectory: /home/cnavarro
loginShell: /bin/bash
userPassword:$PW_RRHH

dn: uid=pmoreno,ou=operaciones,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pmoreno
cn: Pedro Moreno
sn: Moreno
givenName: Pedro
mail: pmoreno@medtrans.es
title: Jefe Operaciones
uidNumber: 2007
gidNumber: 2004
homeDirectory: /home/pmoreno
loginShell: /bin/bash
userPassword:$PW_OPS

dn: uid=ijimenez,ou=operaciones,ou=MedTrans,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ijimenez
cn: Isabel Jimenez
sn: Jimenez
givenName: Isabel
mail: ijimenez@medtrans.es
title: Logistica
uidNumber: 2008
gidNumber: 2004
homeDirectory: /home/ijimenez
loginShell: /bin/bash
userPassword:$PW_OPS

dn: uid=wazuh-reader,ou=servicios,dc=cyntia,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: wazuh-reader
cn: Wazuh Reader
sn: Reader
uidNumber: 3001
gidNumber: 3001
homeDirectory: /home/wazuh-reader
loginShell: /bin/false
userPassword:$PW_WAZUH
EOF

ldapadd -x -D "cn=admin,dc=cyntia,dc=local" -w '-' -f /tmp/usuarios.ldif
```

### Crear los 4 grupos

```bash
cat > /tmp/grupos.ldif << EOF
dn: cn=direccion,ou=grupos,ou=MedTrans,dc=cyntia,dc=local
objectClass: groupOfNames
cn: direccion
member: uid=jmartinez,ou=direccion,ou=MedTrans,dc=cyntia,dc=local
member: uid=lsanchez,ou=direccion,ou=MedTrans,dc=cyntia,dc=local

dn: cn=IT,ou=grupos,ou=MedTrans,dc=cyntia,dc=local
objectClass: groupOfNames
cn: IT
member: uid=agarcia,ou=IT,ou=MedTrans,dc=cyntia,dc=local
member: uid=rlopez,ou=IT,ou=MedTrans,dc=cyntia,dc=local

dn: cn=RRHH,ou=grupos,ou=MedTrans,dc=cyntia,dc=local
objectClass: groupOfNames
cn: RRHH
member: uid=mfernandez,ou=RRHH,ou=MedTrans,dc=cyntia,dc=local
member: uid=cnavarro,ou=RRHH,ou=MedTrans,dc=cyntia,dc=local

dn: cn=operaciones,ou=grupos,ou=MedTrans,dc=cyntia,dc=local
objectClass: groupOfNames
cn: operaciones
member: uid=pmoreno,ou=operaciones,ou=MedTrans,dc=cyntia,dc=local
member: uid=ijimenez,ou=operaciones,ou=MedTrans,dc=cyntia,dc=local
EOF

ldapadd -x -D "cn=admin,dc=cyntia,dc=local" -w '-' -f /tmp/grupos.ldif
```

### Verificar autenticación

```bash
ldapwhoami -x -D "uid=jmartinez,ou=direccion,ou=MedTrans,dc=cyntia,dc=local" -w '-'
```

---

## Parte 6 — LAM (LDAP Account Manager)

### Instalar y arrancar

```bash
pct exec 201 -- bash -c "apt-get install -y ldap-account-manager apache2 php php-ldap"
pct exec 201 -- bash -c "systemctl enable apache2 && systemctl start apache2"
```

### DNAT en nftables del host

Anadir en bloque `prerouting` de `/etc/nftables.conf`:

```
iifname "tailscale0" tcp dport 8080 dnat to 192.168.10.2:80
```

```bash
systemctl restart nftables
```

### Configuracion en la web

Acceder a `http://100.92.243.96:8080/lam/templates/config/index.php`

En **Edit server profiles:**

- Server address: `ldap://localhost:389`
- Tree suffix: `dc=cyntia,dc=local`
- Users suffix: `ou=MedTrans,dc=cyntia,dc=local`
- Groups suffix: `ou=grupos,ou=MedTrans,dc=cyntia,dc=local`
- Language: Español (España) / Time zone: Europe/Madrid

### Acceso

```
URL:       http://100.92.243.96:8080/lam
Usuario:   cn=admin,dc=cyntia,dc=local
Password:  -
Master pw: -
```

---

## Parte 7 — Integración con Wazuh

### Instalar agente 4.9.2

```bash
pct exec 201 -- bash -c "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list && apt-get update && apt-get install -y --allow-downgrades wazuh-agent=4.9.2-1"
```

### ossec.conf del agente

El agente apunta a 192.168.10.1 porque no puede llegar directamente a VLAN20.

```bash
pct exec 201 -- bash -c "cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>192.168.10.1</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>no</enabled>
    </enrollment>
  </client>
  <logging>
    <log_format>plain</log_format>
  </logging>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/slapd.log</location>
  </localfile>
</ossec_config>
EOF"
```

### Relays socat para VLAN10

```bash
cat > /etc/systemd/system/wazuh-relay-vlan10.service << 'EOF'
[Unit]
Description=Wazuh relay for VLAN10
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:1514,bind=192.168.10.1,fork TCP:192.168.20.3:21514
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/wazuh-relay-vlan10-enroll.service << 'EOF'
[Unit]
Description=Wazuh enrollment relay for VLAN10
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:1515,bind=192.168.10.1,fork TCP:192.168.20.3:21515
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wazuh-relay-vlan10 wazuh-relay-vlan10-enroll
systemctl start wazuh-relay-vlan10 wazuh-relay-vlan10-enroll
```

### Registrar agente con IP any

```bash
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -a any -n lxc-ldap"
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -e 006"
pct exec 201 -- bash -c "/var/ossec/bin/manage_agents -i CLAVE_BASE64"
pct exec 201 -- bash -c "/var/ossec/bin/wazuh-control restart"
sleep 30
pct exec 101 -- bash -c "docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
```

---

## Parte 8 — Auditoria y backup

### Habilitar logs OpenLDAP

```bash
pct exec 201 -- bash -c "echo 'loglevel 256' >> /etc/ldap/slapd.conf"
pct exec 201 -- bash -c "echo 'local4.* /var/log/slapd.log' > /etc/rsyslog.d/slapd.conf"
pct exec 201 -- bash -c "systemctl restart rsyslog && systemctl restart slapd"
```

### Anadir LDAP al backup nocturno

En `/usr/local/bin/cyntia-backup.sh`:

```bash
pct exec 201 -- bash -c "slapcat > /tmp/ldap-backup.ldif"
pct pull 201 /tmp/ldap-backup.ldif /mnt/backup-nfs/ldap-$DATE.ldif
pct exec 201 -- bash -c "rm -f /tmp/ldap-backup.ldif"
echo "LDAP backup: OK" >> $LOG
```

### Anadir lxc-ldap al arranque automatico

En `/usr/local/bin/cyntia-start.sh`, tras `pct start 104`:

```bash
pct start 201
sleep 5
```
