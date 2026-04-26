# COMANDO 1 — Ataque SSH al honeypot (genera alerta + Telegram notify)
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Conexion SSH al honeypot\"},\"agent\":{\"id\":\"003\",\"name\":\"lxc-honeypot\"},\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S)\",\"data\":{\"src_host\":\"192.168.10.2\",\"dst_host\":\"192.168.10.4\",\"dst_port\":\"2222\",\"srcip\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/notify_telegram.py"

# COMANDO 2 — block_ip manual (Telegram bloqueo)
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Conexion SSH al honeypot\"},\"agent\":{\"name\":\"lxc-honeypot\"},\"timestamp\":\"2026-04-26T18:00:00\",\"data\":{\"srcip\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/block_ip.py"

# COMANDO 3 — disable_ldap_user (dashboard cambia + Telegram)
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100202\",\"level\":15,\"description\":\"Intento de login SSH con credenciales en honeypot\"},\"agent\":{\"name\":\"lxc-ldap\"},\"timestamp\":\"2026-04-26T18:00:00\",\"data\":{\"srcip\":\"192.168.10.2\",\"dstuser\":\"agarcia\"}}}}' | python3 /var/ossec/active-response/bin/disable_ldap_user.py"

# COMANDO 4 — threat_intel (Telegram con score AbuseIPDB)
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100201\",\"level\":14,\"description\":\"Conexion SSH al honeypot\"},\"agent\":{\"name\":\"lxc-honeypot\"},\"timestamp\":\"2026-04-26T18:00:00\",\"data\":{\"srcip\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/threat_intel.py"

# COMANDO 5 — create_ticket (Telegram con ticket)
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "echo '{\"version\":1,\"command\":\"add\",\"parameters\":{\"alert\":{\"rule\":{\"id\":\"100203\",\"level\":15,\"description\":\"LOGIN SSH COMPLETADO EN HONEYPOT\"},\"agent\":{\"id\":\"003\",\"name\":\"lxc-honeypot\"},\"timestamp\":\"2026-04-26T18:00:00\",\"data\":{\"srcip\":\"185.220.101.1\",\"src_host\":\"185.220.101.1\"}}}}' | python3 /var/ossec/active-response/bin/create_ticket.py"

# LIMPIEZA POST-DEMO
pct exec 101 -- docker exec single-node-wazuh.manager-1 bash -c "python3 /var/ossec/active-response/bin/disable_ldap_user.py --enable agarcia"
nft flush set inet filter blocked_ips

# ____________________________________
# PRUEBA COMPLETA CON SCRIPT DEMO
# ____________________________________

# Probar limpieza
bash /root/limpieza.sh

# Luego probar demo completa
bash /root/demo.sh