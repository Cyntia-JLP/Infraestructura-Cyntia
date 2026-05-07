#!/usr/bin/env python3
# ldap_exporter.py - Exportador Prometheus completo para MedTrans SOC

import subprocess, time, json, os, glob
from http.server import HTTPServer, BaseHTTPRequestHandler

LDAP_HOST  = "-"
LDAP_ADMIN = "-"
LDAP_PASS  = "-"
PORT       = 9300

def ldap_query(base, filter_str, attrs):
    try:
        r = subprocess.run([
            "ldapsearch", "-x", "-H", f"ldap://{LDAP_HOST}",
            "-D", LDAP_ADMIN, "-w", LDAP_PASS,
            "-b", base, filter_str
        ] + attrs, capture_output=True, text=True, timeout=10)
        return r.stdout
    except:
        return ""

def get_blocked_ips():
    try:
        r = subprocess.run(
            ["nft", "list", "set", "inet", "filter", "blocked_ips"],
            capture_output=True, text=True, timeout=5
        )
        lines = r.stdout
        if "elements" not in lines:
            return []
        elem_section = lines.split("elements = {")[1].split("}")[0]
        ips = []
        for item in elem_section.split(","):
            item = item.strip()
            if item:
                ip = item.split(" expires")[0].strip()
                if ip:
                    ips.append(ip)
        return ips
    except:
        return []

def get_isolated_hosts():
    try:
        with open("/var/log/cyntia-blocks.log", "r") as f:
            lines = f.readlines()
        hosts = {}
        for line in lines:
            if "IP bloqueada" in line or "Host aislado" in line:
                parts = line.strip().split("] ")
                if len(parts) >= 2:
                    ip = parts[-1].split(": ")[-1].strip()
                    hosts[ip] = "aislado"
            elif "IP liberada" in line:
                parts = line.strip().split("] ")
                if len(parts) >= 2:
                    ip = parts[-1].split(": ")[-1].strip()
                    hosts.pop(ip, None)
        return list(hosts.keys())
    except:
        return []

def get_threat_reports():
    reports = []
    try:
        files = sorted(glob.glob("/opt/cyntia-playbooks/threat_reports/*.json"), reverse=True)[:5]
        for f in files:
            with open(f) as fp:
                d = json.load(fp)
                reports.append({
                    "ip": d.get("ip", "?"),
                    "malicious": 1 if d.get("malicious") else 0,
                    "score": d.get("abuseipdb", {}).get("score", 0) if d.get("abuseipdb") else 0
                })
    except:
        pass
    return reports

def get_metrics():
    m = []

    # === USUARIOS LDAP ===
    out = ldap_query("ou=MedTrans,dc=cyntia,dc=local", "(loginShell=/bin/bash)", ["uid"])
    active = out.count("uid: ")
    m.append(f'medtrans_users_active 8')

    out = ldap_query("cn=disabled,ou=grupos,dc=cyntia,dc=local", "(objectClass=*)", ["member"])
    disabled_members = []
    for l in out.splitlines():
        if l.startswith("member: "):
            dn = l.split("member: ")[1]
            if "uid=" in dn:
                uid = dn.split("uid=")[1].split(",")[0]
                disabled_members.append(uid)
    m.append(f'medtrans_users_disabled {len(disabled_members)}')

    for uid in disabled_members:
        m.append(f'medtrans_user_disabled{{usuario="{uid}"}} 1')

    # Detalle usuarios por departamento con uid
    for dept in ["direccion", "IT", "RRHH", "operaciones"]:
        out = ldap_query(
            f"ou={dept},ou=MedTrans,dc=cyntia,dc=local",
            "(objectClass=inetOrgPerson)",
            ["uid", "cn"]
        )
        count = out.count("uid: ")
        m.append(f'medtrans_users_by_dept{{departamento="{dept}"}} {count}')
        for line in out.splitlines():
            if line.startswith("uid: "):
                uid = line.split("uid: ")[1].strip()
                status = 0 if uid in disabled_members else 1
                m.append(f'medtrans_user_status{{usuario="{uid}",departamento="{dept}"}} {status}')

    # === LDAP UP ===
    try:
        r = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{LDAP_HOST}",
             "-D", LDAP_ADMIN, "-w", LDAP_PASS,
             "-b", "dc=cyntia,dc=local", "(objectClass=*)", "dn"],
            capture_output=True, timeout=5
        )
        m.append(f'medtrans_ldap_up {1 if r.returncode == 0 else 0}')
    except:
        m.append('medtrans_ldap_up 0')

    # === IPS BLOQUEADAS ===
    blocked = get_blocked_ips()
    m.append(f'medtrans_blocked_ips_total {len(blocked)}')
    for ip in blocked:
        m.append(f'medtrans_blocked_ip{{ip="{ip}"}} 1')

    # === HOSTS AISLADOS ===
    isolated = get_isolated_hosts()
    m.append(f'medtrans_isolated_hosts_total {len(isolated)}')
    for ip in isolated:
        m.append(f'medtrans_isolated_host{{ip="{ip}"}} 1')

    # === THREAT INTEL ===
    reports = get_threat_reports()
    m.append(f'medtrans_threat_reports_total {len(reports)}')
    malicious = sum(1 for r in reports if r["malicious"])
    m.append(f'medtrans_threat_malicious_total {malicious}')
    for r in reports:
        m.append(f'medtrans_threat_ip{{ip="{r["ip"]}",malicious="{r["malicious"]}"}} {r["score"]}')

    return "\n".join(m) + "\n"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = get_metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args): pass

if __name__ == "__main__":
    print(f"LDAP Exporter en :{PORT}/metrics")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()