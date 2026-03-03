#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          FOOTPRINTING TOOL — Backend Flask               ║
║       APIs: crt.sh | dns.google | hackertarget          ║
║             ipinfo.io | Shodan | VirusTotal              ║
╚══════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import json
import socket
import os
import time
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ─── API Keys (optionnelles, dans .env) ───────────────────
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
IPINFO_TOKEN      = os.getenv("IPINFO_TOKEN", "")

HEADERS = {"User-Agent": "FootprintingTool/1.0 (Educational/PenTest)"}
TIMEOUT = 10

# ══════════════════════════════════════════════════════════
#  ROUTES PRINCIPALES
# ══════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def full_scan():
    """Lance un scan complet sur le domaine cible"""
    data = request.get_json()
    target = data.get("target", "").strip().lower()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    if not target:
        return jsonify({"error": "Domaine invalide"}), 400

    results = {}

    # DNS Records
    results["dns"] = get_dns_records(target)

    # Subdomains via crt.sh
    results["subdomains"] = get_subdomains_crtsh(target)

    # WHOIS via hackertarget
    results["whois"] = get_whois(target)

    # IP Info
    results["ip_info"] = get_ip_info(target)

    # VirusTotal (si clé disponible)
    if VIRUSTOTAL_API_KEY:
        results["virustotal"] = get_virustotal(target)

    # Shodan (si clé disponible)
    if SHODAN_API_KEY:
        results["shodan"] = get_shodan(target)

    return jsonify(results)


# ══════════════════════════════════════════════════════════
#  ENDPOINTS INDIVIDUELS
# ══════════════════════════════════════════════════════════

@app.route("/api/dns", methods=["POST"])
def dns_lookup():
    target = request.get_json().get("target", "")
    return jsonify(get_dns_records(target))


@app.route("/api/subdomains", methods=["POST"])
def subdomains():
    target = request.get_json().get("target", "")
    return jsonify(get_subdomains_crtsh(target))


@app.route("/api/whois", methods=["POST"])
def whois_lookup():
    target = request.get_json().get("target", "")
    return jsonify(get_whois(target))


@app.route("/api/ip", methods=["POST"])
def ip_info():
    target = request.get_json().get("target", "")
    return jsonify(get_ip_info(target))


@app.route("/api/headers", methods=["POST"])
def http_headers():
    target = request.get_json().get("target", "")
    return jsonify(get_http_headers(target))


@app.route("/api/ports", methods=["POST"])
def port_scan():
    target = request.get_json().get("target", "")
    ports  = request.get_json().get("ports", [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443])
    return jsonify(scan_ports(target, ports))


@app.route("/api/robots", methods=["POST"])
def robots_txt():
    target = request.get_json().get("target", "")
    return jsonify(get_robots_txt(target))


@app.route("/api/shodan", methods=["POST"])
def shodan_info():
    if not SHODAN_API_KEY:
        return jsonify({"error": "Clé Shodan manquante dans .env"}), 400
    target = request.get_json().get("target", "")
    return jsonify(get_shodan(target))


@app.route("/api/virustotal", methods=["POST"])
def virustotal_info():
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "Clé VirusTotal manquante dans .env"}), 400
    target = request.get_json().get("target", "")
    return jsonify(get_virustotal(target))


@app.route("/api/dorks", methods=["POST"])
def generate_dorks():
    data     = request.get_json()
    target   = data.get("target", "")
    category = data.get("category", "all")
    return jsonify(generate_google_dorks(target, category))


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({
        "status": "online",
        "shodan":     bool(SHODAN_API_KEY),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "ipinfo":     bool(IPINFO_TOKEN),
    })


# ══════════════════════════════════════════════════════════
#  FONCTIONS DE RECONNAISSANCE RÉELLES
# ══════════════════════════════════════════════════════════

def get_dns_records(domain):
    """Récupère les enregistrements DNS via dns.google (API publique gratuite)"""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {"domain": domain, "records": {}, "error": None}

    for rtype in record_types:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            data = resp.json()
            if "Answer" in data:
                results["records"][rtype] = [
                    {"name": r.get("name"), "data": r.get("data"), "ttl": r.get("TTL")}
                    for r in data["Answer"]
                ]
            else:
                results["records"][rtype] = []
        except Exception as e:
            results["records"][rtype] = []

    # Résolution IP directe
    try:
        ip = socket.gethostbyname(domain)
        results["resolved_ip"] = ip
    except:
        results["resolved_ip"] = None

    return results


def get_subdomains_crtsh(domain):
    """Enumération de sous-domaines via crt.sh (Certificate Transparency Logs)"""
    results = {"domain": domain, "subdomains": [], "count": 0, "error": None}

    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, headers=HEADERS, timeout=15)
        data = resp.json()

        subdomains = set()
        for cert in data:
            name = cert.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") and "*" not in sub:
                    subdomains.add(sub)

        # Trier et dédupliquer
        sorted_subs = sorted(list(subdomains))
        results["subdomains"] = sorted_subs
        results["count"]      = len(sorted_subs)

    except Exception as e:
        results["error"] = str(e)

    return results


def get_whois(domain):
    """WHOIS via hackertarget.com (API publique gratuite)"""
    results = {"domain": domain, "raw": "", "parsed": {}, "error": None}

    try:
        url  = f"https://api.hackertarget.com/whois/?q={domain}"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        raw  = resp.text
        results["raw"] = raw

        # Parser les infos importantes
        parsed = {}
        lines  = raw.split("\n")
        keys   = {
            "Registrar":        "registrar",
            "Creation Date":    "created",
            "Updated Date":     "updated",
            "Registry Expiry":  "expires",
            "Registrant":       "registrant",
            "Name Server":      "nameservers",
        }
        for line in lines:
            for key, field in keys.items():
                if line.lower().startswith(key.lower()):
                    val = line.split(":", 1)[-1].strip()
                    if field == "nameservers":
                        parsed.setdefault("nameservers", []).append(val)
                    else:
                        parsed[field] = val
        results["parsed"] = parsed

    except Exception as e:
        results["error"] = str(e)

    return results


def get_ip_info(domain):
    """Informations sur l'IP via ipinfo.io"""
    results = {"domain": domain, "ip": None, "info": {}, "error": None}

    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip

        token = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
        url   = f"https://ipinfo.io/{ip}/json{token}"
        resp  = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        data  = resp.json()

        results["info"] = {
            "ip":       data.get("ip"),
            "hostname": data.get("hostname"),
            "city":     data.get("city"),
            "region":   data.get("region"),
            "country":  data.get("country"),
            "org":      data.get("org"),
            "timezone": data.get("timezone"),
            "loc":      data.get("loc"),
        }
    except Exception as e:
        results["error"] = str(e)

    return results


def get_http_headers(domain):
    """Récupère les headers HTTP du serveur cible"""
    results = {"domain": domain, "headers": {}, "server": None, "technologies": [], "error": None}

    for scheme in ["https", "http"]:
        try:
            url  = f"{scheme}://{domain}"
            resp = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            headers = dict(resp.headers)
            results["headers"] = headers
            results["status_code"] = resp.status_code
            results["final_url"]   = resp.url

            # Extraire les technologies
            tech = []
            if "Server" in headers:
                tech.append(f"Server: {headers['Server']}")
                results["server"] = headers["Server"]
            if "X-Powered-By" in headers:
                tech.append(f"Powered by: {headers['X-Powered-By']}")
            if "X-Generator" in headers:
                tech.append(f"Generator: {headers['X-Generator']}")
            if "X-Drupal-Cache" in headers:
                tech.append("CMS: Drupal")
            if "X-WP-Total" in headers or "x-pingback" in str(headers).lower():
                tech.append("CMS: WordPress")

            results["technologies"] = tech
            break
        except Exception as e:
            results["error"] = str(e)

    return results


def scan_ports(domain, ports):
    """Scan de ports TCP basique"""
    results = {"domain": domain, "open_ports": [], "closed_ports": [], "error": None}

    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip

        PORT_SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
        }

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            entry = {
                "port":    port,
                "service": PORT_SERVICES.get(port, "Unknown"),
                "state":   "open" if result == 0 else "closed",
            }
            if result == 0:
                results["open_ports"].append(entry)
            else:
                results["closed_ports"].append(entry)

    except Exception as e:
        results["error"] = str(e)

    return results


def get_robots_txt(domain):
    """Récupère et analyse le robots.txt"""
    results = {"domain": domain, "content": "", "disallowed": [], "allowed": [], "sitemaps": [], "error": None}

    try:
        for scheme in ["https", "http"]:
            try:
                url  = f"{scheme}://{domain}/robots.txt"
                resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
                if resp.status_code == 200:
                    content = resp.text
                    results["content"] = content
                    for line in content.split("\n"):
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[-1].strip()
                            if path:
                                results["disallowed"].append(path)
                        elif line.lower().startswith("allow:"):
                            path = line.split(":", 1)[-1].strip()
                            if path:
                                results["allowed"].append(path)
                        elif line.lower().startswith("sitemap:"):
                            url_map = line.split(":", 1)[-1].strip()
                            results["sitemaps"].append(url_map)
                    break
            except:
                continue
    except Exception as e:
        results["error"] = str(e)

    return results


def get_shodan(domain):
    """Informations Shodan sur le domaine/IP"""
    results = {"domain": domain, "data": {}, "error": None}

    try:
        ip  = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        data = resp.json()

        if "error" in data:
            results["error"] = data["error"]
        else:
            results["data"] = {
                "ip":           data.get("ip_str"),
                "org":          data.get("org"),
                "isp":          data.get("isp"),
                "os":           data.get("os"),
                "country":      data.get("country_name"),
                "city":         data.get("city"),
                "open_ports":   data.get("ports", []),
                "vulns":        list(data.get("vulns", {}).keys()),
                "last_update":  data.get("last_update"),
                "hostnames":    data.get("hostnames", []),
                "services":     [
                    {"port": s.get("port"), "transport": s.get("transport"), "product": s.get("product", "")}
                    for s in data.get("data", [])
                ],
            }
    except Exception as e:
        results["error"] = str(e)

    return results


def get_virustotal(domain):
    """Analyse VirusTotal du domaine"""
    results = {"domain": domain, "data": {}, "error": None}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {**HEADERS, "x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        data = resp.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        results["data"] = {
            "reputation":    attrs.get("reputation"),
            "malicious":     stats.get("malicious", 0),
            "suspicious":    stats.get("suspicious", 0),
            "harmless":      stats.get("harmless", 0),
            "categories":    attrs.get("categories", {}),
            "creation_date": attrs.get("creation_date"),
            "registrar":     attrs.get("registrar"),
            "whois":         attrs.get("whois", "")[:500],
        }
    except Exception as e:
        results["error"] = str(e)

    return results


def generate_google_dorks(target, category="all"):
    """Génère des Google dorks organisés par catégorie"""
    dorks_map = {
        "subdomains": [
            f"site:*.{target} -www",
            f"site:*.*.{target}",
            f"inurl:dev.{target}",
            f"inurl:staging.{target}",
            f"inurl:api.{target}",
            f"inurl:vpn.{target}",
            f"inurl:test.{target}",
            f"inurl:beta.{target}",
        ],
        "files": [
            f"site:{target} filetype:env",
            f"site:{target} filetype:sql",
            f"site:{target} filetype:bak",
            f"site:{target} filetype:log",
            f"site:{target} filetype:xml inurl:config",
            f"site:{target} filetype:ini \"password\"",
            f"site:{target} ext:old OR ext:backup",
            f"site:{target} intitle:\"index of\" inurl:backup",
            f"site:{target} filetype:yml",
            f"site:{target} filetype:json inurl:config",
        ],
        "credentials": [
            f"site:{target} intext:\"password\" filetype:txt",
            f"site:{target} intext:\"username\" filetype:log",
            f"site:{target} inurl:admin",
            f"site:{target} inurl:login intitle:\"admin\"",
            f"site:{target} inurl:\"/wp-admin/login.php\"",
            f"site:{target} intext:\"DB_PASSWORD\"",
            f"site:{target} filetype:env \"SECRET_KEY\"",
            f"\"@{target}\" filetype:xls",
        ],
        "tech": [
            f"site:{target} inurl:wp-content",
            f"site:{target} \"Powered by\"",
            f"site:{target} intitle:\"Apache2 Ubuntu\"",
            f"site:{target} inurl:joomla",
            f"site:{target} inurl:drupal",
            f"site:{target} inurl:phpinfo.php",
            f"site:{target} intitle:\"phpMyAdmin\"",
            f"site:{target} inurl:\"/laravel\"",
        ],
        "network": [
            f"intitle:\"index of\" site:{target}",
            f"site:{target} intitle:\"cPanel\"",
            f"site:{target} intitle:\"Webmin\"",
            f"site:{target} inurl:8080",
            f"site:{target} inurl:8443",
            f"site:{target} inurl:\"/phpmyadmin\"",
            f"site:{target} inurl:\"/pma\"",
            f"site:{target} intitle:\"router\" inurl:admin",
        ],
        "employees": [
            f"\"@{target}\" site:linkedin.com",
            f"site:linkedin.com \"{target.split('.')[0]}\" \"engineer\"",
            f"site:linkedin.com \"{target.split('.')[0]}\" \"director\"",
            f"\"@{target}\" filetype:pdf",
            f"site:{target} intext:\"contact\" \"email\"",
            f"\"@{target}\" site:twitter.com",
            f"\"{target.split('.')[0]}\" site:github.com",
        ],
    }

    if category == "all":
        return {"dorks": dorks_map, "total": sum(len(v) for v in dorks_map.values())}
    elif category in dorks_map:
        return {"dorks": {category: dorks_map[category]}, "total": len(dorks_map[category])}
    else:
        return {"error": f"Catégorie '{category}' inconnue"}


# ══════════════════════════════════════════════════════════
#  LANCEMENT
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════╗
║       🔍 FOOTPRINTING TOOL — Démarrage       ║
╠══════════════════════════════════════════════╣
║  URL : http://localhost:5000                 ║
║  Mode : Développement                        ║
╚══════════════════════════════════════════════╝
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)
