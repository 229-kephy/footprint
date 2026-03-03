# 🔍 Footprinting Tool — Installation & Usage

## 📋 Prérequis
- Python 3.8+
- pip

---

## 🚀 Installation (3 étapes)

### 1. Installer les dépendances
```bash
cd footprinting-tool
pip install -r requirements.txt
```

### 2. Configurer les clés API (optionnel)
```bash
cp .env.example .env
# Édite .env et ajoute tes clés API
nano .env
```

### 3. Lancer l'outil
```bash
python app.py
```

Ouvre ton navigateur sur : **http://localhost:5000**

---

## 🔑 Clés API

| API | Gratuit ? | Lien |
|-----|-----------|------|
| **Shodan** | Oui (limité) | https://account.shodan.io |
| **VirusTotal** | Oui (500/jour) | https://www.virustotal.com/gui/my-apikey |
| **IPInfo** | Oui (50k/mois) | https://ipinfo.io/account/token |
| **crt.sh** | Oui (sans clé) | Automatique |
| **dns.google** | Oui (sans clé) | Automatique |

---

## 🛡️ Modules disponibles

| Module | Description | Clé requise |
|--------|-------------|-------------|
| DNS Records | A, AAAA, MX, NS, TXT, CNAME via dns.google | Non |
| Subdomains | Certificate Transparency via crt.sh | Non |
| WHOIS | Registrar, dates, nameservers | Non |
| IP Info | Géolocalisation, ASN, organisation | Non (optionnel) |
| HTTP Headers | Serveur, technologies, headers | Non |
| Port Scan | 14 ports TCP courants | Non |
| Robots.txt | Chemins disallowed, sitemaps | Non |
| Google Dorks | 50+ dorks générés (6 catégories) | Non |
| Shodan | Ports, vulnérabilités, services | Oui |
| VirusTotal | Réputation, catégories, malware | Oui |

---

## ⚠️ Avertissement légal

Cet outil est destiné à un usage **éducatif** et dans le cadre de :
- Tests de pénétration autorisés (contrat signé)
- Bug bounty programs
- CTF (Capture The Flag)
- Ton propre infrastructure
- Travaux dirigés

**Toute utilisation non autorisée est illégale.**

---

## 📁 Structure du projet

```
footprinting-tool/
├── app.py              ← Backend Flask (APIs réelles)
├── requirements.txt    ← Dépendances Python
├── .env.example        ← Template de configuration
├── .env               ← Tes clés API (créé par toi)
└── templates/
    └── index.html     ← Frontend (interface web)
```
