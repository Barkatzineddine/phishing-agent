#!/usr/bin/env python3
"""
Agent IA d'analyse de phishing
- Extrait les en-têtes (SPF, DKIM, DMARC), les URL et les pièces jointes d'un fichier .eml
- Un LLM (API Groq, gratuite) décide lui-même quand vérifier les IOC via l'API VirusTotal
- Génère un rapport Markdown avec verdict et niveau de risque

Usage :
    export VT_API_KEY="ta_cle_virustotal"
    export GROQ_API_KEY="ta_cle_groq"
    python agent_phishing.py email_suspect.eml
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from email import policy
from email.parser import BytesParser

import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_KEY = os.environ.get("GROQ_API_KEY")
MODELE = "openai/gpt-oss-20b"  # modèle compatible avec le "tool calling"
VT_KEY = os.environ.get("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"


# ---------------------------------------------------------------------------
# 1. Extraction des informations de l'email
# ---------------------------------------------------------------------------
def extraire_email(chemin):
    with open(chemin, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    auth = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or []))

    def statut(protocole):
        m = re.search(rf"{protocole}=(\w+)", auth, re.IGNORECASE)
        return m.group(1).lower() if m else "absent"

    corps, urls, pieces = "", set(), []
    for part in msg.walk():
        if part.is_multipart():
            continue
        nom = part.get_filename()
        if nom:
            data = part.get_payload(decode=True) or b""
            pieces.append({"nom": nom, "sha256": hashlib.sha256(data).hexdigest()})
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                texte = part.get_content()
            except Exception:
                texte = (part.get_payload(decode=True) or b"").decode("utf-8", "ignore")
            corps += texte
            urls.update(re.findall(r"https?://[^\s\"'<>)]+", texte))

    return {
        "expediteur": str(msg.get("From", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "sujet": str(msg.get("Subject", "")),
        "spf": statut("spf"),
        "dkim": statut("dkim"),
        "dmarc": statut("dmarc"),
        "urls": sorted(urls)[:10],
        "pieces_jointes": pieces,
        "extrait_corps": re.sub(r"<[^>]+>", " ", corps)[:2000],
    }


# ---------------------------------------------------------------------------
# 2. Outils que l'agent peut appeler (VirusTotal)
# ---------------------------------------------------------------------------
def _vt_get(endpoint):
    if not VT_KEY:
        return {"erreur": "VT_API_KEY non définie"}
    try:
        r = requests.get(f"{VT_BASE}/{endpoint}", headers={"x-apikey": VT_KEY}, timeout=30)
        time.sleep(15)  # offre gratuite : 4 requêtes par minute
        if r.status_code == 404:
            return {"resultat": "inconnu de VirusTotal"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malveillant": stats.get("malicious", 0),
            "suspect": stats.get("suspicious", 0),
            "sain": stats.get("harmless", 0),
            "non_detecte": stats.get("undetected", 0),
        }
    except requests.RequestException as e:
        return {"erreur": str(e)}


def verifier_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _vt_get(f"urls/{url_id}")


def verifier_hash(sha256):
    return _vt_get(f"files/{sha256}")


OUTILS = {"verifier_url": verifier_url, "verifier_hash": verifier_hash}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "verifier_url",
            "description": "Vérifie la réputation d'une URL sur VirusTotal.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL complète"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verifier_hash",
            "description": "Vérifie le hash SHA256 d'une pièce jointe sur VirusTotal.",
            "parameters": {
                "type": "object",
                "properties": {"sha256": {"type": "string", "description": "Hash SHA256"}},
                "required": ["sha256"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# 3. Boucle agentique : le LLM décide quels outils utiliser
# ---------------------------------------------------------------------------
SYSTEME = """Tu es un analyste SOC spécialisé dans le phishing.
Analyse l'email fourni. Utilise les outils pour vérifier les URL et les pièces jointes
qui te semblent suspectes. Tiens compte des résultats SPF/DKIM/DMARC et des incohérences
entre From, Return-Path et Reply-To.
Réponds en français, en Markdown, avec exactement ces sections :
## Verdict (Phishing / Suspect / Légitime)
## Niveau de risque (Faible / Moyen / Élevé / Critique)
## Indicateurs de compromission (IOC)
## Raisons
## Actions recommandées"""


def agent(infos, max_tours=8):
    if not GROQ_KEY:
        return "Erreur : la variable GROQ_API_KEY n'est pas définie."

    messages = [
        {"role": "system", "content": SYSTEME},
        {"role": "user", "content": "Analyse cet email :\n" + json.dumps(infos, ensure_ascii=False, indent=2)},
    ]
    headers = {"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}

    for _ in range(max_tours):
        r = requests.post(
            GROQ_URL,
            headers=headers,
            json={"model": MODELE, "messages": messages, "tools": TOOLS, "tool_choice": "auto"},
            timeout=120,
        )
        if not r.ok:
            print(f"[erreur Groq {r.status_code}] {r.text}")
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        messages.append(msg)

        appels = msg.get("tool_calls") or []
        if not appels:
            return msg.get("content", "")

        for appel in appels:
            nom = appel["function"]["name"]
            args = appel["function"].get("arguments") or "{}"
            if isinstance(args, str):
                args = json.loads(args)
            print(f"[agent] appel de l'outil {nom} {args}")
            try:
                resultat = OUTILS[nom](**args)
            except Exception as e:
                resultat = {"erreur": str(e)}
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": appel["id"],
                    "content": json.dumps(resultat, ensure_ascii=False),
                }
            )

    return "Analyse interrompue : nombre maximal d'appels d'outils atteint."


# ---------------------------------------------------------------------------
# 4. Rapport
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        print("Usage : python agent_phishing.py fichier.eml")
        sys.exit(1)

    infos = extraire_email(sys.argv[1])
    print(f"[+] Email extrait : {len(infos['urls'])} URL, {len(infos['pieces_jointes'])} pièce(s) jointe(s)")

    analyse = agent(infos)

    rapport = f"""# Rapport d'analyse de phishing
*Généré le {datetime.now():%d/%m/%Y %H:%M}*

| Champ | Valeur |
|---|---|
| Expéditeur | {infos['expediteur']} |
| Return-Path | {infos['return_path']} |
| Sujet | {infos['sujet']} |
| SPF / DKIM / DMARC | {infos['spf']} / {infos['dkim']} / {infos['dmarc']} |

{analyse}
"""
    with open("rapport.md", "w", encoding="utf-8") as f:
        f.write(rapport)
    print("[+] Rapport enregistré dans rapport.md")


if __name__ == "__main__":
    main()
