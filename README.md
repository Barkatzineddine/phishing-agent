# Agent IA de triage de phishing

Agent IA local qui trie les emails suspects comme le ferait un analyste SOC de niveau 1 :
il analyse les en-têtes d'authentification (SPF, DKIM, DMARC), extrait les URL et les pièces
jointes, décide lui-même de vérifier les IOC via l'API VirusTotal, puis génère un rapport
d'incident avec verdict, niveau de risque et actions recommandées.

Le LLM tourne **en local** (Ollama) : aucun contenu d'email n'est envoyé à un service tiers,
seuls les IOC (URL et hash) sont soumis à VirusTotal.

## Pourquoi ce projet

Le triage des emails signalés est une tâche répétitive et chronophage dans un SOC. Ce projet
automatise les étapes de collecte et d'enrichissement pour que l'analyste ne garde que la
décision finale.

## Fonctionnalités

- Parsing d'un fichier `.eml` : expéditeur, `Return-Path`, `Reply-To`, sujet, corps
- Vérification des résultats **SPF / DKIM / DMARC**
- Extraction des **URL** et des **pièces jointes** (avec calcul du hash SHA256)
- **Workflow agentique** : le LLM dispose d'outils (`verifier_url`, `verifier_hash`) et choisit
  lui-même lesquels appeler, sur quels indicateurs, et quand s'arrêter
- Enrichissement des IOC via l'**API VirusTotal v3**
- Génération d'un **rapport d'incident** en Markdown

## Architecture

```
email.eml
    │
    ├─► Extraction (Python)  ──► en-têtes, SPF/DKIM/DMARC, URL, pièces jointes (SHA256)
    │
    ├─► Agent LLM (Ollama)   ──► décide des vérifications à effectuer
    │        │
    │        └─► Outils ──► API VirusTotal (réputation URL / hash)
    │
    └─► rapport.md           ──► verdict, niveau de risque, IOC, actions recommandées
```

## Installation

```bash
git clone https://github.com/<ton-compte>/phishing-agent.git
cd phishing-agent
pip install -r requirements.txt
```

Installer [Ollama](https://ollama.com) puis télécharger un modèle compatible avec le *tool calling* :

```bash
ollama pull llama3.1
```

Créer un compte gratuit sur [VirusTotal](https://www.virustotal.com) et exporter la clé API :

```bash
export VT_API_KEY="votre_cle_api"
```

## Utilisation

```bash
python agent_phishing.py samples/exemple_phishing.eml
```

Sortie console :

```
[+] Email extrait : 1 URL, 1 pièce(s) jointe(s)
[agent] appel de l'outil verifier_url {'url': 'http://paypa1-secure.com/login?id=1'}
[agent] appel de l'outil verifier_hash {'sha256': 'd930a77b...'}
[+] Rapport enregistré dans rapport.md
```

Le rapport `rapport.md` contient un tableau récapitulatif des en-têtes puis l'analyse du LLM :
verdict, niveau de risque, IOC, raisons et actions recommandées.

## Où trouver des échantillons

- Le fichier `samples/exemple_phishing.eml` fourni ici (email de test construit manuellement)
- Un email réel : dans Gmail, ouvrir le message puis « Télécharger le message »
- Des dépôts publics d'échantillons de phishing au format `.eml`

## Limites connues

- L'offre gratuite de VirusTotal est limitée à 4 requêtes par minute : le script attend
  15 secondes entre chaque appel
- Le nombre d'URL analysées est plafonné à 10 par email
- Le verdict d'un LLM reste indicatif et doit être validé par un analyste
- Les performances dépendent du modèle utilisé et du matériel (environ 8 Go de RAM)

## Améliorations prévues

- Extraction des liens de redirection et des domaines de second niveau
- Ajout d'une source d'enrichissement supplémentaire (AbuseIPDB, URLhaus)
- Mapping des techniques observées sur **MITRE ATT&CK**
- Export du rapport au format JSON pour ingestion dans un SIEM

## Avertissement

Projet réalisé dans un cadre pédagogique, pour l'apprentissage de l'analyse de phishing et de
l'automatisation SOC. Les échantillons malveillants doivent être manipulés dans un
environnement isolé.

## Auteur

Mohamed Zineddine Barkat - étudiant en Master Conception de Systèmes et Cybersécurité (UPEC)
