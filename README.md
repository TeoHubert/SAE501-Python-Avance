# SAE501 - Outils pédagogiques Man-in-the-Middle (MITM)

Par Téo HUBERT, Killian DUCHENE, Maxime DESPRES

## Description

Ce dépôt contient des scripts Python réalisés dans le cadre de la SAE 501 (IUT de Saint-Malo, département Réseaux et Télécommunications). L'objectif pédagogique est d'explorer, en environnement contrôlé et autorisé, des techniques d'analyse et d'interception de trafic réseau (ex. ARP poisoning, sniffing) pour mieux comprendre les vulnérabilités et les mécanismes de protection.

Important : ces outils sont destinés à un usage strictement éducatif et expérimental sur un réseau de laboratoire ou des machines dont vous avez l'autorisation explicite d'administration. Toute utilisation non autorisée sur un réseau tiers est illégale et contraire à l'éthique.

## Fonctionnalités (aperçu)

- Scripts de capture et de filtrage
- Résolution IP -> MAC.
- Pollution de cache ARP.
- Fichier principal avec interface CLI avec l'utilisateur pour configurer l'environnement et gérer les autres fonctionnalités.

## Contenu du dépôt

- `main.py` — Script principal (orchestration / démonstration pédagogique).
- `sniffer.py` — Outils de capture/analyse de paquets.
- `arp_spoofing.py` — Exemple pédagogique de pollution ARP (MITM).
- `get_mac_from_ip.py` — Outil utilitaire pour obtenir l'adresse MAC d'une IP sur l'interface donnée.
- `remove_checksum.py` — Utilitaire (ex : retrait de checksum si besoin lors de tests).
- `sessions_sniffer.pcap` — Fichier pcap généré par le script pour l'analyse hors-ligne par la suite.
- `config.json` (Facultatif) Fichiers de configuration (ex : IP cibles et interface).
- `requirements.txt` — Dépendances Python (Scapy).

## Pré-requis

- Python 3.8+.
- Privileges administrateur (root) pour les opérations réseau et la capture en mode promiscue.
- Dépendances listées dans `requirements.txt` (ex. Scapy).

## Installation (environnement de développement)

1. Créez et activez un environnement virtuel (macOS / zsh) :

   python3 -m venv .venv
   source .venv/bin/activate

2. Installez les dépendances :

   pip install --upgrade pip
   pip install -r requirements.txt

Remarque : certaines fonctions (capture réseau / envoi de paquets) nécessitent des droits élevés. Pour des tests en direct, exécutez les scripts avec `sudo` uniquement dans un environnement de test et après avoir vérifié la configuration.

## Configuration

Le fichier `config.json` contient des valeurs d'exemple. Format attendu :

```json
{
  "cible_1_ip": "192.168.0.101",
  "cible_2_ip": "192.168.0.1",
  "interface": "en0"
}
```

- `cible_1_ip` : adresse IP de la première cible (ex. poste client en test).
- `cible_2_ip` : adresse IP de la seconde cible (ex. passerelle / routeur en test).
- `interface` : interface réseau à utiliser (ex. `en0`, `eth0`).

Adaptez ces valeurs à votre topologie de laboratoire. Ne laissez pas de données réelles ou sensibles dans les fichiers partagés.

## Utilisation (exemples sûrs)

1) Analyse hors-ligne du pcap fourni

- Ouvrez `sessions_sniffer.pcap` avec Wireshark pour inspection visuelle.
- Vous pouvez aussi charger le pcap avec Scapy ou des scripts d'analyse locaux pour tests unitaires.

2) Exécution locale et tests en laboratoire

- Avant toute exécution réseau active, vérifiez `config.json` et exécutez uniquement dans un réseau isolé.
- Pour installer et tester (environnement isolé) : activez le venv puis lancez les scripts nécessaires. Notez que les opérations réseau actives requièrent généralement des privilèges root.

3) Scripts utilitaires

- `get_mac_from_ip.py` : utile pour vérifier la correspondance IP->MAC sur l'interface configurée.

Remarque importante : le dépôt montre des techniques d'attaque à des fins pédagogiques ; le README ne fournit pas d'instructions pas à pas pour commettre des attaques en environnement non autorisé.

## Bonnes pratiques et sécurité

- N'exécutez jamais ces scripts sur un réseau de production ou sans autorisation expresse.
- Utilisez des environnements isolés (VM, VLAN, réseau de labo) pour reproduire des scénarios.
- Conservez des copies du fichier `config.json` sécurisées et ne stockez pas d'informations confidentielles dans le dépôt.

## Dépannage

- Si Scapy ne fonctionne pas correctement sur macOS, vérifiez les permissions et installez les dépendances système nécessaires (ex. libpcap via Homebrew).
- Pour les erreurs liées aux permissions : exécutez les parties capture/envoi avec des droits élevés (en environnement test).

## Contact

Mainteneurs : Téo HUBERT, Killian DUCHENE, Maxime DESPRES