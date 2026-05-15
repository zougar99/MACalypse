# MACalypse - 36 Network Tools

Application Windows pour changer/manager l'identité réseau, avec 36 outils intégrés.

## Fonctionnalités

### Identity (5)
- **MAC Address** - Changer, reset, random, bulk change
- **IP Address** - IP statique, DHCP, random IP
- **DNS** - Set DNS, auto, flush, presets (Google, Cloudflare, etc.)
- **Hostname** - Changer nom PC, random
- **Hardware ID** - Scan HWID, spoof MachineGUID

### Privacy (3)
- **Browser Clean** - Nettoyer Chrome, Edge, Firefox, Brave, Opera
- **Proxy** - Enable/disable, presets (Tor, Burp, Fiddler)
- **Hosts File** - Lire/éditer, bloquer sites

### Network (6)
- **Public IP** - Voir IP publique + infos géo
- **WiFi Pass** - Afficher mots de passe WiFi enregistrés
- **Net Info** - Infos réseau détaillées
- **NetScan** - Scanner réseau local (ping sweep)
- **Speed Test** - Test de débit (1MB/10MB)
- **Network Usage** - Statistiques interfaces (bytes, packets)

### Diagnostic (7)
- **Connections** - Afficher connexions actives
- **Ping/Trace** - Ping et traceroute
- **DNS Lookup** - Lookup DNS, MX, NS + résolution IP
- **ARP/Routes** - Table ARP et routage
- **IP Geolocate** - Géolocalisation IP
- **DNS Benchmark** - Benchmark 5 serveurs DNS
- **Subnet Calc** - Calculateur de sous-réseau CIDR

### Security (4)
- **Firewall** - Enable/disable/status
- **Port Scanner** - Scan ports avec quick top 40
- **Processes** - Voir processus réseau
- **Adapter Ctl** - Enable/disable/cycle adaptateur

### System (6)
- **System Info** - Infos complètes système
- **Startup** - Voir programmes au démarrage
- **Temp Cleaner** - Nettoyer fichiers temporaires
- **Task Kill** - Tuer processus par nom
- **Scheduled Tasks** - Top 50 tâches planifiées
- **Disk Info** - Infos disques (usage, espace libre)

### Utils (5)
- **Hash Gen** - MD5, SHA1, SHA256, SHA512
- **PassGen** - Générer mots de passe
- **Wake on LAN** - Envoi paquet magique
- **Clipboard** - Vider presse-papier
- **MAC Vendor** - Identifier fabricant par MAC OUI
- **Bluetooth** - Scanner périphériques Bluetooth

## Installation

### 1. Installer Python 3.10+

Télécharger depuis https://python.org (cocher "Add to PATH")

### 2. Installer les dépendances

```
pip install -r requirements.txt
```

### 3. Lancer l'application

Double-cliquez sur `run.bat` ou :

```
python app.py
```

**IMPORTANT : L'application doit être lancée en tant qu'Administrateur.**

## Utilisation

1. L'application demande automatiquement les droits Administrateur
2. Sélectionnez un adaptateur réseau dans la liste à gauche
3. Naviguez entre les catégories (Identity, Privacy, Network, etc.)
4. Utilisez les outils dans les onglets de chaque catégorie
5. Consultez le log d'activité en bas pour le suivi des opérations
