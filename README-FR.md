# MassVulScan :alien: [English version](https://github.com/choupit0/MassVulScan/blob/master/README.md)
# Description
Script Bash qui combine la puissance du scanner Masscan pour trouver des ports ouverts, l'efficacité du scanner Nmap pour identifier les services ouverts et leur version et enfin le script NSE vulners.nse pour identifier les vulnérabilités potentielles (CVE). Un rapport HTML sera généré contenant le résultat de l'analyse ainsi qu'un fichier TXT permettant de se focaliser sur les hosts vulnérables.

![Example Menu](screenshots/Menu_1-9-0.PNG)

# Pré-requis
- Package xsltproc (pour la conversion d'un fichier XML vers HTML, pour le rapport final)
- Masscan, version >= 1.0.5 (https://github.com/robertdavidgraham/masscan)
- Nmap (https://nmap.org)
- Script NSE vulners.nse (https://github.com/vulnersCom/nmap-vulners)

**Je vous invite à lire le fichier "requirements.txt" si vous avez des difficultés. Il vous indiquera la marche à suivre pour installer chacun des pré-requis.**

Une nouvelle fonctionnalité dans la version v1.7 du script installera pour vous tous les pré-requis nécessaires au fonctionnement du script. Seuls les OS de la famille Debian sont concernés pour le moment.
Cette fonctionnalité a été validée sur les OS 64bits suivants (2 core CPU et 2GB RAM ~10 minutes) :
- Debian 10.0
- Elementary 5.0
- LinuxMint 19.1
- Ubuntu 19.04
- Parrot 5.5.17 (HackTheBox / HTB)
# Fonctionnement
Déroulement du script :
1) Identification express des hosts qui sont en ligne (nmap)
2) Pour chacun de ces hosts, identification extrêment rapide des ports TCP/UDP ouverts (masscan)
3) Le résultat (fichier) est trié afin de rassembler tous les ports à scanner par host
4) Identificaton des services et vulnérabilités, multiples sessions (nmap + vulners.nse) en parallèle, une session par host
5) Affichage des hosts (potentiellement) vulnérables à l'écran en fin de script
6) Génération de deux rappports : un rapport HTML global sera créé contenant tous les détails pour chacun des hosts, vulérables ou non et un fichier TXT permettant de se concentrer sur les hosts (potentiellement) vulnérables avec les détails

Le rapport HTML utilise une feuille de style bootstrap (https://github.com/honze-net/nmap-bootstrap-xsl) pour plus de confort.
# Comment l'utiliser ?
Il suffit d'indiquer en paramètre (-f|--include-file) le fichier contenant une liste de réseaux, adresses IP ou noms d'hôtes (version 1.9.0) à scanner :
```
git clone https://github.com/choupit0/MassVulScan.git
cd MassVulScan
chmod +x MassVulScan.sh
(root user or sudo) ./MassVulScan.sh -f [input file]
```
Liste des paramètres/arguments disponibles :
```
-f [input file] = paramètre obligatoire qui contiendra la liste des réseaux, IP ou noms d'hôtes à scanner
-e [exclude file] = paramètre optionnel afin d'exclure une liste de réseaux ou IP (pas de noms d'hôtes) à scanner
-i (interactive mode) = paramètre optionnel pour choisir les ports à scanner, la vitesse (pkts/sec) et le script Nmap
-a (all ports) = paramètre optionnel pour scanner les 65535 ports (TCP et UDP), à la vitesse de 5K pkts/sec
-c (check) = paramètre optionnel pour trouver les hosts en ligne (pré-scan) et ne scanner que ceux-là
-k (keep files) = paramètre optionnel pour conserver les hosts scannés avec et sans le(s) port(s) dans 2 fichiers
-ns (No Nmap scan) = paramètre optionnel pour détecter uniquement les ports ouverts de chacun des hosts
```
Par défaut le script ne scannera que les 1000 premiers ports TCP/UDP parmi les ports les plus courants. Vous pouvez retrouver la liste ici : /usr/local/share/nmap/nmap-services. De même, le taux ou le nombre de paquets par seconde est fixé à 2500 par défaut.

Pour le format des fichiers, vous trouverez deux exemples dans le répertoire dédié :
```
root@ubuntu:~/audit/MassVulScan# cat example/hosts.txt
# Private subnet
192.168.2.0/24
webmail.acme.corp
root@ubuntu:~/audit/MassVulScan# cat example/exclude.txt
# Gateway
192.168.2.254
```
**A noter que le script détectera en cours de route si vous utilisez plusieurs interfaces réseaux. Ce qui est important pour Masscan qui prendra toujours par défaut l'interface qui possède la route par défaut. Il vous sera demandé d'en choisir une (pas de problème avec Nmap).**
# Démo
![Example Demo](demo/MassVulScan_Demo.gif)
# Quelques captures d'écran
![Example Masscan](screenshots/Masscan.PNG)

![Example Nmap](screenshots/Nmap.PNG)

![Example EOF](screenshots/End-of-script.PNG)

![Example Vulnerable-hosts](screenshots/Ex-vulnerable-host-found.PNG)

![Example HTML](screenshots/HTML.PNG)
# Compatibilité
Le script a uniquement été testé sur des OS de la famille Debian mais devrait fonctionner sur la majorité des distributions Linux (hormis pour l'installation des pré-requis). Il peut détecter les ports ouverts sur les protocoles TCP et UDP.
# Remarques / Astuces
A noter que l'avantage d'utiliser le script NSE vulners.nse est qu'il interroge systématiquement la base de données du site de vulners.com, il s'agira donc des dernières données disponibles. De même, ce dernier effectue un classement et un trie des CVE identifiées, les plus sévères en haut de la liste, ce qui est bien pratique.

Le script est également compatible avec les catégories de Nmap (https://nmap.org/book/nse-usage.html#nse-categories) permettant de rechercher davantage de vulnérabilités (les plus connues comme ms17-010, EternalBlue) en plus des CVE identifiées depuis vulners.com. 

Enfin, avec le "mode interactif" (-i) vous avez la possibilité de préciser des arguments au script, par exemple : vulners --script-args mincvss=5
# Problème connus
Concernant SNMP, parfois, l'analyse du port UDP ne semble pas fonctionner correctement avec le programme masscan. J'essaie de trouver une solution.

Inclure package netcat lors du check des prérequis.
