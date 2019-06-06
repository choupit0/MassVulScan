# MassVulScan :alien: [Version Francaise](https://github.com/choupit0/MassVulScan/blob/master/README-FR.md)
# Description
Bash script that combines the power of the Masscan scanner to find open ports, the efficiency of the Nmap scanner to identify open services and their version, and finally the NSE vulners.nse script to identify potential vulnerabilities (CVEs). An HTML report will be generated containing the result of the analysis as well as a TXT file allowing to focus on the vulnerable hosts.

![Example Menu](screenshots/Menu.PNG)

# Prerequisites
- Package xsltproc (for the conversion of an XML file to HTML, for the final report)
- Masscan, version >= 1.0.5 (https://github.com/robertdavidgraham/masscan)
- Nmap (https://nmap.org)
- NSE script vulners.nse (https://github.com/vulnersCom/nmap-vulners)

**I invite you to read the file "requirements.txt" if you have difficulties. It will tell you how to install each of the prerequisites.**
# How the script works?
The main steps of the script:
1) Express identification of hosts that are online (nmap)
2) For each of these hosts, extremely fast identification of open TCP/UDP ports (masscan)
3) The result (file) is sorted to gather all ports to be scanned by host
4) Identification of services and vulnerabilities, multiple sessions (nmap + vulners.nse) in parallel, one session per host
5) Display of (potentially) vulnerable hosts on the screen at the end of the script
6) Generation of two reports: a global HTML report will be created containing all the details for each of the hosts, vulnerable or not and a TXT file allowing to focus on hosts (potentially) vulnerable with the details

The HTML report uses a bootstrap style sheet (https://github.com/honze-net/nmap-bootstrap-xsl) for more convenience.
# How to use it?
All you have to do is indicate the file (-f | --include-file) containing a list of networks / hosts to scan:
```
git clone https://github.com/choupit0/MassVulScan.git
cd MassVulScan
chmod +x MassVulScan.sh
(root user or sudo) ./MassVulScan.sh -f [input file]
```
List of available parameters/arguments:
```
-f [input file] = mandatory parameter that will contain the list of networks/hosts to scan
-e [exclude file] = optional parameter to exclude a list of networks/hosts to scan
-i (interactive mode) = optional parameter to choose ports to scan and speed (pkts/sec for Masscan)
```
By default the script will scan only the first 1000 TCP/UDP ports among the most common ports. You can find the list here: /usr/local/share/nmap/nmap-services. Similarly, the rate or number of packets per second is set to 5000 by default.

For the format of the files, you will find two examples in the dedicated directory:
```
root@ubuntu:~/audit/MassVulScan# cat example/hosts.txt
# Private subnet
192.168.2.0/24
root@ubuntu:~/audit/MassVulScan# cat example/exclude.txt
# Gateway
192.168.2.254
```
# GIF Demo
![Example Demo](demo/MassVulScan_Demo.gif)
# Some screenshots
![Example Masscan](screenshots/Masscan.PNG)

![Example Nmap](screenshots/Nmap.PNG)

![Example EOF](screenshots/End-of-script.PNG)

![Example Vulnerable-hosts](screenshots/Ex-vulnerable-host-found.PNG)

![Example HTML](screenshots/HTML.PNG)
# Compatibility
The script has only been tested on Debian and Ubuntu but should work on most Linux distributions. It works with TCP and UDP protocols.
# Notes / Tips
The script is also compatible with Nmap's "Vuln" option to search for more vulnerabilities (the better known as ms17-010, EternalBlue) in addition to the CVEs identified from vulners.com. All you have to do is modify the lines of the script containing "**--script vulners**" and replace with "**--script vuln,vulners**".
With the VI editor it's very simple:
```
vi MassVulScan.sh
:%s/--script vulners/--script vuln,vulners/g
:wq
```
Note that the advantage of using the NSE vulners.nse script is that it systematically polls the vulners.com site database, so it will be the latest available data. Similarly, the latter performs a ranking and sorting of identified VECs, the most severe at the top of the list, which is very convenient.
Last thing, hit the "D" (= debug) key during nmap scans if you want to see what's going on.
