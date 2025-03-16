<p align="center">
  <img src="https://github.com/choupit0/MassVulScan/blob/master/DALL%C2%B7E%20Logo.gif" width="150" alt="MassVulScan logo">
</p>

<h1 align="center">MassVulScan</h1>
<p align="center">🔍 <b>A fast network scanning tool to detect open ports and security vulnerabilities</b></p>

<p align="center">
  <a href="https://github.com/choupit0/MassVulScan/tags"><img src="https://img.shields.io/github/v/tag/choupit0/MassVulScan?color=blue" alt="Tag"></a>
  <a href="https://github.com/choupit0/MassVulScan/issues"><img src="https://img.shields.io/github/issues/choupit0/MassVulScan?color=green" alt="Issues"></a>
  <a href="https://github.com/choupit0/MassVulScan/graphs/commit-activity"><img src="https://img.shields.io/github/last-commit/choupit0/MassVulScan?color=blue" alt="Last Commit"></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/made%20with-Bash-1f425f.svg" alt="Bash software"></a>
  <a href="https://github.com/choupit0/MassVulScan/blob/master/LICENSE"><img src="https://img.shields.io/github/license/choupit0/MassVulScan?color=brightgreen" alt="License"></a>
  <a href="https://github.com/choupit0/MassVulScan"><img src="https://img.shields.io/github/stars/choupit0/MassVulScan?color=yellow" alt="Stars"></a>
</p>

## 🌟 Overview
**MassVulScan** is a high-performance network scanning tool for pentesters (HackTheBox / HTB compatible) and system/network administrators looking to identify open ports and potential vulnerabilities on their internal/external networks. Built on powerful tools like `masscan` and `nmap`, it combines speed and accuracy to scan large-scale networks efficiently.

## 🎯 Features
- **Fast Port Scanning**: Built on `masscan` for quick open-port detection.
- **Vulnerability Detection**: Uses `nmap` scripts for detailed service analysis.
- **Optimized Scans**: Intelligent subnet filtering to avoid duplicates.
- **Platform Compatibility**: Runs on Linux, Debian OS family only.
- **Power of Bash**: Simplicity meets performance

## 📋 Changelog
[Changelog](https://github.com/choupit0/MassVulScan/blob/master/CHANGELOG.md)

### Last update
1.9.5 (2025-03-16)

**Améliorations ou changements/Implemented enhancements or changes:**
- Adding a new option "-h | --hosts" to scan one or more hosts via command-line argument (without using a file)

**Correction de bugs/Fixed bugs:**
- Fixing a bug in the exclusion of ports to scan (option -i and --exclude-ports)

## 📦 Installation
Ensure the following prerequisites are installed:

- **masscan** (version >= 1.0.5)
- **nmap** (version >= 7.60)
- **NSE vulners script**
- **xsltproc package**

```bash
# Clone the repository
git clone https://github.com/choupit0/MassVulScan.git

# Go to the project directory
cd MassVulScan

# Install dependencies (root or sudo)
./sources/installation.sh
```

### Additional parameters
| Parameter                   | Description                                                                        |
|-----------------------------|------------------------------------------------------------------------------------|
| `--auto-installation-latest`| compilation of the latest versions of `nmap` and `masscan` -> ~5 minutes (default) |
| `--auto-installation-apt`   | speedest but not the last versions -> ~1 minute                                    |

**Note about APT installation**
Warning, I detected an error with the APT version. There is a mistake of upstream. The Masscan version 1.0.5 tag points to
a commit that still contains 1.0.4 as version. But this is the correct code for the 1.0.5 version. https://github.com/robertdavidgraham/masscan/issues/566#issuecomment-798877419
(Thank you to https://github.com/rhertzog)

## 🛠️ How MassVulScan Works
**MassVulScan** follows a series of streamlined steps to identify active hosts, open ports, and potential vulnerabilities across your network:

1. **Quick Host Discovery** (optional): Uses `nmap` to identify online hosts efficiently.
2. **Rapid Port Scanning**: For each host, `masscan` performs an ultra-fast scan to detect open TCP/UDP ports.
3. **Data Organization**: Results are sorted to compile all detected ports and protocols by host. The organized data can be saved for later analysis (optional).
4. **Service and Vulnerability Detection**: Runs multiple parallel sessions (`nmap` + `vulners.nse`) to detect services and vulnerabilities, one session per host.
5. **Report Generation**: 
   - **HTML Report**: Contains detailed information on each host, including vulnerabilities, with a clean and accessible layout.
   - **TXT Report**: Focuses on potentially vulnerable hosts for quick reference.

The HTML report uses a Bootstrap stylesheet ([nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl)) for enhanced readability and a user-friendly format.

## 🚀 Usage
**File-based scanning mode:**

`targets.txt` containing a list of networks, IPs and/or hostnames to scan.

```bash
sudo ./MassVulScan.sh -f targets.txt
```

`exclude.txt` containing including IPv4 addresses (CIDR format compatible) to NOT scan.

```bash
sudo ./MassVulScan.sh -f targets.txt -x exclude.txt
```

**Command-line argument mode:**

```bash
sudo ./MassVulScan.sh -h 172.18.0.0/24 -r -c -a
```

**Full option list:**

```bash
sudo ./MassVulScan.sh -h
```

### ⚙️ Required options
| Option | Description                                                              |
|--------|--------------------------------------------------------------------------|
| `-h`   | Target host(s): IP address (CIDR format compatible)                      |
| `-f`   | File with IPs (CIDR format compatible) or hostnames to scan, one by line |

### ⚙️ Optional options
| Option | Description                                                                                              |
|--------|----------------------------------------------------------------------------------------------------------|
| `-x`   | Exclude these IPs (CIDR format compatible), one by line (e.g. gateways from your providers)              |
| `-i`   | Interactive mode: ports to scan, rate level and NSE script to use (e.g. vulners --script-args mincvss=5) |
| `-a`   | Scan all ports (TCP + UDP) at 1.5K pkts/sec with NSE vulners script                                      |
| `-c`   | Perform a pre-scanning to identify online hosts and scan only them                                       |
| `-r`   | Generate a TXT file including IPs scanned with open ports and protocols                                  |
| `-n`   | Quick mode without full Nmap scan to detect the hosts with open ports (no HTML report)                   |
| `-h`   | Show help                                                                                                |
| `-V`   | Show MassVulScan version                                                                                 |

By default the script will scan only the first 1000 TCP/UDP ports among the most common ports. You can find the list here: /usr/local/share/nmap/nmap-services. Similarly, the rate or number of packets per second is set to 1500 by default.

**Note that the script will detect if you have multiple network interfaces. This is important for Masscan, which will always used the interface that has the default route. You will be asked to choose one (no problem with Nmap).**

The script is also compatible with Nmap's categories (https://nmap.org/book/nse-usage.html#nse-categories) to search for specific vulnerabilities (the better known as ms17-010, EternalBlue) in addition to the CVEs identified from vulners.com.

## 🎬 GIF Demo
![Example Demo](demo/MassVulScan_Demo.gif)
##  📸 Some screenshots
![Example Masscan](screenshots/Masscan.PNG)

![Example Nmap](screenshots/Nmap.PNG)

![Example EOF](screenshots/Full-script.PNG)

![Example Vulnerable-hosts](screenshots/Ex-vulnerable-host-found.PNG)

![Example HTML](screenshots/HTML.PNG)

## 🐞 Known issues
No known issues.
## ✅ TODO
Improve the pre-scanning phase to identify online hosts (fping).

Manage better multiple IP addresses on one network interface.

Improve process of installation (install what is strictly necessary, comparison of versions).

~~Allow scanning a host without using an input file (command-line argument)~~

~~Improve the parsing of hosts file to detect duplicate networks, Ex: 10.10.18.0/24 and 10.10.18.0/28, and avoid duplicate scan.~~

## Star History

<a href="https://star-history.com/#choupit0/massvulscan&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=choupit0/massvulscan&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=choupit0/massvulscan&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=choupit0/massvulscan&type=Date" />
 </picture>
</a>
