# Changelog
2.0.1 (2025-04-11)

**Correction de bugs/Fixed bugs:**

- Nmap 7.95 compilation issue resolved (e.g., Debian 12, Issue #4)
- Code review and cleanup
- Path issue resolved for certain generated reports (-h command with a host containing special characters)
- Missing packages and revision of their installation order

2.0.0 (2025-04-09)

**Améliorations ou changements/Implemented enhancements or changes:**

- Significant rewrite of Bash scripts
- Optimized installation: only installing missing packages and performs a prerequisites check only on the first run (speed gain)
- Improved version comparison for certain packages
- MassVulScan evolves: more modern, interactive, and visually appealing with Gum (interactive mode)
- Tool updates: compatibility with the latest versions of Nmap (7.95) and Masscan (1.3.2)
- Adding a new option "-d | --dns" to choose the (private or public) DNS server (default: 1.1.1.1)
- Adding a new option for NSE scripts to choose --script-args (e.g., `--script-args mincvss=5` (interactive mode)
- Some packages have been replaced to improve compatibility depending on the OS used

**Correction de bugs/Fixed bugs:**

- Fixing minor bugs

1.9.5 (2025-03-16)

**Améliorations ou changements/Implemented enhancements or changes:**

- Adding a new option "-h | --hosts" to scan one or more hosts via command-line argument (without using a file)

**Correction de bugs/Fixed bugs:**

- Fixing a bug in the exclusion of ports to scan (option -i and --exclude-ports)

1.9.4 (2024-10-24)

**Améliorations ou changements/Implemented enhancements or changes:**

- Detect and deduplicate CIDR subnets to avoid multiple scan
  E.g.: 10.10.18.0/28 is contained within 10.10.18.0/24 so we only keep 10.10.18.0/24 (the larger one)

1.9.3 (2024-04-23)

**Améliorations ou changements/Implemented enhancements or changes:**

- Much more efficient way to validate the IP addresses in input

1.9.2 (2023-03-28)

**Améliorations ou changements/Implemented enhancements or changes:**

- Code cleaning (shellcheck, symlink compatible now)

1.9.1 (2021-03-08)

**Améliorations ou changements/Implemented enhancements or changes:**

- Improved parsing of input files

**Correction de bugs/Fixed bugs:**

- no reported issue by the community

1.9.0 (2021-01-22)

**Améliorations ou changements/Implemented enhancements or changes:**

- Nmap 7.90 compatibility
- Masscan 1.3.0 compatibility
- Best parsing input and exclude files (script + ipcalc)
- Small cosmetic changes
- Some parameters changed
- Public DNS server by default for DNS queries/lookups (1.1.1.1 from cloudflare: https://1.1.1.1/)
- Reports name changed
- This changelog

**Correction de bugs/Fixed bugs:**

- Issue solved with some hosts file outside of MassVulScan folder
- Issue solved to find live hosts

