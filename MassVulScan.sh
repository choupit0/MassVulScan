#!/bin/bash

############################################################################################################################
# 
# Script Name   : MassVulScan.sh
# Description   :
#  This script combines the high processing speed to find open ports (MassScan),
#  the effectiveness to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#  A beautiful report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports, and
#  finally a text file including specifically the potential vulnerables hosts is created.
# Author        : https://github.com/choupit0
# Site          : https://hack2know.how/
# Date          : 20190201
# Version       : 1.2   
# Usage         : ./MassVulScan.sh [[[-f file] [-e] file [-i] | [-h]]]
# Requirements  : Install MassScan (>=1.0.5), Nmap and vulners.nse (nmap script) to use this script.
#                 Xsltproc package is also necessary.
#                 Please, read the file "requirements.txt" if you need some help.
#
#############################################################################################################################

yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"

# Checking requirements
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(locate vulners.nse) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}""[X] There are some requirements to launch this script.""${end_color}"
	echo -e "${yellow_color}""[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):""${end_color}"
	echo "$(grep ^-- requirements.txt)"
	exit 1
	else
		masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
		nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
		if [[ ${masscan_version} < "1.0.5" ]]; then
			echo -e "${red_color}""[X] Masscan is not up to date.""${end_color}"
			echo "Please. Be sure to have the last Masscan version >= 1.0.5."
			echo "Your current version: ${masscan_version}"
			echo "https://github.com/robertdavidgraham/masscan"
			exit 1
		fi
		if [[ ${nmap_version} < "7.60" ]]; then
			echo -e "${red_color}""[X] Nmap is not up to date.""${end_color}"
			echo "Please. Be sure to have Nmap version >= 7.60."
			echo "Your current version: ${nmap_version}"
			echo "https://nmap.org/download.html"
			exit 1
		fi
fi

hosts="$1"
exclude_file=""
interactive="off"

# Logo
logo(){
if [[ $(which figlet) ]]; then
        my_logo="$(figlet -f mini -k MassVulScan)"
        echo -e "${green_color}""${my_logo}""${end_color}"
        else
                echo -e "${green_color}""                          __"
                echo -e "${green_color}""|\/|  _.  _  _ \  /    | (_   _  _. ._"
                echo -e "${green_color}""|  | (_| _> _>  \/ |_| | __) (_ (_| | |"
                echo -e "${end_color}"
fi
}

# Usage of script
usage(){
        logo
        echo -e "${blue_color}""${bold_color}""[-] Usage: Root user or sudo${end_color} ./$(basename "$0") [[[-f file] [-e file] [-i] | [-h]]]""${end_color}"
        echo -e "${yellow_color}""        -f | --include-file""${end_color}"
        echo -e "${bold_color}""          (mandatory parameter)""${end_color}"
        echo "          Input file including IPv4 addresses (no hostname) to scan, compatible with subnet mask."
        echo "          Example:"
        echo "                  # You can add a comment in the file"
        echo "                  10.10.4.0/24"
        echo "                  10.3.4.224"
        echo -e "${bold_color}""          By default: the top 1000 TCP/UDP ports are scanned with rate at 5K pkts/sec).""${end_color}"
        echo -e "${yellow_color}""        -e | --exclude-file""${end_color}"
        echo -e "${bold_color}""          (optional parameter)""${end_color}"
        echo "          Exclude file including IPv4 addresses (no hostname) do not scan, compatible with subnet mask."
        echo "          Example:"
        echo "                  # You can add a comment in the file"
        echo "                  10.10.4.128/25"
        echo "                  10.3.4.225"
        echo -e "${yellow_color}""        -i | --interactive""${end_color}"
        echo -e "${bold_color}""          (must be used in addition of \"-f\" parameter)""${end_color}"
        echo "          Interactive menu with extra parameters:"
        echo "                  - Ports to scan (Ex. -p1-65535 (all TCP ports)."
        echo "                  - Rate level (pkts/sec)."
        echo -e "${yellow_color}""        -h | --help""${end_color}"
        echo "          This help menu."
        echo ""
}

# No paramaters
if [[ "$1" == "" ]]; then
	usage
	exit 1
fi

# Available parameters
while [[ "$1" != "" ]]; do
        case "$1" in
                -f | --include-file )
                        shift
                        hosts="$1"
                        ;;
                -e | --exclude-file )
                        file_to_exclude="yes"
                        shift
                        exclude_file="$1"
                        ;;
                -i | --interactive )
                        interactive="on"
                        ;;
                -h | --help )
                        usage
                        exit 0
                        ;;
                * )
                        usage
                        exit 1
        esac
        shift
done

# Root user?
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}""[X] You are not the root.""${end_color}"
	echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
	echo -e "${red_color}""[X] Input file does not exist or is empty.""${end_color}"
	echo "Please, try again."
	exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}""[X] Exclude file does not exist or is empty.""${end_color}"
                echo "Please, try again."
                exit 1
        fi
fi

clear

# Interactive mode "on" or "off"?
if [[ ${interactive} = "on" ]]; then
        echo -e "${yellow_color}""[I] We will use the input file: ${hosts}""${end_color}"
        # Ports to scan?
        echo -e "${blue_color}""Now, which TCP/UDP port(s) do you want to scan?""${end_color}"
        echo -e "${blue_color}""[default: --top-ports 1000 (TCP/UDP), just typing \"Enter|Return\" key to continue]?""${end_color}"
        echo "(\"Top ports\" from list: /usr/local/share/nmap/nmap-services)"
        echo -e "${blue_color}""Usage example:""${end_color}"
        echo "  -p20-25,80                      to scan TCP ports in the range 20-25 and port 80"
        echo "  -p20-25,80 --exclude-ports 26   same thing as before and remove a port in the range"
        echo "  -p1-100,U:1-100                 to scan TCP and UDP range of ports"
        echo "  -pU:1-100                       to scan only UDP range of ports"
        echo "  -p1-65535,U:1-65535             all TCP AND UDP ports"
        read -p ">> " -r -t 60 ports_list
                if [[ -z ${ports_list} ]];then
                        ports="--top-ports 1000"
                        else
                                ports=${ports_list}
                fi
        echo -e "${yellow_color}""[I] Port(s) to scan: ${ports}""${end_color}"
        # Which rate?
        echo -e "${blue_color}""Which rate (pkts/sec)?""${end_color}"
        echo -e "${blue_color}""[default: --max-rate 5000, just typing \"Enter|Return\" key to continue]""${end_color}"
        echo -e "${red_color}""Be carreful, beyond \"10000\" it coud be dangerous for your network!!!""${end_color}"
        read -p ">> " -r -t 60 max_rate
                if [[ -z ${max_rate} ]];then
                        rate="5000"
                        else
                                rate=${max_rate}
                fi
        echo -e "${yellow_color}""[I] Rate chosen: ${rate}""${end_color}"
        else
                ports="--top-ports 1000"
                rate="5000"
fi

################
# Masscan part #
################

nb_hosts_masscan="$(grep -cv ^"#" "${hosts}")"
echo -e "${yellow_color}""[I] ${nb_hosts_masscan} ip(s) or subnet(s) to check.""${end_color}"
echo -e "${blue_color}""[-] Verifying Masscan parameters and running the tool...please, be patient!""${end_color}"	

if [[ ${exclude_file} = "" ]]; then
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" --max-rate "${rate}" -oL masscan-output.txt
	else
		sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}""[X] ERROR! Thanks to verify your parameters or your input/exclude file format. The script is ended.""${end_color}"
	exit 1
fi

echo -e "${green_color}""[V] Masscan phase is ended.""${end_color}"

if [[ -z masscan-output.txt ]]; then
	echo -e "${error_color}""[X] ERROR! File \"masscan-output.txt\" disapeared! The script is ended.""${end_color}"
	exit 1
fi

if [[ ! -s masscan-output.txt ]]; then
        echo -e "${green_color}""[!] No ip with open TCP/UDP ports found, so, exit! ->""${end_color}"
	rm -rf masscan-output.txt
	exit 0
	else
		udp_ports="$(grep -c "^open udp" masscan-output.txt)"
		tcp_ports="$(grep -c "^open tcp" masscan-output.txt)"
		echo -e "${red_color}""Hosts with open port(s):""${end_color}"
		grep ^open masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print "\t" i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
fi

#############
# Nmap part #
#############

nb_ports="$(grep -c ^open masscan-output.txt)"
nb_hosts_nmap="$(grep ^open masscan-output.txt | cut -d" " -f4 | sort | uniq -c | wc -l)"
echo -e "${yellow_color}""[I] ${nb_hosts_nmap} host(s) to scan concerning ${nb_ports} open ports""${end_color}"
echo -e "${blue_color}""[-] Launching Nmap scanner(s)...please, be patient!""${end_color}"

nmap_file(){
# Preparing the input file for Nmap
proto="$1"

# Source of inspiration: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
grep "^open ${proto}" masscan-output.txt | awk '/.+/ { \
				if (!($4 in ips_list)) { \
				value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s:%s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > nmap-input_"${proto}".txt
}

if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

# Directrory for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"

# Function for parallel Nmap scans
parallels_scans(){
ip="$(echo "$1" | cut -d":" -f1)"
port="$(echo "$1" | cut -d":" -f2)"

if [[ $2 == "nmap-input_tcp.txt" ]]; then
	nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n --script vulners -oA "${nmap_temp}"/"${ip}"_tcp_nmap-output "${ip}"
	else
		nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n --script vulners -oA "${nmap_temp}"/"${ip}"_udp_nmap-output "${ip}"
fi
}

for file in nmap-input_*.txt; do
	# We are launching all the Nmap scanners in the same time
	while IFS= read -r ip_to_scan; do
		parallels_scans "${ip_to_scan}" "${file}" &
	done < "${file}"
	wait
done

reset

echo -e "${green_color}""[V] Nmap phase is ended.""${end_color}"

###############
# Report part #
###############

nmap_bootstrap="./nmap-bootstrap.xsl"
date="$(date +%F_%H-%M-%S)"

# Verifying vulnerable hosts
vuln_hosts_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
vuln_ports_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"

if [[ ${vuln_hosts_count} != "0" ]]; then
	vuln_hosts="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done)"
	vuln_hosts_ip="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"

	echo -e "${red_color}""[X] ${vuln_hosts_count} vulnerable (or potentially vulnerable) host(s) found concerning ${vuln_ports_count} port(s):""${end_color}"
	echo -e -n "${vuln_hosts_ip}\n" | while read line; do
		host="$(host "${line}")"
		echo "${line}" "${host}" >> vulnerable_hosts.txt
	done

	vuln_hosts_format="$(awk '{print $1 "\t" $NF}' vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"
	echo -e -n "${vuln_hosts_format}\n"
	echo -e -n "\t----------------------------\n" > vulnerable_hosts_details_"${date}".txt
	echo -e -n "Report date: $(date)\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "${vuln_hosts_format}\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "All the details below." >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "\n\t----------------------------\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e -n "${vuln_hosts}\n" >> vulnerable_hosts_details_"${date}".txt
	echo -e "${yellow_color}""[I] All details on the vulnerabilities in TXT file: vulnerable_hosts_details_${date}.txt""${end_color}"
	
	else
		echo -e "${green_color}""[V] No vulnerable host found... at first sight!""${end_color}"
fi

# Merging all the Nmap XML files to one big XML file
echo "<?xml version=\"1.0\"?>" > nmap-output.xml
echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> nmap-output.xml
echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> nmap-output.xml
echo "<!-- nmap results file generated by MassVulScan.sh -->" >> nmap-output.xml
echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n --script vulners [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> nmap-output.xml
echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> nmap-output.xml

for i in ${nmap_temp}/*.xml; do
	sed -n -e '/<host /,/<\/host>/p' "$i" >> nmap-output.xml
done

echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> nmap-output.xml

# Using bootstrap to generate a beautiful HTML file (report)
xsltproc -o nmap-output_"${date}".html "${nmap_bootstrap}" nmap-output.xml 2>/dev/null

# End of script
echo -e "${yellow_color}""[I] Global HTML report generated: nmap-output_${date}.html, bye!""${end_color}"

rm -rf nmap-input_udp.txt nmap-input_tcp.txt masscan-output.txt vulnerable_hosts.txt nmap-output.xml "${nmap_temp}" 2>/dev/null

exit 0
