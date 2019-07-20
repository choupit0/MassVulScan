#!/bin/bash

############################################################################################################################
# 
# Script Name    : MassVulScan.sh
# Description    : This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#                  A beautiful report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports,
#                  and finally a text file including specifically the potential vulnerables hosts is created.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20190720
# Version        : 1.7.5
# Usage          : ./MassVulScan.sh [[-f file] + [-e file] [-i] [-a] [-c] | [-v] [-h]]
# Prerequisites  : Install MassScan (>=1.0.5), Nmap and vulners.nse (nmap script) to use this script.
#                  Xsltproc package is also necessary.
#                  Please, read the file "requirements.txt" if you need some help.
#                  With a popular OS from Debian OS family (e.g. Debian, Ubuntu, Linux Mint or Elementary),
#                  the installation of these prerequisites is automatic.
#
#############################################################################################################################

version="1.7.5"
yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"

# Root user?
root_user(){
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}[X] You are not the root.${end_color}"
	echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi
}

# Error status
proc_status(){
if [[ $? == "0" ]]; then
	echo -e "${yellow_color}Done.${end_color}"
	else
		echo -e "${red_color}Failed attempt -> check the log file: ${log_file}${end_color}"
fi
} 

# Installation of the prerequisites
prerequisites_install(){
# Disable CTRL+C
trap '' SIGINT

echo -e "${red_color}${bold_color}Warning: do not try to cancel the installation at this point!!!${end_color}"
echo -e "${blue_color}${bold_color}Installation in progress...Please, be patient!${end_color}"
echo -e "${blue_color}[Check the most recent log file in the folder \"log\" to see progression (tail -f [log file])]${end_color}"
echo -n -e "${blue_color}\r[-] Verifying space disk available...${end_color}"
sleep 1

# Checking available space disk
for folder in "/tmp" "/bin" "/usr"; do
	space_m="$(df --output=avail -BM ${folder} | tail -n 1 | grep -o "[0-9]*M")"
	space="$(df --output=avail -BM ${folder} | tail -n 1 | grep -o "[0-9]*")"
	if [[ ${space} -lt "250" ]]; then
		echo -e "${red_color}\nThere is no enough space available in the ${folder} folder: ${space_m}${end_color}"
		exit 1
	fi
done

echo -n -e "${blue_color}\r[-] Checking your Internet connexion...${end_color}"

# Checking the Internet connection
check_github_status="$(nc -z -v -w 1 github.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"
check_nmap_status="$(nc -z -v -w 1 nmap.org 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

if [[ ${check_github_status} == "open" ]] && [[ ${check_nmap_status} == "open" ]]; then
	temp_folder="$(mktemp -d /tmp/temp_folder-XXXXXXXX)"
	if [[ ! -d "./log" ]]; then
		mkdir "$(pwd)"/log
	fi
	log_file="$(pwd)/log/log_$(date +%F_%H-%M-%S).txt"
	# Prerequisites packages
	echo -n -e "\r                                       "
	echo -n -e "${blue_color}\r[-] Updating your package lists...${end_color}" && echo "---- APT UPDATE ---" &> "${log_file}"
	if [[ $(which apt) ]]; then
		apt update &>> "${log_file}"
		echo -n -e "${blue_color}\r[-] Installing the prerequisites packages...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
		apt install -y build-essential git wget tar libpcre3-dev libssl-dev libpcap-dev net-tools locate xsltproc &>> "${log_file}"
	elif [[ $(which apt-get) ]]; then
		apt-get update &>> "${log_file}"
		echo -n -e "${blue_color}\r[-] Installing the prerequisites packages...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
		apt-get install -y build-essential git wget tar libpcre3-dev libssl-dev libpcap-dev net-tools locate xsltproc &>> "${log_file}"
	fi
	proc_status
	# Packages Masscan, Nmap and NSE script Vulners.nse
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Masscan\", \"Nmap\" and \"Vulners.nse\"...${end_color}" && echo "---- DOWNLOAD SOURCES ---" &>> "${log_file}"
	cd "${temp_folder}"
	git clone https://github.com/robertdavidgraham/masscan.git &>> "${log_file}"
	git clone https://github.com/vulnersCom/nmap-vulners &>> "${log_file}"
	wget https://nmap.org/dist/nmap-7.70.tgz &>> "${log_file}"
	cd "${temp_folder}/masscan"
	echo -n -e "\r                                                                            "
	echo -n -e "${blue_color}\r[-] Compiling \"Masscan\" ...${end_color}" && echo "---- COMPILING MASSCAN ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Masscan\"...${end_color}" && echo "---- MASSCAN INSTALLATION ---" &>> "${log_file}"
	mv "bin/masscan" "/usr/bin/" &>> "${log_file}"
	proc_status
	cd "${temp_folder}"
	tar -xzf nmap-7.70.tgz &>> "${log_file}"
	cd "nmap-7.70"
	echo -n -e "${blue_color}\r[-] Resolving dependencies for \"Nmap\"...${end_color}" && echo "---- DEPENDENCIES FOR NMAP ---" &>> "${log_file}"
	./configure &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Compiling \"Nmap\" (this may take time)...${end_color}" && echo "---- COMPILING NMAP ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Nmap\"...${end_color}" && echo "---- NMAP INSTALLATION ---" &>> "${log_file}"
	make install &>> "${log_file}"
	proc_status
	echo -n -e "\r                                                            "
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Vulners.nse\"...${end_color}" && echo "---- VULNERS.NSE INSTALLATION ---" &>> "${log_file}"
	mv "${temp_folder}/nmap-vulners/vulners.nse" "/usr/local/share/nmap/scripts/"
	proc_status
	echo -n -e "\r                                              "
	echo -n -e "${blue_color}\r[-] Updating the databases...${end_color}" && echo "---- DATABASES UPDATE ---" &>> "${log_file}"
	updatedb &>> "${log_file}"
	nmap --script-updatedb &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Removing temporary files and folders...${end_color}" && echo "---- REMOVE TEMP FOLDERS ---" &>> "${log_file}"
	rm -rf "${temp_folder}" &>> "${log_file}"
	proc_status
	echo -n -e "\r                                           "
	echo -n -e "${green_color}\r[V] Installation finished.\n${end_color}"
	echo -n -e "${yellow_color}\r[I] Log file: ${log_file}\n${end_color}"
	echo -e "${blue_color}${bold_color}Please, now launch again the script to see options.\n${end_color}"
	else
		echo -e "${red_color}\nI can't reach Internet sites (\"github.com\" and \"nmap.org\") for downloading the packages...${end_color}"
		echo -e "${blue_color}${bold_color}Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
		exit 1
fi
}

# Automatic installation
auto_install_menu(){
if [[ $(which apt) ]] || [[ $(which apt-get) ]]; then
	echo -e "${blue_color}${bold_color}If you like, I can install the prerequisites for you (~5-10 minutes). Do you agree?${end_color}"
	echo -e "${blue_color}${bold_color}All these packages will be installed or updated:${end_color}"
	echo -e "${blue_color}\t--> From apt: build-essential git wget tar libpcre3-dev libssl-dev libpcap-dev net-tools locate xsltproc${end_color}"
	echo -e "${blue_color}\t--> From git: masscan vulners.nse${end_color}"
	echo -e "${blue_color}\t--> From source: nmap${end_color}"
	echo -e "${blue_color}${bold_color}[default: no, just typing \"Enter|Return\" key to exit or write \"yes\" to continue]${end_color}"
	read -p "Automatic installation? >> " -r -t 60 auto_install_answer
	if [[ -z ${auto_install_answer} ]] || [[ ${auto_install_answer} != "yes" ]];then
		echo -e "${yellow_color}""Okay, exit.""${end_color}"
	exit 1
	else
		root_user
		echo -e "${blue_color}${bold_color}[-] Great, we starting the installation...please, be patient!${end_color}"
		# Clearing the screen
		clear
		prerequisites_install
		exit 0
	fi
else
	echo -e "${blue_color}${bold_color}No APT package manager found on your system.${end_color}"
	echo -e "${yellow_color}[I] The automatic installation feature is only available for Debian OS family.${end_color}"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(locate vulners.nse) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${yellow_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	echo "$(grep ^-- "requirements.txt")"
	# Automatic installation for Debian OS family
	auto_install_menu
	else
		masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
		nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
		if [[ ${masscan_version} < "1.0.5" ]]; then
			echo -e "${red_color}[X] Masscan is not up to date.${end_color}"
			echo "Please. Be sure to have the last Masscan version >= 1.0.5."
			echo "Your current version is: ${masscan_version}"
			# Automatic installation for Debian OS family
			auto_install_menu
		fi
		if [[ ${nmap_version} < "7.60" ]]; then
			echo -e "${red_color}[X] Nmap is not up to date.${end_color}"
			echo "Please. Be sure to have Nmap version >= 7.60."
			echo "Your current version is: ${nmap_version}"
			# Automatic installation for Debian OS family
			auto_install_menu
		fi
fi

hosts="$1"
exclude_file=""
interactive="off"
check="off"

# Logo
logo(){
if [[ $(which figlet) ]]; then
        my_logo="$(figlet -f mini -k MassVulScan)"
        echo -e "${green_color}${my_logo}${end_color}"
        else
                echo -e "${green_color}                          __"
                echo -e "${green_color}|\/|  _.  _  _ \  /    | (_   _  _. ._"
                echo -e "${green_color}|  | (_| _> _>  \/ |_| | __) (_ (_| | |"
                echo -e "${end_color}"
fi
}

# Usage of script
usage(){
        logo
        echo -e "${blue_color}${bold_color}[-] Usage: Root user or sudo${end_color} ./$(basename "$0") [[-f file] + [-e file] [-i] [-a] [-c] | [-v] [-h]]"
        echo -e "${yellow_color}        -f | --include-file${end_color}"
        echo -e "${bold_color}          (mandatory parameter)${end_color}"
        echo "          Input file including IPv4 addresses (no hostname) to scan, compatible with subnet mask."
        echo "          Example:"
        echo "                  # You can add a comment in the file"
        echo "                  10.10.4.0/24"
        echo "                  10.3.4.224"
        echo -e "${bold_color}          By default: the top 1000 TCP/UDP ports are scanned and the maximum rate is fix to 5K pkts/sec.${end_color}"
        echo -e "${yellow_color}        -e | --exclude-file${end_color}"
        echo -e "${bold_color}          (optional parameter, must be used in addition of \"-f\" parameter)${end_color}"
        echo "          Exclude file including IPv4 addresses (no hostname) do not scan, compatible with subnet mask."
        echo "          Example:"
        echo "                  # You can add a comment in the file"
        echo "                  10.10.4.128/25"
        echo "                  10.3.4.225"
        echo -e "${yellow_color}        -i | --interactive${end_color}"
        echo -e "${bold_color}          (optional parameter, must be used in addition of \"-f\" parameter)${end_color}"
        echo "          Interactive menu with extra parameters:"
        echo "                  - Ports to scan (e.g. -p1-65535 (all TCP ports)."
        echo "                  - Rate level (pkts/sec)."
        echo -e "${yellow_color}        -a | --all-ports${end_color}"
        echo -e "${bold_color}          (optional parameter, must be used in addition of \"-f\" parameter)${end_color}"
        echo "          Scan all 65535 ports, TCP and UDP. The maximum rate is fix to 5K pkts/sec."
        echo -e "${yellow_color}        -c | --check${end_color}"
        echo -e "${bold_color}          (optional parameter, must be used in addition of \"-f\" parameter)${end_color}"
        echo "          Perform a pre-scanning to identify online hosts and scan only them."
        echo "          By default, all the IPs addresses will be tested, even if the host is unreachable."
        echo -e "${yellow_color}        -v | --version${end_color}"
        echo "          Script version."
        echo -e "${yellow_color}        -h | --help${end_color}"
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
                -a | --all-ports )
                        all_ports="on"
                       ;;
                -c | --check )
                        check="on"
                        ;;
                -h | --help )
                        usage
                        exit 0
                        ;;
                -v | --version )
                        echo -e "${yellow_color}[I] Script version is: ${bold_color}${version}${end_color}"
                        exit 0
                        ;;
               * )
                        usage
                        exit 1
        esac
        shift
done

root_user

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
	echo -e "${red_color}[X] Input file does not exist or is empty.${end_color}"
	echo "Please, try again."
	exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}[X] Exclude file does not exist or is empty.${end_color}"
                echo "Please, try again."
                exit 1
        fi
fi

clear

# Interactive mode "on" or "off"?
if [[ ${interactive} = "on" ]] && [[ ${all_ports} = "on" ]]; then
        echo -e "${red_color}Sorry, but you can't chose interactive (-i) mode with all ports scanning mode (-a).${end_color}"
	exit 1
elif [[ ${all_ports} = "on" ]]; then
        echo -e "${yellow_color}[I] Okay, 65535 ports to be scan both on TCP and UDP.${ports}${end_color}"
	ports="-p1-65535,U:1-65535"
	rate="5000"
elif [[ ${interactive} = "on" ]]; then
        echo -e "${yellow_color}[I] We will use the input file: ${hosts}${end_color}"
        # Ports to scan?
        echo -e "${blue_color}Now, which TCP/UDP port(s) do you want to scan?${end_color}"
        echo -e "${blue_color}[default: --top-ports 1000 (TCP/UDP), just typing \"Enter|Return\" key to continue]?${end_color}"
        echo "(\"Top ports\" from list: /usr/local/share/nmap/nmap-services)"
        echo -e "${blue_color}Usage example:${end_color}"
        echo "  -p20-25,80                      to scan TCP ports in the range 20-25 and port 80"
        echo "  -p20-25,80 --exclude-ports 26   same thing as before and remove a port in the range"
        echo "  -p1-100,U:1-100                 to scan TCP and UDP range of ports"
        echo "  -pU:1-100                       to scan only UDP range of ports"
        echo "  -p1-65535,U:1-65535             all TCP AND UDP ports"
        read -p "Port(s) to scan? >> " -r -t 60 ports_list
                if [[ -z ${ports_list} ]];then
                        ports="--top-ports 1000"
                        else
                                ports=${ports_list}
                fi
        echo -e "${yellow_color}[I] Port(s) to scan: ${ports}${end_color}"
        # Which rate?
        echo -e "${blue_color}Which rate (pkts/sec)?${end_color}"
        echo -e "${blue_color}[default: --max-rate 5000, just typing \"Enter|Return\" key to continue]${end_color}"
        echo -e "${red_color}Be carreful, beyond \"10000\" it coud be dangerous for your network!!!${end_color}"
        read -p "Rate ? >> " -r -t 60 max_rate
                if [[ -z ${max_rate} ]];then
                        rate="5000"
                        else
                                rate=${max_rate}
                fi
        echo -e "${yellow_color}[I] Rate chosen: ${rate}${end_color}"
        else
                ports="--top-ports 1000"
                rate="5000"
fi

################################################
# Checking if there are more than 2 interfaces #
################################################

interface="$(ip route | grep default | cut -d" " -f5)"
nb_interfaces="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -co "^[[:alnum:]]*")"

if [[ ${nb_interfaces} -gt "2" ]]; then
	interfaces_list="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -o "^[[:alnum:]]*")"
	interfaces_tab=(${interfaces_list})
	echo -e "${blue_color}${bold_color}Warning: multiple network interfaces have been detected:${end_color}"
	interfaces_loop="$(for index in "${!interfaces_tab[@]}"; do echo "${index}) ${interfaces_tab[${index}]}"; done)"
	echo -e "${blue_color}${interfaces_loop}${end_color}"
	echo -e "${blue_color}Which one do you want to use? [choose the corresponding number to the interface name]${end_color}"
	echo -e "${blue_color}(or typing \"Enter|Return\" key to use the one corresponding to the default route]${end_color}"
        read -p "Interface? >> " -r -t 60 interface_number
                if [[ -z ${interface_number} ]];then
        		echo -e "${yellow_color}No interface chosen...the script will use the one with the default route.${end_color}"
                        else
                                interface="${interfaces_tab[${interface_number}]}"
                fi
        echo -e "${yellow_color}[I] Network interface chosen: ${interface}${end_color}"
fi

##################################################
##################################################
## Okay, serious matters start there! Let's go! ##
##################################################
##################################################

###################################################
# 1/4 First analysis with Nmap to find live hosts #
###################################################

if [[ ${check} = "on" ]]; then

	echo -e "${blue_color}[-] Verifying how many hosts are online...please, be patient!${end_color}"	
	nmap -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${hosts}" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > temp-nmap-output
		if [[ $? != "0" ]]; then
			echo -e "${error_color}[X] ERROR! Thanks to verify your parameters or your input/exclude file format.${end_color}"
			echo -e "${error_color}[X] ERROR! Or maybe there is no host detected online. The script is ended.${end_color}"
			rm -rf temp-nmap-output
			exit 1
		fi

echo -e "${green_color}[V] Pre-scanning phase is ended.${end_color}"
hosts="temp-nmap-output"
nb_hosts_nmap="$(< "${hosts}" wc -l)"
echo -e "${yellow_color}[I] ${nb_hosts_nmap} ip(s) to check.${end_color}"

fi

########################################
# 2/4 Using Masscan to find open ports #
########################################

echo -e "${blue_color}[-] Verifying Masscan parameters and running the tool...please, be patient!${end_color}"

if [[ ${exclude_file} = "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt # > /dev/null 2>&1
	elif [[ ${exclude_file} = "" ]] && [[ $(id -u) != "0" ]]; then
		sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt # > /dev/null 2>&1
	elif [[ ${exclude_file} != "" ]] && [[ $(id -u) = "0" ]]; then
		masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt # > /dev/null 2>&1
	else
		sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt # > /dev/null 2>&1
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}[X] ERROR! Thanks to verify your parameters or your input/exclude file format. The script is ended.${end_color}"
	rm -rf masscan-output.txt
	exit 1
fi

echo -e "${green_color}[V] Masscan phase is ended.${end_color}"

if [[ -z masscan-output.txt ]]; then
	echo -e "${error_color}[X] ERROR! File \"masscan-output.txt\" disapeared! The script is ended.${end_color}"
	exit 1
fi

if [[ ! -s masscan-output.txt ]]; then
        echo -e "${green_color}[!] No ip with open TCP/UDP ports found, so, exit! ->${end_color}"
	rm -rf masscan-output.txt
	exit 0
	else
		udp_ports="$(grep -c "^open udp" masscan-output.txt)"
		tcp_ports="$(grep -c "^open tcp" masscan-output.txt)"
		echo -e "${red_color}Host(s) with open port(s):${end_color}"
		grep ^open masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print "\t" i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
fi

###########################################################################################
# 3/4 Identifying open services with Nmap and if they are vulnerable with vulners script  #
###########################################################################################

nb_ports="$(grep -c ^open masscan-output.txt)"
nb_hosts_nmap="$(grep ^open masscan-output.txt | cut -d" " -f4 | sort | uniq -c | wc -l)"

echo -e "${yellow_color}[I] ${nb_hosts_nmap} host(s) to scan concerning ${nb_ports} open ports${end_color}"

check_vulners_api_status="$(nc -z -v -w 1 vulners.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

if [[ ${check_vulners_api_status} == "open" ]]; then
	echo -e "${yellow_color}[I] Vulners.com site is reachable on port 443.${end_color}"
	else
		echo -e "${blue_color}${bold_color}Warning: Vulners.com site is NOT reachable on port 443. Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
		echo -e "${blue_color}${bold_color}So, vulnerability check will be not possible, only opened ports will be present in the HTML report.${end_color}"
fi 

echo -e "${blue_color}[-] Launching Nmap scanner(s)...please, be patient!${end_color}"

# Preparing the input file for Nmap
nmap_file(){
proto="$1"

# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
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

# Folder for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"

# Function for parallel Nmap scans
parallels_scans(){
ip="$(echo "$1" | cut -d":" -f1)"
port="$(echo "$1" | cut -d":" -f2)"

if [[ $2 == "nmap-input_tcp.txt" ]]; then
	nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n --script vulners -oA "${nmap_temp}/${ip}"_tcp_nmap-output "${ip}" # > /dev/null 2>&1
	else
		nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n --script vulners -oA "${nmap_temp}/${ip}"_udp_nmap-output "${ip}" # > /dev/null 2>&1
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

echo -e "${green_color}[V] Nmap phase is ended.${end_color}"

##########################
# 4/4 Generating reports #
##########################

nmap_bootstrap="./stylesheet/nmap-bootstrap.xsl"
date="$(date +%F_%H-%M-%S)"
report_folder="$(pwd)/reports/"

echo -e "${blue_color}${bold_color}Do you want giving a specific name to your report(s)?${end_color}"
echo -e "${blue_color}${bold_color}[if not, just pressing \"Enter|Return\" key]${end_color}"
read -p "Report(s) name? >> " -r -t 60 what_report_name
	if [[ -z ${what_report_name} ]];then
		global_report_name="global-report_"
		vulnerable_report_name="vulnerable_hosts_details_"
		else
			global_report_name="${what_report_name}_"
			vulnerable_report_name="${what_report_name}_vulnerable_hosts_"
	fi

# Verifying vulnerable hosts
vuln_hosts_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
vuln_ports_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"

if [[ ${vuln_hosts_count} != "0" ]]; then
	vuln_hosts="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done)"
	vuln_hosts_ip="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"

	echo -e "${red_color}\n[X] ${vuln_hosts_count} vulnerable (or potentially vulnerable) host(s) found concerning ${vuln_ports_count} port(s):${end_color}"
	echo -e -n "${vuln_hosts_ip}\n" | while read line; do
		host="$(host "${line}")"
		echo "${line}" "${host}" >> vulnerable_hosts.txt
	done

	vuln_hosts_format="$(awk '{print $1 "\t" $NF}' vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"
	echo -e -n "${vuln_hosts_format}\n"
	echo -e -n "\t----------------------------\n" > "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "Report date: $(date)\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "${vuln_hosts_format}\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "All the details below." >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "\n\t----------------------------\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"
	echo -e -n "${vuln_hosts}\n" >> "${report_folder}${vulnerable_report_name}${date}.txt"


	echo -e "${yellow_color}[I] All details on the vulnerabilities in this TXT file: ${report_folder}${vulnerable_report_name}${date}.txt${end_color}"
	
	else
		echo -e "${blue_color}${bold_color} No vulnerable host found... at first sight!.${end_color}"
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
xsltproc -o "${report_folder}${global_report_name}${date}.html" "${nmap_bootstrap}" nmap-output.xml 2>/dev/null

# End of script
echo -e "${yellow_color}[I] Global HTML report generated: ${report_folder}${global_report_name}${date}.html${end_color}"
echo -e "${green_color}[V] Report phase is ended, bye!${end_color}"

rm -rf temp-nmap-output nmap-input_udp.txt nmap-input_tcp.txt masscan-output.txt vulnerable_hosts.txt nmap-output.xml "${nmap_temp}" 2>/dev/null

exit 0
