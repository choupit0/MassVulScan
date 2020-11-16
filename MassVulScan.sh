#!/bin/bash

#############################################################################################################################
# 
# Script Name    : MassVulScan.sh
# Description    : This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#                  A beautiful report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports,
#                  and finally a text file including specifically the potential vulnerables hosts is created.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20200219
# Version        : 1.9.0
# Usage          : ./MassVulScan.sh [[-f file] + [-e file] [-i] [-a] [-c] [-k] [-ns] | [-h] [-v]]
# Prerequisites  : Install MassScan (>=1.0.5), Nmap and vulners.nse (nmap script) to use this script.
#                  Xsltproc package is also necessary.
#                  Please, read the file "requirements.txt" if you need some help.
#                  With a popular OS from Debian OS family (e.g. Debian, Ubuntu, Linux Mint or Elementary),
#                  the installation of these prerequisites is automatic.
#
#############################################################################################################################

version="1.9.0"
yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
source_installation="./sources/installation.sh"
source_top_tcp="./sources/top-ports-tcp-1000.txt"
source_top_udp="./sources/top-ports-udp-1000.txt"
script_start="$SECONDS"
report_folder="$(pwd)/reports/"

# Time elapsed 
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Root user?
root_user(){
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}[X] You are not the root.${end_color}"
	echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi
}

# Verifying if installation source file exist
source_file(){
if [[ -z ${source_installation} ]] || [[ ! -s ${source_installation} ]]; then
	echo -e "${red_color}[X] Source file \"${source_installation}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This script can install the prerequisites for you.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

# Verifying if top-ports source files exist
source_file_top(){
if [[ -z ${source_top_tcp} ]] || [[ ! -s ${source_top_tcp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_tcp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This file is a prerequisite to scan TCP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
elif [[ -z ${source_top_udp} ]] || [[ ! -s ${source_top_udp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_udp}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This file is a prerequisite to scan UDP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(locate vulners.nse) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${yellow_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	echo "$(grep ^-- "requirements.txt")"
	# Automatic installation for Debian OS family
	source_file
	source "${source_installation}"
	else
		masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
		nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
		if [[ ${masscan_version} < "1.0.5" ]]; then
			echo -e "${red_color}[X] Masscan is not up to date.${end_color}"
			echo "Please. Be sure to have the last Masscan version >= 1.0.5."
			echo "Your current version is: ${masscan_version}"
			# Automatic installation for Debian OS family
			source_file
			source "${source_installation}"
		fi
		if [[ ${nmap_version} < "7.60" ]]; then
			echo -e "${red_color}[X] Nmap is not up to date.${end_color}"
			echo "Please. Be sure to have Nmap version >= 7.60."
			echo "Your current version is: ${nmap_version}"
			# Automatic installation for Debian OS family
			source_file
			source "${source_installation}"
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
	echo -e "${yellow_color}[I] Version ${version}"
else
	echo -e "${green_color}                          __"
	echo -e "${green_color}|\/|  _.  _  _ \  /    | (_   _  _. ._"
	echo -e "${green_color}|  | (_| _> _>  \/ |_| | __) (_ (_| | |"
	echo -e "${end_color}"
	echo -e "${yellow_color}[I] Version ${version}"
fi
}

# Usage of script
usage(){
        logo
	echo -e "${blue_color}${bold_color}[-] Usage: Root user or sudo${end_color} ./$(basename "$0") [[-f file] + [-e file] [-i] [-a] [-c] [-k] [-ns] | [-v] [-h]]"
	echo -e "${blue_color}${bold_color}[-] Information: Bash script which identifies open network ports and any associated vulnerabilities.${end_color}"
	echo -e "${bold_color}    * Mandatory parameter:"
	echo -e "${yellow_color}        -f | --include-file${end_color}"
	echo "          Input file including IPv4 addresses and/or hostnames to scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.0/24"
	echo "                  webmail.acme.corp"
	echo -e "${bold_color}          By default: the top 1000 TCP/UDP ports are scanned, the rate is fix to 2.5K pkts/sec, and${end_color}"
	echo -e "${bold_color}          the NSE vulners.nse is used.${end_color}"
	echo -e "${bold_color}    * Optional parameters (must be used in addition of \"-f\" parameter):"
	echo -e "${yellow_color}        -e | --exclude-file${end_color}"
	echo "          Exclude file including IPv4 addresses (NO hostname) to NOT scan, compatible with subnet mask."
	echo "          Example:"
	echo "                  # You can add a comment in the file"
	echo "                  10.66.0.128/25"
	echo "                  10.66.6.225"
	echo -e "${yellow_color}        -i | --interactive${end_color}"
	echo "          Interactive menu with extra parameters:"
	echo "                  1) Ports to scan (e.g. -p1-65535 = all TCP ports)"
	echo "                  2) Rate level (pkts/sec)"
	echo "                  3) Nmap Scripting Engine (NSE) to use (default is vulners.nse)"
	echo -e "${yellow_color}        -a | --all-ports${end_color}"
	echo "          Scan all 65535 ports (TCP + UDP), the maximum rate is fix to 2K pkts/sec, and"
	echo "          the NSE vulners.nse script is used."
	echo -e "${yellow_color}        -c | --check${end_color}"
	echo "          Perform a pre-scanning to identify online hosts and scan only them."
	echo "          By default, all the IPs addresses will be tested, even if the host is unreachable."
	echo -e "${yellow_color}        -k | --keep-ips${end_color}"
	echo "          Keep IPs scanned with and without open ports and protocols in two files (same exiting file is overwritten)"
	echo "          By default, all the files used are deleted at the end of the script."
	echo "          Example:"
	echo "                  All_IPs_scanned_with_ports.txt:    tcp:10.66.6.11:25,443 webmail.acme.corp,smtp.acme.corp"
	echo "                                                     udp:10.66.6.12:53,137"
	echo "                  All_IPs_scanned_without_ports.txt: 10.66.6.11"
	echo -e "${yellow_color}        -ns | --no-nmap-scan${end_color}"
	echo "          Use only the script to detect the hosts with open ports (no reports provided)."
	echo -e "${yellow_color}        -h | --help${end_color}"
	echo "          This help menu."
	echo -e "${yellow_color}        -v | --version${end_color}"
	echo "          Script version."
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
                -k | --keep-ips )
                        keep="on"
                        ;;
                -ns | --no-nmap-scan )
                        no_nmap_scan="on"
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

# Checking if process already running
check_proc="$(ps -C "MassVulScan.sh" | grep -c "MassVulScan\.sh")"

if [[ ${check_proc} -gt "2" ]]; then
	echo -e "${red_color}[X] A process \"MassVulScan.sh\" is already running.${end_color}"
	exit 1
fi

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
	echo -e "${red_color}[X] Input file \"${hosts}\" does not exist or is empty.${end_color}"
	echo "Please, try again."
	exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}[X] Exclude file \"${exclude_file}\" does not exist or is empty.${end_color}"
                echo "Please, try again."
                exit 1
        fi
fi

# Cleaning old files
rm -rf IPs_hostnames_merged.txt file_with_IPs_and_hostnames.txt hosts_to_convert.txt \
hosts_converted.txt file_with_IPs_sorted temp-nmap-output nmap-input.temp.txt \
nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
file_with_uniq_IP_only.txt file_with_multiple_IPs_only.txt nmap-output.xml file_with_IPs_unsorted.txt \
All_IPs_scanned_without_ports_temp.txt /tmp/nmap_temp-* *_sorted 2>/dev/null

# Folder for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"

clear

##########################
# Parsing the input file #
##########################

echo -n -e "${blue_color}${bold_color}\r[-] Parsing the input file..."

# First parsing to translate the hostnames to IPs
num_hosts=$(grep -v "^#" ${hosts} | grep "\S" | grep -vEoc '([0-9]{1,3}\.){3}[0-9]{1,3}')

if [[ ${num_hosts} != "0" ]]; then

        # Saving IPs first
	if [[ $(grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}') ]]; then
		grep -v "^#" ${hosts} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' > file_with_IPs_only.txt
	fi

        # Filtering on the hosts only
        grep -v "^#" ${hosts} | grep "\S" | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' > hosts_to_convert.txt

        while IFS=, read -r host_to_convert; do
		host_ip=$(dig ${host_to_convert} +short | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
		echo $host_ip ${host_to_convert} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >> hosts_converted.txt
        done < hosts_to_convert.txt

fi

if [[ -s hosts_converted.txt ]]; then
	num_valid_hosts=$(sort -u hosts_converted.txt | wc -l)
	echo -n -e "${blue_color}${bold_color}\r${num_valid_hosts} Valid hostname(s) has been detected, we will translate them to IPv4 format:\n${end_color}"
fi	

if [[ -s file_with_IPs_only.txt ]]; then
	mv file_with_IPs_only.txt file_with_IPs_and_hostnames.txt
fi

# Second parsing to detect multiple IPs for the same hostname
if [[ -s hosts_converted.txt ]]; then
	while read line; do
		num_ips=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)

		if [[ ${num_ips} -gt "1" ]]; then
			# Filtering on the multiple IPs only
			hostname=$(echo ${line} | grep -oE '[^ ]+$')
			ips_list=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
			ips_tab=(${ips_list})
			ips_loop="$(for index in "${!ips_tab[@]}"; do echo "${ips_tab[${index}]} ${hostname}"; done)"

			echo "${ips_loop}" >> file_with_multiple_IPs_only.txt

		elif [[ ${num_ips} -eq "1" ]]; then
			# Saving uniq IP
			echo ${line} >> file_with_uniq_IP_only.txt
		fi
	done < hosts_converted.txt

	if [[ -s file_with_uniq_IP_only.txt ]]; then
		cat file_with_uniq_IP_only.txt >> file_with_IPs_and_hostnames.txt
	fi

	if [[ -s file_with_multiple_IPs_only.txt ]]; then
		cat file_with_multiple_IPs_only.txt >> file_with_IPs_and_hostnames.txt
	fi

	# Third parsing to detect duplicate IPs and keep the multiple hostnames
	# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html

	cat file_with_IPs_and_hostnames.txt | awk '/.+/ { \
				if (!($1 in ips_list)) { \
				value[++i] = $1 } ips_list[$1] = ips_list[$1] $2 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s %s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > file_with_IPs_unsorted.txt
fi

if [[ -s file_with_IPs_unsorted.txt ]]; then
	echo -e "${bold_color}$(cat file_with_IPs_unsorted.txt)${end_color}"
	cut -d" " -f1 file_with_IPs_unsorted.txt | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts}_sorted
else
        echo -n -e "${blue_color}${bold_color}\rOnly IPs has been detected in the input file.\n${end_color}"
	cut -d" " -f1 ${hosts} | sort -u | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts}_sorted
fi

hosts="${hosts}_sorted"	

# Interactive mode "on" or "off"?
top_ports_tcp="$(grep -v ^"#" sources/top-ports-tcp-1000.txt)"
top_ports_udp="$(grep -v ^"#" sources/top-ports-udp-1000.txt)"

if [[ ${interactive} = "on" ]] && [[ ${all_ports} = "on" ]]; then
        echo -e "${red_color}Sorry, but you can't chose interactive mode (-i) with all ports scanning mode (-a).${end_color}"
	exit 1
elif [[ ${all_ports} = "on" ]]; then
        echo -e "${yellow_color}[I] Okay, 65535 ports to be scan both on TCP and UDP.${ports}${end_color}"
	ports="-p1-65535,U:1-65535"
	rate="2000"
	script="vulners"
elif [[ ${interactive} = "on" ]]; then
        echo -e "${yellow_color}[I] We will use the input file: ${hosts}${end_color}"
        # Ports to scan?
        echo -e "${blue_color}${bold_color}Now, which TCP/UDP port(s) do you want to scan?${end_color}"
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
			source_file_top
                        ports="-p${top_ports_tcp},U:${top_ports_udp}"
			echo -e "${yellow_color}[I] Default parameter: --top-ports 1000 (TCP/UDP).${end_color}"
                        else
                                ports=${ports_list}
				echo -e "${yellow_color}[I] Port(s) to scan: ${ports}${end_color}"
                fi
        # Which rate?
        echo -e "${blue_color}${bold_color}Which rate (pkts/sec)?${end_color}"
        echo -e "${blue_color}[default: --max-rate 2500, just typing \"Enter|Return\" key to continue]${end_color}"
        echo -e "${red_color}Be carreful, beyond \"10000\" it coud be dangerous for your network!!!${end_color}"
        read -p "Rate? >> " -r -t 60 max_rate
                if [[ -z ${max_rate} ]];then
                        rate="2500"
			echo -e "${yellow_color}[I] Default parameter: --max-rate 2500.${end_color}"
                        else
                                rate=${max_rate}
				echo -e "${yellow_color}[I] Rate chosen: ${rate}${end_color}"
                fi

		# Which script?
	
	if [[ ${no_nmap_scan} != "on" ]]; then
		locate_scripts="$(locate vulners.nse | grep "/nmap/scripts/vulners.nse" | sed 's/vulners.nse//')"
		scripts_list="$(ls ${locate_scripts}*.nse 2>/dev/null)"

		# Verifying is Nmap folder scripts is present
		if [[ $? != "0" ]]; then
			echo -e "${red_color}[X] The Nmap folder does not exist or is empty (e.g. /usr/local/share/nmap/scripts/*.nse).${end_color}"
			echo -e "${yellow_color}[I] This script can install the prerequisites for you: ${source_installation}${end_color}"
			echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
		exit 1
		fi

		scripts_tab=(${scripts_list})
		scripts_loop="$(for index in "${!scripts_tab[@]}"; do echo "${index}) ${scripts_tab[${index}]}"; done)"
		echo -e "${blue_color}${scripts_loop}${end_color}"
		echo -e "${blue_color}${bold_color}Which Nmap Scripting Engine (NSE) to use?${end_color}"
		echo -e "${blue_color}[choose the corresponding number to the script name]${end_color}"
		echo -e "${blue_color}[or type the script name and args (e.g. ${bold_color}vulners --script-args mincvss=5)]${end_color}"
		echo -e "${blue_color}${bold_color}Or typing \"Enter|Return\" key to use the default on: vulners.nse${end_color}"
		read -p "Script number? >> " -r -t 60 script_number
	
			case "${script_number}" in
				[0-9]* )
					script="${scripts_tab[${script_number}]}"
					echo -e "${yellow_color}[I] Script name chosen: ${script}${end_color}"
					;;
				'' )
					script="vulners"
					echo -e "${yellow_color}[I] No script chosen, we will use the default one (vulners.nse).${end_color}"
					;;
				* )
					script=${script_number}
					echo -e "${yellow_color}[I] Script name and args chosen: ${script}${end_color}"
					;;
			esac
			
			# For bad numbers
			if [[ -z ${script} ]]; then
				echo -e "${red_color}[X] Please, choose the right number or the right categorie name.${end_color}"
				exit 1
			fi
	fi

        else
		if [[ ${no_nmap_scan} != "on" ]]; then	
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			rate="2500"
			script="vulners"
			echo -e "${yellow_color}[I] Default parameters: --top-ports 1000 (TCP/UDP), --max-rate 2500 and Vulners script (NSE).${end_color}"
		else
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			rate="2500"
			echo -e "${yellow_color}[I] Default parameters: --top-ports 1000 (TCP/UDP) and --max-rate 2500 (no Nmap Scan).${end_color}"
		fi
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
	echo -e "${blue_color}${bold_color}Which one do you want to use? [choose the corresponding number to the interface name]${end_color}"
	echo -e "${blue_color}${bold_color}Or typing \"Enter|Return\" key to use the one corresponding to the default route${end_color}"
        read -p "Interface number? >> " -r -t 60 interface_number
                if [[ -z ${interface_number} ]];then
        		echo -e "${yellow_color}[I] No interface chosen, we will use the one with the default route.${end_color}"
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
			time_elapsed			
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
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
elif [[ ${exclude_file} = "" ]] && [[ $(id -u) != "0" ]]; then
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
elif [[ ${exclude_file} != "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt
else
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${exclude_file}" --max-rate "${rate}" -oL masscan-output.txt
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
	time_elapsed
	exit 0
	else
		tcp_ports="$(grep -c "^open tcp" masscan-output.txt)"
		udp_ports="$(grep -c "^open udp" masscan-output.txt)"
		nb_ports="$(grep -c ^open masscan-output.txt)"
		nb_hosts_nmap="$(grep ^open masscan-output.txt | cut -d" " -f4 | sort | uniq -c | wc -l)"
		echo -e "${yellow_color}[I] ${nb_hosts_nmap} host(s) concerning ${nb_ports} open ports.${end_color}"
fi

###########################################################################################
# 3/4 Identifying open services with Nmap and if they are vulnerable with vulners script  #
###########################################################################################

# Output file with hostnames
merge_ip_hostname(){
cat nmap-input.txt | while IFS=, read -r line; do
	search_ip=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

	if [[ $(grep "${search_ip}" file_with_IPs_unsorted.txt) ]] 2>/dev/null; then

		if [[ $(grep "${search_ip}" file_with_IPs_unsorted.txt | awk -F" " '{print $2}') ]]; then
			search_hostname=$(grep "${search_ip}" file_with_IPs_unsorted.txt | awk -F" " '{print $2}')
			echo "${line} ${search_hostname}" >> IPs_hostnames_merged.txt
		else
			echo "${line}" >> IPs_hostnames_merged.txt
		fi
	else
		echo "${line}" >> IPs_hostnames_merged.txt
	fi
done
}

# Hosts list scanned
hosts_scanned(){
	echo -e "${bold_color}Host(s) discovered with an open port(s):${end_color}"
	grep ^open masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
}

# Preparing the input file for Nmap
nmap_file(){
proto="$1"

# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
grep "^open ${proto}" masscan-output.txt | awk '/.+/ { \
				if (!($4 in ips_list)) { \
				value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s:%s:%s\n%s", $2, value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' >> nmap-input.temp.txt
}

rm -rf nmap-input.temp.txt

if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 nmap-input.temp.txt > nmap-input.txt

if [[ ${no_nmap_scan} != "on" ]]; then
	# If we are using Vulners.nse script, check if vulners.com site is reachable
	if [[ ${script} == "vulners" ]]; then
		check_vulners_api_status="$(nc -z -v -w 1 vulners.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

		if [[ ${check_vulners_api_status} == "open" ]]; then
			echo -e "${yellow_color}[I] Vulners.com site is reachable on port 443.${end_color}"
			else
				echo -e "${blue_color}${bold_color}Warning: Vulners.com site is NOT reachable on port 443. Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
				echo -e "${blue_color}${bold_color}So, vulnerability check will be not possible, only opened ports will be present in the report.${end_color}"
		fi
	fi

	nb_nmap_process="$(sort -n nmap-input.txt | wc -l)"

	# Keep the nmap input file?
	if [[ ${keep} == "on" ]]; then
		hosts_scanned
		merge_ip_hostname
		mv IPs_hostnames_merged.txt ${report_folder}All_IPs_scanned_with_ports.txt
		grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' nmap-input.txt | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
		echo -e "${yellow_color}[I] All the IPs scanned are in these 2 files:${end_color}"
		echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
		echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"
	fi

	# Function for parallel Nmap scans
	parallels_scans(){
	proto="$(echo "$1" | cut -d":" -f1)"
	ip="$(echo "$1" | cut -d":" -f2)"
	port="$(echo "$1" | cut -d":" -f3)"

	if [[ $proto == "tcp" ]]; then
		nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n --script ${script} -oA "${nmap_temp}/${ip}"_tcp_nmap-output "${ip}" > /dev/null 2>&1
		echo "${ip} (${proto}): Done" >> process_nmap_done.txt
		else
			nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n --script ${script} -oA "${nmap_temp}/${ip}"_udp_nmap-output "${ip}" > /dev/null 2>&1
			echo "${ip} (${proto}): Done" >> process_nmap_done.txt
	fi

	nmap_proc_ended="$(grep "$Done" -co process_nmap_done.txt)"
	pourcentage="$(awk "BEGIN {printf \"%.2f\n\", "${nmap_proc_ended}/${nb_nmap_process}*100"}")"
	echo -n -e "\r                                                                                                         "
	echo -n -e "${yellow_color}${bold_color}\r[I] Scan is done for ${ip} (${proto}) -> ${nmap_proc_ended}/${nb_nmap_process} Nmap process launched...(${pourcentage}%)${end_color}"

	}

	# Controlling the number of Nmap scanner to launch
	if [[ ${nb_nmap_process} -ge "50" ]]; then
		max_job="50"
		echo -e "${blue_color}${bold_color}Warning: A lot of Nmap process to launch: ${nb_nmap_process}${end_color}"
		echo -e "${blue_color}[-] So, to no disturb your system, I will only launch ${max_job} Nmap process at time.${end_color}"
		else
			echo -e "${blue_color}${bold_color}[-] Launching ${nb_nmap_process} Nmap scanner(s) in the same time...${end_color}"
			max_job="${nb_nmap_process}"
	fi

	# Queue files
	new_job(){
	job_act="$(jobs | wc -l)"
	while ((job_act >= ${max_job})); do
		job_act="$(jobs | wc -l)"
	done
	parallels_scans "${ip_to_scan}" &
	}

	# We are launching all the Nmap scanners in the same time
	count="1"

	rm -rf process_nmap_done.txt

	while IFS=, read -r ip_to_scan; do
		new_job $i
		count="$(expr $count + 1)"
	done < nmap-input.txt

	wait

	sleep 2 && tset

	echo -e "${green_color}[V] Nmap phase is ended.${end_color}"

	# Verifying vulnerable hosts
	vuln_hosts_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
	vuln_ports_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"
	vuln_hosts="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done)"
	vuln_hosts_ip="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"
	date="$(date +%F_%H-%M-%S)"

	if [[ ${vuln_hosts_count} != "0" ]]; then
		echo -e "${red_color}[X] ${vuln_hosts_count} vulnerable (or potentially vulnerable) host(s) found.${end_color}"
		echo -e -n "${vuln_hosts_ip}\n" | while read line; do
			host="$(dig -x "${line}" +short)"
			echo "${line}" "${host}" >> vulnerable_hosts.txt
		done
	
		vuln_hosts_format="$(awk '{print $1 "\t" $NF}' vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"
		echo -e -n "\t----------------------------\n" > "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "Report date: $(date)\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "${vuln_hosts_format}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "All the details below." >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "\n\t----------------------------\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
		echo -e -n "${vuln_hosts}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	else
		echo -e "${blue_color}No vulnerable host found... at first sight!.${end_color}"

	fi

elif [[ ${no_nmap_scan} == "on" ]] && [[ ${keep} == "on" ]]; then
	echo -e "${yellow_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat IPs_hostnames_merged.txt)${end_color}"
	mv IPs_hostnames_merged.txt ${report_folder}All_IPs_scanned_with_ports.txt
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' nmap-input.txt | sort -u > ${report_folder}All_IPs_scanned_without_ports.txt
	echo -e "${yellow_color}[I] All the IPs scanned are in these 2 files:${end_color}"
	echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_with_ports.txt${end_color}"
	echo -e "${blue_color}-> ${report_folder}All_IPs_scanned_without_ports.txt${end_color}"

else
	echo -e "${yellow_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat IPs_hostnames_merged.txt)${end_color}"
fi

##########################
# 4/4 Generating reports #
##########################

if [[ ${no_nmap_scan} != "on" ]]; then
	nmap_bootstrap="./stylesheet/nmap-bootstrap.xsl"

	echo -e "${blue_color}${bold_color}Do you want giving a specific name to your report(s)?${end_color}"
	echo -e "${blue_color}${bold_color}[if not, just pressing \"Enter|Return\" key for a generic name]${end_color}"
	read -p "Report(s) name? >> " -r -t 60 what_report_name
		if [[ -z ${what_report_name} ]];then
			global_report_name="global-report_"
			vulnerable_report_name="vulnerable_hosts_details_"
			else
				global_report_name="${what_report_name}_"
				vulnerable_report_name="${what_report_name}_vulnerable_hosts_"
		fi

	if [[ -s ${report_folder}vulnerable_hosts_details_${date}.txt ]] && [[ ${report_folder}vulnerable_hosts_details_${date}.txt != ${report_folder}${vulnerable_report_name}${date}.txt ]]; then
		mv ${report_folder}vulnerable_hosts_details_${date}.txt ${report_folder}${vulnerable_report_name}${date}.txt
		echo -e "${yellow_color}[I] All details on the vulnerabilities:"
		echo -e "${blue_color}-> ${report_folder}${vulnerable_report_name}${date}.txt${end_color}"
	elif [[ -s ${report_folder}vulnerable_hosts_details_${date}.txt ]] && [[ ${report_folder}vulnerable_hosts_details_${date}.txt == ${report_folder}${vulnerable_report_name}${date}.txt ]]; then
		echo -e "${yellow_color}[I] All details on the vulnerabilities:"
		echo -e "${blue_color}-> ${report_folder}vulnerable_hosts_details_${date}.txt${end_color}"
	fi

	# Merging all the Nmap XML files to one big XML file
	echo "<?xml version=\"1.0\"?>" > nmap-output.xml
	echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> nmap-output.xml
	echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> nmap-output.xml
	echo "<!-- nmap results file generated by MassVulScan.sh -->" >> nmap-output.xml
	echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n --script ${script} [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> nmap-output.xml
	echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> nmap-output.xml

	for i in ${nmap_temp}/*.xml; do
		sed -n -e '/<host /,/<\/host>/p' "$i" >> nmap-output.xml
	done

	echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
	      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> nmap-output.xml

	# Using bootstrap to generate a beautiful HTML file (report)
	xsltproc -o "${report_folder}${global_report_name}${date}.html" "${nmap_bootstrap}" nmap-output.xml 2>/dev/null

	# End of script
	echo -e "${yellow_color}[I] Global HTML report generated:"
	echo -e "${blue_color}-> ${report_folder}${global_report_name}${date}.html${end_color}"
	echo -e "${green_color}[V] Report phase is ended, bye!${end_color}"
else
	echo -e "${yellow_color}[I] No reports to produce with --no-nmap-scan parameter.${end_color}"

fi

rm -rf IPs_hostnames_merged.txt file_with_IPs_and_hostnames.txt hosts_to_convert.txt \
hosts_converted.txt file_with_IPs_sorted temp-nmap-output nmap-input.temp.txt \
nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
file_with_uniq_IP_only.txt file_with_multiple_IPs_only.txt nmap-output.xml file_with_IPs_unsorted.txt \
All_IPs_scanned_without_ports_temp.txt "${nmap_temp}" ${hosts} 2>/dev/null

time_elapsed

exit 0
