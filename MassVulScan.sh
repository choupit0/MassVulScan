#!/bin/bash

#    This file is part of MassVulScan.
#
#    Copyright (C) 2021 choupit0
#
#    MassVulScan is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    MassVulScan is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with MassVulScan.  If not, see <https://www.gnu.org/licenses/>.
# 
# Script Name    : MassVulScan.sh
# Description    : This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#                  A beautiful report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports,
#                  and finally a text file including specifically the potential vulnerables hosts is created.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20230328
# Version        : 1.9.2
# Usage          : ./MassVulScan.sh [[-f file] + [-x file] [-i] [-a] [-c] [-r] [-n] | [-h] [-V]]
# Prerequisites  : Install MassScan (>=1.0.5), Nmap and vulners.nse (nmap script) to use this script.
#                  Xsltproc and ipcalc packages are also necessary.
#                  Please, read the file "requirements.txt" if you need some help.
#                  With a popular OS from Debian OS family (e.g. Debian, Ubuntu, Linux Mint or Elementary),
#                  the installation of these prerequisites is automatic.
#

version="1.9.2"
purple_color="\033[1;35m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
dir_name="$(dirname -- "$( readlink -f -- "$0"; )")"
source_installation="${dir_name}/sources/installation.sh"
source_top_tcp="${dir_name}/sources/top-ports-tcp-1000.txt"
source_top_udp="${dir_name}/sources/top-ports-udp-1000.txt"
report_folder="${dir_name}/reports/"
nmap_scripts_folder="/usr/local/share/nmap/scripts/"
script_start="$SECONDS"
# Name server used for the DNS queries/lookups
# Change it for your private DNS server if you want scan your private LAN
dns="1.1.1.1"

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
	echo -e "${purple_color}[I] This script can install the prerequisites for you.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

# Verifying if top-ports source files exist
source_file_top(){
if [[ -z ${source_top_tcp} ]] || [[ ! -s ${source_top_tcp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_tcp}\" does not exist or is empty.${end_color}"
	echo -e "${purple_color}[I] This file is a prerequisite to scan TCP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
elif [[ -z ${source_top_udp} ]] || [[ ! -s ${source_top_udp} ]]; then
	echo -e "${red_color}[X] Source file \"${source_top_udp}\" does not exist or is empty.${end_color}"
	echo -e "${purple_color}[I] This file is a prerequisite to scan UDP top ports.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(locate vulners.nse) ]] || [[ ! $(which xsltproc) ]] || [[ ! $(which ipcalc) ]]; then
	echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${purple_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	grep ^-- "${dir_name}/requirements.txt"
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
	echo -e "${purple_color}[Identify open network ports and any associated vulnerabilities]${end_color}"
	echo -e "${purple_color}[I] Version ${version}"
else
	echo -e "${green_color}                          __"
	echo -e "${green_color}|\/|  _.  _  _ \  /    | (_   _  _. ._"
	echo -e "${green_color}|  | (_| _> _>  \/ |_| | __) (_ (_| | |"
	echo -e "${end_color}"
	echo -e "${purple_color}[Identify open network ports and any associated vulnerabilities]${end_color}"
	echo -e "${purple_color}[I] Version ${version}"
fi
}

# Usage of script
usage(){
        logo
	echo -e "${blue_color}${bold_color}[-] Usage: Root user or sudo ./$(basename "$0") [[-f file] + [-x file] [-i] [-a] [-c] [-r] [-n] | [-V] [-h]]${end_color}"
	echo -e "${bold_color}    * Mandatory parameter:"
	echo -e "${purple_color}        -f | --include-file${end_color} \tFile including IPv4 addresses (CIDR format) or hostnames to scan (one by line)"
	echo -e "${bold_color}    * Optional parameters (must be used in addition of \"-f\" parameter):"
	echo -e "${purple_color}        -x | --exclude-file${end_color} \tFile including IPv4 addresses ONLY (CIDR format) to NOT scan (one by line)"
	echo -e "${purple_color}        -i | --interactive${end_color} \tExtra parameters: ports to scan, rate level and NSE script"
	echo -e "${purple_color}        -a | --all-ports${end_color} \tScan all 65535 ports (TCP + UDP) at 2K pkts/sec with NSE vulners script"
	echo -e "${purple_color}        -c | --check${end_color} \t\tPerform a pre-scanning to identify online hosts and scan only them"
	echo -e "${purple_color}        -r | --report${end_color} \t\tFile including IPs scanned with open ports and protocols"
	echo -e "${purple_color}        -n | --no-nmap-scan${end_color} \tUse only the script to detect the hosts with open ports (no HTML report)"
	echo -e "${bold_color}      Information:"
	echo -e "${purple_color}        -h | --help${end_color} \t\tThis help menu"
	echo -e "${purple_color}        -V | --version${end_color} \t\tScript version"
	echo ""
}

# No paramaters
if [[ "$1" == "" ]]; then
	echo -e "${red_color}\n[X] Missing parameter.${end_color}"
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
                -x | --exclude-file )
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
                -r | --report )
                        report="on"
                        ;;
                -n | --no-nmap-scan )
                        no_nmap_scan="on"
                        ;;
                -h | --help )
                        usage
                        exit 0
                        ;;
                -V | --version )
                        echo -e "${purple_color}[I] Script version for $(basename "$0"): ${bold_color}${version}${end_color}"
                        exit 0
                        ;;
                * )
			echo -e "${red_color}\n[X] One parameter is missing or does not exist.${end_color}"
                        usage
                        exit 1
        esac
        shift
done

root_user

# Checking if process already running
check_proc="$(pgrep -i massvulscan | wc -l)"

if [[ ${check_proc} -gt "2" ]]; then
	echo -e "${red_color}[X] A process is already running.${end_color}"
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

# Complete path to the "hosts" file
hosts="$(readlink -f "$hosts")"

# Cleaning old files - if the script is ended before the end (CTRL + C)
rm -rf /tmp/temp_dir-* /tmp/temp_nmap-* paused.conf 2>/dev/null

# Folder for temporary file(s)
temp_dir="$(mktemp -d /tmp/temp_dir-XXXXXXXX)"
temp_nmap="$(mktemp -d /tmp/temp_nmap-XXXXXXXX)"

clear

if [[ ${hosts} == "" ]]; then
        echo -n -e "${red_color}\r[X] Please, set a hosts file in parameter.\n${end_color}"
        exit 1
elif [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
        echo -n -e "${red_color}\r[X] The file \"${hosts}\" does not exist or is empty.\n${end_color}"
        exit 1
fi

#######################################
# Parsing the input and exclude files #
#######################################
num_hostnames_init=$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -vEc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
num_ips_init=$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')

valid_ip(){
ip_to_check="$1"
if [[ $(ipcalc "${ip_to_check}" | grep -c "INVALID") == "0" ]]; then
        is_valid="yes"
else
        is_valid="no"
fi
}

echo -n -e "\r                                                                                                                 "
echo -n -e "${blue_color}\r[-] Parsing the input file (DNS lookups, duplicate IPs, multiple hostnames and valid IPs)...${end_color}"

# Saving IPs first
if [[ ${num_ips_init} -gt "0" ]]; then
        ips_tab_init=("$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')")
        printf '%s\n' "${ips_tab_init[@]}" | while IFS=, read -r check_ip; do
                valid_ip "${check_ip}"
                if [[ "${is_valid}" == "yes" ]]; then
                        echo "${check_ip}" >> "${temp_dir}"/IPs.txt
                else
                        echo -n -e "${red_color}\r[X] \"${check_ip}\" is not a valid IPv4 address and/or subnet mask                           \n${end_color}"
                fi
        done
fi

# First parsing to translate the hostnames to IPs
if [[ ${num_hostnames_init} != "0" ]]; then
        # Filtering on the hosts only
        hostnames_tab=("$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)")

        # Conversion to IPs
        printf '%s\n' "${hostnames_tab[@]}" | while IFS=, read -r host_to_convert; do
                search_ip=$(dig @${dns} "${host_to_convert}" +short | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
                if [[ ${search_ip} != "" ]]; then
                        echo "${search_ip}" "${host_to_convert}" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "${temp_dir}"/hosts_converted.txt
                else
                        echo -n -e "\r                                                                                                                 "
                        echo -n -e "${red_color}\r[X] No IP found for hostname \"${host_to_convert}\".\n${end_color}"
                fi
        done
fi

# Second parsing to detect multiple IPs for the same hostname
if [[ -s ${temp_dir}/hosts_converted.txt ]]; then
        #ips_found="$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "${temp_dir}"/hosts_converted.txt | sort -u | wc -l)"
        while IFS=, read -r line; do
                check_ips="$(echo "${line}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)"

                # Filtering on the multiple IPs only
                if [[ ${check_ips} -gt "1" ]]; then
                        hostname=$(echo "${line}" | grep -oE '[^ ]+$')
                        ips_list=$(echo "${line}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
                        ips_tab=(${ips_list})
                        ips_loop="$(for index in "${!ips_tab[@]}"; do echo "${ips_tab[${index}]} ${hostname}"; done)"

                        echo "${ips_loop}" >> "${temp_dir}"/multiple_IPs.txt
                elif [[ ${check_ips} -eq "1" ]]; then
                        # Saving uniq IP
                        echo "${line}" >> "${temp_dir}"/uniq_IPs.txt
                fi
        done < "${temp_dir}"/hosts_converted.txt

        if [[ -s ${temp_dir}/uniq_IPs.txt ]]; then
                cat "${temp_dir}"/uniq_IPs.txt >> "${temp_dir}"/IPs_and_hostnames.txt
                rm -rf "${temp_dir}"/uniq_IPs.txt 2>/dev/null
        fi

        if [[ -s ${temp_dir}/multiple_IPs.txt ]]; then
                cat "${temp_dir}"/multiple_IPs.txt >> "${temp_dir}"/IPs_and_hostnames.txt
                rm -rf "${temp_dir}"/multiple_IPs.txt 2>/dev/null
        fi

        # Third parsing to detect duplicate IPs and keep the multiple hostnames

        cat "${temp_dir}"/IPs_and_hostnames.txt | awk '/.+/ { \
                if (!($1 in ips_list)) { \
                value[++i] = $1 } ips_list[$1] = ips_list[$1] $2 "," } END { \
                for (j = 1; j <= i; j++) { \
                printf("%s %s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > "${temp_dir}"/IPs_unsorted.txt
        rm -rf "${temp_dir}"/IPs_and_hostnames.txt
fi

if [[ ! -s ${temp_dir}/IPs_unsorted.txt ]] && [[ ! -s ${temp_dir}/IPs.txt ]]; then
        echo -n -e "${red_color}\r[X] No valid host found.\n${end_color}"
        exit 1
fi

hosts_file_no_path="$(basename "$hosts")"

if [[ -s ${temp_dir}/IPs_unsorted.txt ]] && [[ -s ${temp_dir}/IPs.txt ]]; then
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        cat "${temp_dir}"/IPs.txt >> "${temp_dir}"/IPs_unsorted.txt
        rm -rf "${temp_dir}"/IPs.txt
        sort -u "${temp_dir}"/IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${hosts_file_no_path}"_parsed
        rm -rf "${temp_dir}"/IPs_unsorted.txt
        cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
elif [[ -s ${temp_dir}/IPs_unsorted.txt ]]; then
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        sort -u "${temp_dir}"/IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${hosts_file_no_path}"_parsed
        rm -rf "${temp_dir}"/IPs_unsorted.txt
        cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
else
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        mv "${temp_dir}"/IPs.txt "${temp_dir}"/"${hosts_file_no_path}"_parsed
        cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
fi

hosts_file="${temp_dir}/${hosts_file_no_path}_parsed"

if [[ ${exclude_file} != "" ]]; then
	# Complete path to the "hosts" file
	exclude_file="$(readlink -f "$exclude_file")"
	echo -n -e "\r                                                                                                                 "
	echo -n -e "${blue_color}\r[-] Parsing the exclude file (valid IPv4 addresses ONLY)...${end_color}"
	num_xips_init=$(grep -Ev '^[[:punct:]]|[[:punct:]]$' "${exclude_file}" | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
	if [[ ${num_xips_init} -gt "0" ]]; then
		xips_tab_init=("$(grep -Ev '^[[:punct:]]|[[:punct:]]$' "${exclude_file}" | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')")
		printf '%s\n' "${xips_tab_init[@]}" | while IFS=, read -r check_ip; do
			valid_ip "${check_ip}"
			if [[ "${is_valid}" == "yes" ]]; then
				echo "${check_ip}" >> "${temp_dir}"/xIPs.txt
			else
				echo -n -e "${red_color}\r[X] \"${check_ip}\" is not a valid IPv4 address and/or subnet mask to exclude                    \n${end_color}"
			fi
		done
	fi
fi

xhosts_file_no_path="$(basename "$exclude_file")"

if [[ -s ${temp_dir}/xIPs.txt ]]; then
        echo -n -e "\r                                                                                            "
        echo -n -e "${purple_color}\r[I] Valid host(s) to exclude:\n${end_color}"
        sort -u "${temp_dir}"/xIPs.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${xhosts_file_no_path}"_parsed
        rm -rf "${temp_dir}"/xIPs.txt
        cat "${temp_dir}"/"${xhosts_file_no_path}"_parsed

fi

xhosts_file="${temp_dir}/${xhosts_file_no_path}_parsed"

###################################
# Interactive mode "on" or "off"? #
###################################
top_ports_tcp="$(grep -v ^"#" "${source_top_tcp}")"
top_ports_udp="$(grep -v ^"#" "${source_top_udp}")"

if [[ ${interactive} = "on" ]] && [[ ${all_ports} = "on" ]]; then
        echo -e "${red_color}Sorry, but you can't chose interactive mode (-i) with all ports scanning mode (-a).${end_color}"
	exit 1
elif [[ ${all_ports} = "on" ]]; then
        echo -e "${purple_color}[I] Okay, 65535 ports to be scan both on TCP and UDP.${end_color}"
	ports="-p1-65535,U:1-65535"
	rate="1000"
	script="vulners"
elif [[ ${interactive} = "on" ]]; then
        echo -e "${purple_color}[I] We will use the input file: ${hosts_file}${end_color}"
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
			echo -e "${purple_color}[I] Default parameter: --top-ports 1000 (TCP/UDP).${end_color}"
                        else
                                ports=${ports_list}
				echo -e "${purple_color}[I] Port(s) to scan: ${ports}${end_color}"
                fi
        # Which rate?
        echo -e "${blue_color}${bold_color}Which rate (pkts/sec)?${end_color}"
        echo -e "${blue_color}[default: --max-rate 1000, just typing \"Enter|Return\" key to continue]${end_color}"
        echo -e "${red_color}Be carreful, beyond \"10000\" it coud be dangerous for your network!!!${end_color}"
        read -p "Rate? >> " -r -t 60 max_rate
                if [[ -z ${max_rate} ]];then
                        rate="1000"
			echo -e "${purple_color}[I] Default parameter: --max-rate 1000.${end_color}"
                        else
                                rate=${max_rate}
				echo -e "${purple_color}[I] Rate chosen: ${rate}${end_color}"
                fi

		# Which script?
	
	if [[ ${no_nmap_scan} != "on" ]]; then
		locate_scripts="${nmap_scripts_folder}"
		scripts_list="$(ls "${locate_scripts}"*.nse 2>/dev/null)"

		# Verifying is Nmap folder scripts is present
		if [[ $? != "0" ]]; then
			echo -e "${red_color}[X] The Nmap folder does not exist or is empty (e.g. /usr/local/share/nmap/scripts/*.nse).${end_color}"
			echo -e "${purple_color}[I] This script can install the prerequisites for you: ${source_installation}${end_color}"
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
					echo -e "${purple_color}[I] Script name chosen: ${script}${end_color}"
					;;
				'' )
					script="vulners"
					echo -e "${purple_color}[I] No script chosen, we will use the default one (vulners.nse).${end_color}"
					;;
				* )
					script=${script_number}
					echo -e "${purple_color}[I] Script name and args chosen: ${script}${end_color}"
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
			rate="1000"
			script="vulners"
			echo -e "${purple_color}[I] Default parameters: --top-ports 1000 (TCP/UDP), --max-rate 1000 and Vulners script (NSE).${end_color}"
		else
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			rate="1000"
			echo -e "${purple_color}[I] Default parameters: --top-ports 1000 (TCP/UDP) and --max-rate 1000 (no Nmap Scan).${end_color}"
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
        		echo -e "${purple_color}[I] No interface chosen, we will use the one with the default route.${end_color}"
                        else
                                interface="${interfaces_tab[${interface_number}]}"
                fi
        echo -e "${purple_color}[I] Network interface chosen: ${interface}${end_color}"
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
	cut -d" " -f1 "${hosts_file}" > "${temp_dir}"/ips_list.txt
	echo -e "${blue_color}[-] Verifying how many hosts are online...please, be patient!${end_color}"	
	nmap -n -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${temp_dir}"/ips_list.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > "${temp_dir}"/live_hosts.txt
		if [[ $? != "0" ]]; then
			echo -e "${error_color}[X] ERROR! Maybe there is no host detected online. The script is ended.${end_color}"
			rm -rf "${temp_dir}"/live_hosts.txt "${temp_dir}"/"${hosts}"_parsed
			time_elapsed			
			exit 1
		fi

echo -e "${green_color}[V] Pre-scanning phase is ended.${end_color}"
rm -rf "${temp_dir}"/ips_list.txt 2>/dev/null
nb_hosts_to_scan="$(wc -l "${temp_dir}/live_hosts.txt")"
echo -e "${purple_color}[I] ${nb_hosts_to_scan} ip(s) to scan.${end_color}"

fi

########################################
# 2/4 Using Masscan to find open ports #
########################################

if [[ -s "${temp_dir}/live_hosts.txt" ]]; then
        hosts="${temp_dir}/live_hosts.txt"
        else
                cut -d" " -f1 "${hosts_file}" > "${temp_dir}"/ips_list.txt
                hosts="${temp_dir}/ips_list.txt"
fi

echo -e "${blue_color}[-] Verifying Masscan parameters and running the tool...please, be patient!${end_color}"

if [[ ${exclude_file} == "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open "${ports}" --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL "${temp_dir}"/masscan-output.txt
elif [[ ${exclude_file} == "" ]] && [[ $(id -u) != "0" ]]; then
	sudo masscan --open "${ports}" --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL "${temp_dir}"/masscan-output.txt
elif [[ ${exclude_file} != "" ]] && [[ $(id -u) = "0" ]]; then
	masscan --open "${ports}" --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${xhosts_file}" --max-rate "${rate}" -oL "${temp_dir}"/masscan-output.txt
else
	sudo masscan --open "${ports}" --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${xhosts_file}" --max-rate "${rate}" -oL "${temp_dir}"/masscan-output.txt
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}[X] ERROR! Thanks to verify your parameters or your input/exclude file format. The script is ended.${end_color}"
	rm -rf "${temp_dir}"/masscan-output.txt
	exit 1
fi

echo -e "${green_color}[V] Masscan phase is ended.${end_color}"

if [[ ! -s ${temp_dir}/masscan-output.txt ]]; then
        echo -e "${green_color}[!] No ip with open TCP/UDP ports found, so, exit! ->${end_color}"
	rm -rf "${temp_dir}"/masscan-output.txt "${temp_dir}"/hosts_converted.txt "${temp_dir}"/ips_list.txt
	time_elapsed
	exit 0
	else
		tcp_ports="$(grep -c "^open tcp" "${temp_dir}"/masscan-output.txt)"
		udp_ports="$(grep -c "^open udp" "${temp_dir}"/masscan-output.txt)"
		nb_ports="$(grep -c ^open "${temp_dir}"/masscan-output.txt)"
		nb_hosts_nmap="$(grep ^open "${temp_dir}"/masscan-output.txt | cut -d" " -f4 | sort | uniq -c | wc -l)"
		echo -e "${purple_color}[I] ${nb_hosts_nmap} host(s) concerning ${nb_ports} open ports.${end_color}"
fi

rm -rf "${temp_dir}"/ips_list.txt 2>/dev/null

###########################################################################################
# 3/4 Identifying open services with Nmap and if they are vulnerable with vulners script  #
###########################################################################################

# Output file with hostnames
merge_ip_hostname(){
cat "${temp_dir}"/nmap-input.txt | while IFS=, read -r line; do
	search_ip=$(echo "${line}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

	if [[ $(grep "${search_ip}" "${hosts_file}") ]] 2>/dev/null; then

		if [[ $(grep "${search_ip}" "${hosts_file}" | awk -F" " '{print $2}') ]]; then
			search_hostname=$(grep "${search_ip}" "${hosts_file}" | awk -F" " '{print $2}')
			echo "${line} ${search_hostname}" >> "${temp_dir}"/IPs_hostnames_merged.txt
		else
			echo "${line}" >> "${temp_dir}"/IPs_hostnames_merged.txt
		fi
	else
		echo "${line}" >> "${temp_dir}"/IPs_hostnames_merged.txt
	fi
done
}

# Hosts list scanned
hosts_scanned(){
	echo -e "${bold_color}Host(s) discovered with an open port(s):${end_color}"
	grep ^open "${temp_dir}"/masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
}

# Preparing the input file for Nmap
nmap_file(){
proto="$1"

grep "^open ${proto}" "${temp_dir}"/masscan-output.txt | awk '/.+/ { \
				if (!($4 in ips_list)) { \
				value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s:%s:%s\n%s", $2, value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' >> "${temp_dir}"/nmap-input.temp.txt
}

rm -rf "${temp_dir}"/nmap-input.temp.txt

if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 "${temp_dir}"/nmap-input.temp.txt > "${temp_dir}"/nmap-input.txt

if [[ ${no_nmap_scan} != "on" ]]; then
	# If we are using Vulners.nse script, check if vulners.com site is reachable
	if [[ ${script} == "vulners" ]]; then
		check_vulners_api_status="$(nc -z -v -w 1 vulners.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

		if [[ ${check_vulners_api_status} == "open" ]]; then
			echo -e "${purple_color}[I] Vulners.com site is reachable on port 443.${end_color}"
			else
				echo -e "${blue_color}${bold_color}Warning: Vulners.com site is NOT reachable on port 443. Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
				echo -e "${blue_color}${bold_color}So, vulnerability check will be not possible, only opened ports will be present in the report.${end_color}"
		fi
	fi

	nb_nmap_process="$(sort -n "${temp_dir}"/nmap-input.txt | wc -l)"
	date="$(date +%F_%H-%M-%S)"

	# Keep the nmap input file?
	if [[ ${report} == "on" ]]; then
		hosts_scanned
		merge_ip_hostname
		mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${hosts_file_no_path}"_open-ports_"${date}".txt
		echo -e "${purple_color}[I] IP(s) found with open ports:${end_color}"
		echo -e "${blue_color}-> ${report_folder}${hosts_file_no_path}_open-ports_${date}.txt${end_color}"
	fi

	# Function for parallel Nmap scans
	parallels_scans(){
	proto="$(echo "$1" | cut -d":" -f1)"
	ip="$(echo "$1" | cut -d":" -f2)"
	port="$(echo "$1" | cut -d":" -f3)"

	if [[ $proto == "tcp" ]]; then
		nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n --script ${script} -oA "${temp_nmap}/${ip}"_tcp_nmap-output "${ip}" > /dev/null 2>&1
		echo "${ip} (${proto}): Done" >> "${temp_dir}"/process_nmap_done.txt
		else
			nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n --script ${script} -oA "${temp_nmap}/${ip}"_udp_nmap-output "${ip}" > /dev/null 2>&1
			echo "${ip} (${proto}): Done" >> "${temp_dir}"/process_nmap_done.txt
	fi

	nmap_proc_ended="$(grep "$Done" -co "${temp_dir}"/process_nmap_done.txt)"
	pourcentage="$(awk "BEGIN {printf \"%.2f\n\", \"${nmap_proc_ended}\"/\"${nb_nmap_process}\"*100}")"
	echo -n -e "\r                                                                                                         "
	echo -n -e "${purple_color}${bold_color}\r[I] Scan is done for ${ip} (${proto}) -> ${nmap_proc_ended}/${nb_nmap_process} Nmap process launched...(${pourcentage}%)${end_color}"

	}

	# Controlling the number of Nmap scanner to launch
	if [[ ${nb_nmap_process} -ge "50" ]]; then
		max_job="50"
		echo -e "${blue_color}${bold_color}Warning: A lot of Nmap process to launch: ${nb_nmap_process}${end_color}"
		echo -e "${blue_color}[-] So, to no disturb your system, I will only launch ${max_job} Nmap process at time.${end_color}"
		else
			max_job="${nb_nmap_process}"
        		echo -n -e "\r                                                                                             "
			echo -e "${purple_color}${bold_color}\r[I] Launching ${nb_nmap_process} Nmap scanner(s).${end_color}"
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

	#rm -rf ${temp_dir}/process_nmap_done.txt

	while IFS=, read -r ip_to_scan; do
		new_job "$i"
		count="$(expr $count + 1)"
	done < "${temp_dir}"/nmap-input.txt

	wait

	sleep 2 && tset

	echo -e "${green_color}\r[V] Nmap phase is ended.${end_color}"
	
	# Verifying vulnerable hosts
	vuln_hosts_count="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
	vuln_ports_count="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"
	vuln_hosts="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done)"
	vuln_hosts_ip="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"
	date="$(date +%F_%H-%M-%S)"

	if [[ ${vuln_hosts_count} != "0" ]]; then
		echo -e "${red_color}[X] ${vuln_hosts_count} vulnerable (or potentially vulnerable) host(s) found.${end_color}"
		echo -e -n "${vuln_hosts_ip}\n" | while IFS=, read -r line; do
			host="$(dig -x "${line}" +short)"
			echo "${line}" "${host}" >> "${temp_dir}"/vulnerable_hosts.txt
		done
	
		vuln_hosts_format="$(awk '{print $1 "\t" $NF}' "${temp_dir}"/vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"
		echo -e -n "\t----------------------------\n" > "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Report date: $(date)\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "${vuln_hosts_format}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "All the details below." >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "\n\t----------------------------\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "${vuln_hosts}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
	else
		echo -e "${blue_color}No vulnerable host found... at first sight!.${end_color}"

	fi

elif [[ ${no_nmap_scan} == "on" ]] && [[ ${report} == "on" ]]; then
	date="$(date +%F_%H-%M-%S)"
	echo -e "${purple_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat "${temp_dir}"/IPs_hostnames_merged.txt)${end_color}"
	mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${hosts_file_no_path}"_open-ports_"${date}".txt
	echo -e "${purple_color}[I] IP(s) found with open ports:${end_color}"
	echo -e "${blue_color}-> ${report_folder}${hosts_file_no_path}_open-ports_${date}.txt${end_color}"

else
	echo -e "${purple_color}[I] No Nmap scan to perform.${end_color}"
	hosts_scanned
	merge_ip_hostname
	echo -e "${bold_color}$(cat "${temp_dir}"/IPs_hostnames_merged.txt)${end_color}"
fi

##########################
# 4/4 Generating reports #
##########################

if [[ ${no_nmap_scan} != "on" ]]; then
	nmap_bootstrap="${dir_name}/stylesheet/nmap-bootstrap.xsl"
	global_report="${hosts_file_no_path}_global-report_${date}.html"

	if [[ -s ${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt ]]; then
		echo -e "${purple_color}[I] All details on the vulnerabilities:"
		echo -e "${blue_color}-> ${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt${end_color}"
	fi

	# Merging all the Nmap XML files to one big XML file
	echo "<?xml version=\"1.0\"?>" > "${temp_dir}"/nmap-output.xml
	echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> "${temp_dir}"/nmap-output.xml
	echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> "${temp_dir}"/nmap-output.xml
	echo "<!-- nmap results file generated by MassVulScan.sh -->" >> "${temp_dir}"/nmap-output.xml
	echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n --script ${script} [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> "${temp_dir}"/nmap-output.xml
	echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> "${temp_dir}"/nmap-output.xml

	for i in "${temp_nmap}"/*.xml; do
		sed -n -e '/<host /,/<\/host>/p' "$i" >> "${temp_dir}"/nmap-output.xml
	done

	echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
	      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> "${temp_dir}"/nmap-output.xml

	# Using bootstrap to generate a beautiful HTML file (report)
	xsltproc -o "${report_folder}${global_report}" "${nmap_bootstrap}" "${temp_dir}"/nmap-output.xml 2>/dev/null

	# End of script
	echo -e "${purple_color}[I] HTML report generated:"
	echo -e "${blue_color}-> ${report_folder}${global_report}${end_color}"
	echo -e "${green_color}[V] Report phase is ended, bye!${end_color}"
else
	echo -e "${purple_color}[I] No HTML report generated.${end_color}"

fi

# Cleaning files
rm -rf "${temp_dir}" "${temp_nmap}" paused.conf 2>/dev/null

time_elapsed

exit 0
