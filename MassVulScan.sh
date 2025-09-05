#!/usr/bin/env bash

#    This file is part of MassVulScan.
#
#    Copyright (C) 2017 choupit0
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
#    MassVulScan - cross-distro version (Debian & RedHat based)
#
# Script Name    : MassVulScan.sh
# Slogan         : Identify open network ports and any associated vulnerabilities
# Description    : This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#                  A nice report (nmap-bootstrap.xsl) is generated containing all hosts found with open ports,
#                  and finally a text file including specifically the potential vulnerables hosts is created.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Updated        : 2025-09-05
# License        : GPLv3
# Version        : 3.0.0
# Usage          : ./MassVulScan.sh COMMAND [ARGS] OPTION
#

version="3.0.0"
dir_name="$(dirname -- "$( readlink -f -- "$0"; )")"
source_installation="${dir_name}/sources/installation.sh"
source_top_tcp="${dir_name}/sources/top-ports-tcp-1000.txt"
source_top_udp="${dir_name}/sources/top-ports-udp-1000.txt"
report_folder="${dir_name}/reports/"
blue_color="\033[0;36m"
red_color="\033[1;31m"
green_color="\033[0;32m"
purple_color="\033[1;35m"
bold_color="\033[1m"
end_color="\033[0m"
script_start="$SECONDS"
dns="1.1.1.1"
network_interface=""

##########################
# OS Detection Function  #
##########################
detect_os(){
    if [ -f /etc/debian_version ]; then
        os_family="debian"
    elif [ -f /etc/redhat-release ]; then
        os_family="redhat"
    else
        os_family="unknown"
    fi
    echo "$os_family"
}

##########################
# Checking prerequisites #
##########################
checking_prerequisites(){
os_family=$(detect_os)
missing_or_outdated_packages=()

if [[ "${os_family}" == "debian" ]]; then
    # Debian/Ubuntu packages
    for package in iproute2 build-essential git curl wget gpg tar libpcre3-dev libssl-dev libpcap-dev net-tools xsltproc bind9-dnsutils netcat-traditional toilet boxes lolcat gum automake; do
        package_status=$(dpkg-query -W -f='${Status}' "${package}" 2>/dev/null | grep "install ok installed")
        if [[ ! ${package_status} ]]; then
            missing_or_outdated_packages+=("${package}")
        fi
    done
elif [[ "${os_family}" == "redhat" ]]; then
    # RedHat/Rocky packages (equivalents adapted)
    for package in iproute gcc gcc-c++ make git curl wget tar pcre-devel openssl-devel libpcap-devel net-tools bind-utils nmap-ncat toilet boxes gum automake bzip2; do
        if ! rpm -q "${package}" &>/dev/null; then
            missing_or_outdated_packages+=("${package}")
        fi
    done
    for package in gpg xsltproc lolcat; do
	if ! command -v "${package}" >/dev/null 2>&1; then
            missing_or_outdated_packages+=("${package}")
        fi
    done
else
    echo -e "${red_color}Unsupported OS. Only Debian or RedHat families are supported.${end_color}"
    exit 1
fi

# Masscan & Nmap check
for package in masscan nmap; do
    if [[ ${package} == "masscan" ]] && [[ ! $(which masscan 2>/dev/null) ]]; then
        missing_or_outdated_packages+=("${package}")
    elif [[ ${package} == "nmap" ]] && [[ ! $(which nmap 2>/dev/null) ]]; then
        missing_or_outdated_packages+=("${package}")
    fi
done

# Version checks (same as original)
installed_masscan_version="$(masscan -V 2>/dev/null | grep "Masscan version" | grep -Eo '([0-9]+\.[0-9]+(\.[0-9]+)?)')"
installed_nmap_version="$(nmap -V 2>/dev/null | grep "Nmap version" | grep -Eo '([0-9]+\.[0-9]+(\.[0-9]+)?)')"
min_masscan_version_required="1.3.2"
min_nmap_version_required="7.92"

version_comparison(){
    local v1=$1 v2=$2
    IFS=. read -r a1 b1 c1 <<< "$v1"
    IFS=. read -r a2 b2 c2 <<< "$v2"
    [[ -z $c1 ]] && c1=0
    [[ -z $c2 ]] && c2=0
    if (( a1 < a2 || (a1 == a2 && b1 < b2) || (a1 == a2 && b1 == b2 && c1 < c2) )); then
        echo -1
    elif (( a1 == a2 && b1 == b2 && c1 == c2 )); then
        echo 0
    else
        echo 1
    fi
}

if [[ ${installed_masscan_version} ]]; then
    check_version=$(version_comparison ${installed_masscan_version} ${min_masscan_version_required})
    if [[ $check_version -lt 0 ]]; then
        missing_or_outdated_packages+=("masscan")
    fi
fi

if [[ ${installed_nmap_version} ]]; then
    check_version=$(version_comparison ${installed_nmap_version} ${min_nmap_version_required})
    if [[ $check_version -lt 0 ]]; then
        missing_or_outdated_packages+=("nmap")
    else
        if [[ $(which nmap) == */local/* ]];then
            nmap_scripts_folder="/usr/local/share/nmap/scripts/"
        else
            nmap_scripts_folder="/usr/share/nmap/scripts/"
        fi
    fi
fi

# Vulners
if [[ ! $(ls ${nmap_scripts_folder}vulners.nse 2>/dev/null) ]]; then
    missing_or_outdated_packages+=("vulners")
fi

# Installation if missing
if [[ ${#missing_or_outdated_packages[@]} -gt 0 ]]; then
    echo -e "${bold_color}${red_color}Some prerequisites are missing or outdated (${#missing_or_outdated_packages[@]}):${end_color}"
    echo -e "${blue_color}${missing_or_outdated_packages[*]}${end_color}"
    export packages_to_install="${missing_or_outdated_packages[*]}"
	export nmap_scripts_folder
	export os_family
	if [[ ! -s ${source_installation} ]]; then
		echo -e "${red_color}Missing installation source file: ${source_installation}. Please re-clone repository.${end_color}"
		exit 1
	fi
	source ${source_installation}
else
    touch "${dir_name}/.prerequisites_already_installed" 2>/dev/null
fi
}

if [[ ! -f "${dir_name}/.prerequisites_already_installed" ]];then
    checking_prerequisites
fi

# NSE folder
if [[ $(which nmap) == */local/* ]];then
    nmap_scripts_folder="/usr/local/share/nmap/scripts/"
else
    nmap_scripts_folder="/usr/share/nmap/scripts/"
fi

######################################
# The script is now fully functional #
######################################

# Time elapsed 
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Let's make our script more glamorous
warning_message_with_border(){
if [[ ! -z $2 ]]; then
	gum style --background 1 --padding "1 1" --bold "$1" "$2"
else
	gum style --background 1 --padding "1 1" --bold "$1"
fi
}

tip_message_with_border(){
if [[ ! -z $2 ]]; then
	gum style --background 4 --padding "1 1" --bold "$1" "$2"
else
	gum style --background 4 --padding "1 1" --bold "$1"
fi
}

task_completion_message(){
        gum style --foreground 10 --bold "$1"
}

blue_info_message(){
if [[ ! -z $2 ]]; then
	gum style --foreground 69 --bold "$1" "$2"
else
	gum style --foreground 69 --bold "$1"
fi
}

yellow_info_message(){
if [[ ! -z $2 ]]; then
	gum style --foreground 11 --bold "$1" "$2"
else
	gum style --foreground 11 --bold "$1"
fi
}

logo(){
# Fonts to use
fonts=("smbraille" "smblock" "pagga" "future" "emboss" "emboss2")
random_font=${fonts[$RANDOM % ${#fonts[@]}]}
current_lang=${LANG}
current_lc_all=${LC_ALL}

# Find the first available locale containing "utf8"
utf8_locale=$(locale -a | grep 'utf8' | head -n 1)
if [ -n "$utf8_locale" ]; then
        export PATH=$PATH:/usr/games
        export LANG=$utf8_locale
        export LC_ALL=$utf8_locale
        echo
        toilet -f ${random_font} "MassVulScan" | boxes -d peek -a hc -p h1 | lolcat
        gum style --foreground 5 --bold --align right --width 40 "v${version}"
        export LANG=${current_lang}
        export LC_ALL=${current_lc_all}
        echo
else
        gum style --foreground 42 --bold --border thick "M a s s V u l S c a n"
        gum style --foreground 5 --bold --align right --width 25 "v${version}"
fi
}

# Root user?
root_user(){
if [[ $(id -u) != "0" ]]; then
	warning_message_with_border "You are not the root user." "If you have the appropriate permissions (sudoers), rerun the script with 'sudo'."
	exit 1
fi
}

# Verifying if top-ports source files exist
source_file_top(){
if [[ -z ${source_top_tcp} || ! -s ${source_top_tcp} ]]; then
	warning_message_with_border "The file \"${source_top_tcp}\" is missing or is empty."
	tip_message_with_border "Redownload the source from Github: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
elif [[ -z ${source_top_udp} || ! -s ${source_top_udp} ]]; then
	warning_message_with_border "The file \"${source_top_udp}\" is missing or is empty."
	tip_message_with_border "Redownload the source from Github: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

hosts="$1"
exclude_file=""
interactive="off"
check="off"

# Usage of script
usage(){
	echo -e "${bold_color}${red_color}Usage: ./$(basename "$0") COMMAND [ARGS]${end_color} OPTIONS"
	echo -e "      ${red_color}Commands (required):${end_color}"
	echo -e "        -h | --hosts ${red_color}[ARGS]${end_color}  \t\tTarget host(s): IP address (CIDR format compatible)"
	echo -e "        -f | --include-file ${red_color}[ARGS]${end_color} \tFile including IPv4 addresses (CIDR format) or hostnames to scan (one by line)"
	echo -e "      Options:"
	echo -e "        -x | --exclude-file ${red_color}[ARGS]${end_color} \tFile including IPv4 addresses ONLY (CIDR format) to NOT scan (one by line)"
	echo -e "        -i | --interactive-mode \tExtra parameters: ports to scan, rate level and NSE script"
	echo -e "        -a | --all-ports \t\tScan all 65535 ports (TCP + UDP) at 1.5K pkts/sec with NSE vulners script"
	echo -e "        -c | --check-live-hosts \tPerform a pre-scanning to identify online hosts and scan only them"
	echo -e "        -r | --report \t\t\tFile including IPs scanned with open ports and protocols"
	echo -e "        -n | --no-nmap-scan \t\tThe script detect only the hosts with open ports (no nmap scan & HTML report)"
	echo -e "        -d | --dns ${red_color}[ARGS]${end_color} \t\tDNS server to use (useful with the "-f" command and hostnames, current: ${dns})"
	echo -e "        -I | --interface ${red_color}[ARGS]${end_color} \tNetwork interface to use for scanning (e.g. eth0, wlan0), or the one with the default route is used"
	echo -e "      Information:"
	echo -e "        -H | --help \t\t\tShow this help menu"
	echo -e "        -V | --version \t\t\tScript version"
	echo ""
}

# No paramaters
if [[ "$#" -eq 0 ]]; then
	logo
	usage
	exit 1
fi

# Available parameters
while [[ "$1" != "" ]]; do
        case "$1" in
                -h | --hosts )
			            host_parameter="yes"
			            shift
                        initial_hosts="$1"
                        hosts="$1"
                        ;;
                -f | --include-file )
			            file_of_hosts_to_include="yes"
                        shift
                        hosts="$1"
                        ;;
                -x | --exclude-file )
                        file_of_hosts_to_exclude="yes"
                        shift
                        exclude_file="$1"
                        ;;
                -i | --interactive-mode )
                        interactive="on"
                       ;;
                -a | --all-ports )
                        all_ports="on"
                       ;;
                -c | --check-live-hosts )
                        check="on"
                        ;;
                -r | --report )
                        report="on"
                        ;;
                -n | --no-nmap-scan )
                        no_nmap_scan="on"
                        ;;
                -d | --dns )
			            shift
                        dns="$1"
                        ;;
                -I | --interface )
			            shift
                        network_interface="$1"
                        ;;
		        -H | --help )
			            echo ""
                        usage
                        exit 0
                        ;;
                -V | --version )
			            blue_info_message "MassVulScan version ${version} (https://github.com/choupit0/MassVulScan)"
						blue_info_message "Now compatible with RedHat and Debian OS since version 3.0.0."
                        exit 0
                        ;;
                * )
			            warning_message_with_border "One parameter is missing or does not exist."
                        exit 1
        esac
        shift
done

root_user

# Checking if process already running
check_proc="$(pgrep -i massvulscan)"
check_proc_nb="$(pgrep -i massvulscan | wc -l)"

if [[ ${check_proc_nb} -gt "2" ]]; then
	warning_message_with_border "A process is already running: ${check_proc}"
	exit 1
fi

# Only one required parameter at a time
if [[ ${host_parameter} = "yes" ]] && [[ ${file_of_hosts_to_include} = "yes" || ${file_of_hosts_to_exclude} = "yes" ]]; then
	warning_message_with_border "You can only use one command at a time.: -h | --hosts [ARGS] OR -f | --include-file [ARGS]" "Additionally: -x | --exclude-file [ARGS] is incompatible with -h | --hosts"
        exit 1
# Valid input file or host?
elif [[ ${file_of_hosts_to_include} = "yes" ]] && [[ -z ${hosts} ]]; then
	warning_message_with_border "You must specify an argument: -f | --include-file [ARGS]"
	exit 1
elif [[ ${file_of_hosts_to_include} = "yes" ]] && [[ ! -s ${hosts} ]]; then
	warning_message_with_border "The input file \"${hosts}\" does not exist or is empty."
	exit 1
elif [[ ${host_parameter} = "yes" ]] && [[ -z ${hosts} ]]; then
	warning_message_with_border "You must specify an argument: -h | --hosts [ARGS]"
	exit 1
fi

# Valid exclude file?
if [[ ${file_of_hosts_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]]; then
		warning_message_with_border "You must specify an argument: -x | --exclude-file [ARGS]"
                exit 1
        elif [[ ! -s ${exclude_file} ]]; then
		warning_message_with_border "The exclude file \"${hosts}\" does not exist or is empty."
                exit 1
        fi
fi

# Formatting of the "hosts" variable
if [[ ${file_of_hosts_to_include} = "yes" ]]; then
	# Complete path to the "hosts" file
	hosts="$(readlink -f "$hosts")"
fi

# Cleaning old files - if the script is ended before the end (CTRL + C)
rm -rf /tmp/temp_dir-* /tmp/temp_nmap-* paused.conf 2>/dev/null

# Folder for temporary file(s)
temp_dir="$(mktemp -d /tmp/temp_dir-XXXXXXXX)"
temp_nmap="$(mktemp -d /tmp/temp_nmap-XXXXXXXX)"

clear

# Function to validate the format of an IP address
valid_ip(){
ip_to_check="$1"
stat=1
regexv6='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
if [[ ${ip_to_check} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ ${ip_to_check} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=(${ip_to_check})
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
elif [[ $ip =~ $regexv6 ]]; then
        stat=0
fi
return $stat
}

# DNS Server selection
if [[ ${dns} == "1.1.1.1" ]]; then
	yellow_info_message "Default Public DNS Server Configured: ${dns}"
elif valid_ip "${dns}"; then
	yellow_info_message "Your own DNS Server configuration: ${dns}"
else
	warning_message_with_border "\"${dns}\" is not a valid IPv4 address for a DNS server."
	exit 1
fi

#######################################
# Parsing the input and exclude files #
#######################################
if [[ ${file_of_hosts_to_include} = "yes" || ${file_of_hosts_to_exclude} = "yes" ]]; then
	num_hostnames_init=$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -vEc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
	num_ips_init=$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')

	echo -n -e "\r                                                                                                                 "
	echo -n -e "\rParsing the input file (DNS lookups, duplicate IPs, multiple hostnames and valid IPs)..."

	# Saving IPs first
	if [[ ${num_ips_init} -gt "0" ]]; then
		ips_tab_init=("$(grep '[[:alnum:].-]' "${hosts}" | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')")
		printf '%s\n' "${ips_tab_init[@]}" | while IFS=, read -r check_ip; do
			if valid_ip "${check_ip}"; then
				echo "${check_ip}" >> "${temp_dir}"/IPs.txt
			else
				echo -n -e "\r\"${check_ip}\" is not a valid IPv4 address and/or subnet mask                           \n"
			fi
		done
	fi

	# Detect and deduplicate CIDR subnets with the help of Claude 3.5 Sonnet from https://claude.ai/
	if [[ -s ${temp_dir}/IPs.txt ]] && grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "${temp_dir}"/IPs.txt; then
		# Extract CIDR only
		sed -n '/\//p' "${temp_dir}"/IPs.txt > "${temp_dir}"/IPs_CIDR.txt

		# Convert the other lines to CIDR format
		sed -E 's|^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$|\1/32|' "${temp_dir}"/IPs.txt > "${temp_dir}"/IPs_CIDR.txt

		# Remove the original file
		rm -rf "${temp_dir}"/IPs.txt

		# Function to convert an IP address to a number
		ip_to_int() {
		    local ip=$1
		    local IFS='.'
		    read -r i1 i2 i3 i4 <<< "$ip"
		    echo $(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
		}

		# Function to calculate the network mask
		get_mask() {
		    local bits=$1
		    if [ "$bits" -eq 32 ]; then
			echo 4294967295  # 2^32 - 1
		    else
			echo $(( ((1 << bits) - 1) << (32 - bits) ))
		    fi
		}

		# Function to get the network address
		get_network_addr() {
		    local ip=$1
		    local mask=$2
		    echo $(( ip & mask ))
		}

		# Function to check if one network is contained within another
		is_subnet_contained() {
		    local net1=$1
		    local cidr1=$2
		    local net2=$3
		    local cidr2=$4

		    # If the first network has a larger mask (more specific),
		    # it could be contained in the second one
		    if [ "$cidr1" -ge "$cidr2" ]; then
			local mask2=$(get_mask "$cidr2")
			# If both networks have the same network address with the largest mask,
			# then the first one is contained in the second
			[ $(( net1 & mask2 )) -eq $(( net2 & mask2 )) ]
			return $?
		    fi
		    return 1
		}

		# Associative array to cache IP -> int conversions
		declare -A ip_cache

		# Preprocessing: convert all IP addresses to numbers and sort by CIDR
		while IFS=/ read -r ip cidr; do
		    if [ -z "${ip_cache[$ip]}" ]; then
			ip_cache[$ip]=$(ip_to_int "$ip")
		    fi
		    echo "${ip_cache[$ip]} $cidr $ip/$cidr"
		done < "${temp_dir}"/IPs_CIDR.txt | sort -k2 -n > "${temp_dir}"/IPs_CIDR_temp.txt

		# Array to store unique networks
		declare -a unique_networks

		# Read each line from the preprocessed file
		while IFS=' ' read -r ip_num cidr original_cidr; do
		    is_contained=false

		    # Check if this network is contained in any of the already found networks
		    for existing in "${unique_networks[@]}"; do
			IFS=/ read -r existing_ip existing_cidr <<< "$existing"
			if [ -z "${ip_cache[$existing_ip]}" ]; then
			    ip_cache[$existing_ip]=$(ip_to_int "$existing_ip")
			fi

			if is_subnet_contained "$ip_num" "$cidr" "${ip_cache[$existing_ip]}" "$existing_cidr"; then
			    is_contained=true
			    break
			fi
		    done

		    # If the network is not contained in another, add it to the list
		    if [ "$is_contained" = false ]; then
			unique_networks+=("$original_cidr")
		    fi
		done < "${temp_dir}"/IPs_CIDR_temp.txt

		printf '%s\n' "${unique_networks[@]}" >> "${temp_dir}"/IPs.txt

		rm -rf "${temp_dir}"/IPs_CIDR_temp.txt 2>/dev/null
	fi
	# End of detect and deduplicate CIDR subnets with the help of Claude 3.5 Sonnet from https://claude.ai/

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
				echo -n -e "\rNo IP found for hostname \"${host_to_convert}\".\n"
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
		warning_message_with_border "No valid host found."
		exit 1
	fi

	if [[ ${host_parameter} = "yes" ]]; then
		hosts_file_no_path="${initial_hosts}"
	else
		hosts_file_no_path="$(basename "$hosts")"
	fi

	if [[ -s ${temp_dir}/IPs_unsorted.txt ]] && [[ -s ${temp_dir}/IPs.txt ]]; then
		echo -n -e "\r                                                                                             "
		echo -n -e "\rValid host(s) to scan:\n"
		cat "${temp_dir}"/IPs.txt >> "${temp_dir}"/IPs_unsorted.txt
		rm -rf "${temp_dir}"/IPs.txt
		sort -u "${temp_dir}"/IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${hosts_file_no_path}"_parsed
		rm -rf "${temp_dir}"/IPs_unsorted.txt
		cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
	elif [[ -s ${temp_dir}/IPs_unsorted.txt ]]; then
		echo -n -e "\r                                                                                             "
		echo -n -e "\rValid host(s) to scan:\n"
		sort -u "${temp_dir}"/IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${hosts_file_no_path}"_parsed
		rm -rf "${temp_dir}"/IPs_unsorted.txt
		cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
	else
		echo -n -e "\r                                                                                             "
		echo -n -e "\rValid host(s) to scan:\n"
		mv "${temp_dir}"/IPs.txt "${temp_dir}"/"${hosts_file_no_path}"_parsed
		cat "${temp_dir}"/"${hosts_file_no_path}"_parsed
	fi

	hosts_file="${temp_dir}/${hosts_file_no_path}_parsed"

	if [[ ${exclude_file} != "" ]]; then
		# Complete path to the "hosts" file
		exclude_file="$(readlink -f "$exclude_file")"
		echo -n -e "\r                                                                                                                 "
		echo -n -e "\rParsing the exclude file (valid IPv4 addresses ONLY)..."
		num_xips_init=$(grep -Ev '^[[:punct:]]|[[:punct:]]$' "${exclude_file}" | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
		if [[ ${num_xips_init} -gt "0" ]]; then
			xips_tab_init=("$(grep -Ev '^[[:punct:]]|[[:punct:]]$' "${exclude_file}" | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')")
			printf '%s\n' "${xips_tab_init[@]}" | while IFS=, read -r check_ip; do
				if valid_ip "${check_ip}"; then
					echo "${check_ip}" >> "${temp_dir}"/xIPs.txt
				else
					echo -n -e "\r\"${check_ip}\" is not a valid IPv4 address and/or subnet mask to exclude                    \n"
				fi
			done
		fi
	fi

	xhosts_file_no_path="$(basename "$exclude_file")"

	if [[ -s ${temp_dir}/xIPs.txt ]]; then
		echo -n -e "\r                                                                                            "
		echo -n -e "\rValid host(s) to exclude:\n"
		sort -u "${temp_dir}"/xIPs.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > "${temp_dir}"/"${xhosts_file_no_path}"_parsed
		rm -rf "${temp_dir}"/xIPs.txt
		cat "${temp_dir}"/"${xhosts_file_no_path}"_parsed
	fi

	xhosts_file="${temp_dir}/${xhosts_file_no_path}_parsed"
fi

####################
# Interactive mode #
####################
top_ports_tcp="$(grep -v ^"#" "${source_top_tcp}")"
top_ports_udp="$(grep -v ^"#" "${source_top_udp}")"

if [[ ${interactive} = "on" ]] && [[ ${all_ports} = "on" ]]; then
        warning_message_with_border "You can't chose interactive mode (-i) with all ports scanning mode (-a)."
	exit 1
elif [[ ${all_ports} = "on" ]]; then
	gum style --foreground 1 --bold --border thick "All-ports scan mode"
        blue_info_message "We will scan ALL the ports 1-65535 on TCP AND UDP protocols and use the NSE Vulners script."
	ports="-p1-65535,U:1-65535"
	rate="1500"
	script="vulners"
elif [[ ${interactive} = "on" ]]; then
	gum style --foreground 42 --bold --border thick "Interactive Mode"
	
	# Default port list
	default_ports=(
		"Top 1000 ports (TCP/UDP)"
		"Common ports (20-25,53,80,110,143,161,443,445,993,995,3306,8080)"
		"All TCP and UDP ports (1-65535)"
		"Custom ports (enter manually)")
      
	# Use gum choose to select ports
	selected_option=$(printf "%s\n" "${default_ports[@]}" | gum choose --selected "All TCP and UDP ports (1-65535)" --header "Select the ports:")

	case "$selected_option" in
		"Top 1000 ports (TCP/UDP)")
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			blue_info_message "Selected ports: --top-ports 1000 (TCP/UDP)."
			;;
		"Common ports (20-25,53,80,110,143,161,443,445,993,995,3306,8080)")
			ports="-p20-25,53,80,110,143,443,445,993,995,3306,8080,U:53,161"
			blue_info_message "Selected ports: ${ports}"
			;;
		"All TCP and UDP ports (1-65535)")
			ports="-p1-65535,U:1-65535"
			blue_info_message "Selected ports: ${ports}"
			;;
		"Custom ports (enter manually)")
			# Use gum input to enter custom ports
			custom_ports=$(gum input --placeholder "Enter custom ports (e.g., -p20-25,80 --exclude-ports 26 or -pU:53,161 for UDP)" --timeout 120s)
			if [[ -z ${custom_ports} ]]; then
				echo "Error: No custom ports provided."
				exit 1
			else
				ports=${custom_ports}
				blue_info_message "Custom ports to scan: ${ports}"
			fi
			;;
		*)
			echo "Error: Invalid option selected."
			;;
	esac
	
	# Default rate options for masscan
	default_rates=(
		"100 packets/sec (Slow and stealthy)"
		"1000 packets/sec (Moderate speed)"
		"10000 packets/sec (Fast)"
		"Custom rate (enter manually)")
      
	# Use gum choose to select the rate
	selected_rate_option=$(printf "%s\n" "${default_rates[@]}" | gum choose --selected "1000 packets/sec (Moderate speed)" --header "Select the rate:")

	case "$selected_rate_option" in
		"100 packets/sec (Slow and stealthy)")
			rate="100"
			blue_info_message "Selected rate: ${rate}"
			;;
		"1000 packets/sec (Moderate speed)")
			rate="1000"
			blue_info_message "Selected rate: ${rate}"
			;;
		"10000 packets/sec (Fast)")
			rate="10000"
			blue_info_message "Selected rate: ${rate}"
			;;
		"Custom rate (enter manually)")
			# Use gum input to enter custom rate
			custom_rate=$(gum input --placeholder "Enter custom rate (packets/sec)" --timeout 120s)
			if [[ -z ${custom_rate} ]]; then
				echo "Error: No custom rate provided."
				exit 1
			else
				rate=${custom_rate}
				blue_info_message "Custom rate: ${rate}"
			fi
			;;
		*)
			echo "Error: Invalid option selected."
			;;
	esac

	# Use gum to select the NSE script for nmap
	
	if [[ ${no_nmap_scan} != "on" ]]; then
		locate_scripts="${nmap_scripts_folder}"
		scripts_list="$(ls "${locate_scripts}"*.nse | awk -F'/' '{print $NF}' 2>/dev/null)"

		# Verifying is Nmap folder scripts is present
		if [[ $? != "0" ]]; then
			echo -e "The Nmap folder does not exist or is empty (e.g. /usr/local/share/nmap/scripts/*.nse)."
			echo -e "This script can install the prerequisites for you: ${source_installation}"
			echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
		exit 1
		fi
	
		scripts_tab=(${scripts_list})
		selected_script=$(printf "%s\n" "${scripts_tab[@]}" | gum filter --indicator "◉" --limit 1 --header "Select a script:" --placeholder "Search for and select the Nmap NSE script" --timeout 120s)

		if [[ -n ${selected_script} ]]; then
			script="${selected_script}"
			blue_info_message "Selected script: ${selected_script}"
			
			# suggestions for --script-args
			default_script_args=(
			"Set a minimum CVSS score of 5 (vulners)"
			"Set a minimum CVSS score of 7 (vulners)"
			"Set a minimum CVSS score of 10 (vulners)"
			"No script argument"
			"Custom script arguments (enter manually)")
	      
			# Use gum choose to select the --script-args
			selected_script_args=$(printf "%s\n" "${default_script_args[@]}" | gum choose --selected "No script argument" --header "Select the script argument:")

			case "$selected_script_args" in
				"Set a minimum CVSS score of 5 (vulners)")
					script_args="mincvss=5"
					blue_info_message "Selected script argument: ${script_args}"
					script="${script} --script-args ${script_args}"
					;;
				"Set a minimum CVSS score of 7 (vulners)")
					script_args="mincvss=7"
					blue_info_message "Selected script argument: ${script_args}"
					script="${script} --script-args ${script_args}"
					;;
				"Set a minimum CVSS score of 10 (vulners)")
					script_args="mincvss=10"
					blue_info_message "Selected script argument: ${script_args}"
					script="${script} --script-args ${script_args}"
					;;
				"No script argument")
					script_args=""
					blue_info_message "No script argument."
					;;
				"Custom script arguments (enter manually)")
					# Use gum input to enter custom script argument
					custom_script_args=$(gum input --placeholder "Enter custom script argument (e.g., smbusername=<username>,smbpass=<password> for the NSE 'script smb-enum-services')" --timeout 120s)
					if [[ -z ${custom_script_args} ]]; then
						echo "Error: No custom script argument provided."
						exit 1
					else
						script_args=${custom_script_args}
						blue_info_message "Custom script argument: ${script_args}"
						script="${script} --script-args ${script_args}"
					fi
					;;
				*)
					echo "Error: Invalid option selected."
					;;
			esac
		else
			echo "Error: No script selected."
			exit 1
		fi
	fi

        else
		if [[ ${no_nmap_scan} != "on" ]]; then	
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			rate="1500"
			script="vulners"
			blue_info_message "Default parameters: --top-ports 1000 (TCP/UDP), --max-rate 1500 and Vulners script (NSE)"
		else
			source_file_top
			ports="-p${top_ports_tcp},U:${top_ports_udp}"
			rate="1500"
			blue_info_message "Default parameters: --top-ports 1000 (TCP/UDP) and --max-rate 1500 (no Nmap Scan)"
		fi
fi

# Network interface selection
if [[ ${network_interface} == "" ]]; then

	# Get the default interface
	default_interface="$(ip route show default | awk '/default/ {print $5; exit}')"

	# Get the number of network interfaces
	nb_interfaces="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -co "^[[:alnum:]]*")"

	################################################
	# Checking if there are more than 2 interfaces #
	################################################

	if [[ "${nb_interfaces}" -gt "2" ]]; then
		# List of network interfaces
		interfaces_list="$(ifconfig | grep -E "[[:space:]](Link|flags)" | grep -o "^[[:alnum:]]*")"
		interfaces_tab=(${interfaces_list})

		# Display a warning message with gum
		echo "Warning: multiple network interfaces have been detected:" | gum style --foreground 212

		# Display the list of interfaces using gum for selection
		selected_interface=$(printf "%s\n" "${interfaces_tab[@]}" | gum choose --limit 1 --selected ${default_interface} --header "Which one do you want to use (the default one is selected)?" --timeout 90s)

		# Check if an interface was selected
		if [[ -z "${selected_interface}" ]]; then
			echo "No interface chosen, we will use the one with the default route." | gum style --foreground 212
			interface="${default_interface}"
		else
			interface="${selected_interface}"
		fi

			echo "Network interface chosen: "${interface}"" | gum style --foreground 212
	else
		interface="${default_interface}"
		echo "Default network interface chosen: "${interface}"" | gum style --foreground 212
	fi
else
	# Check if the provided interface exists on the system
	
	# Get the list of network interfaces available on the system and only UP
	available_interfaces=$(ip -o link show up | awk -F': ' '{print $2}')

	if ! echo "$available_interfaces" | grep -qw "$network_interface"; then
		warning_message_with_border "\"${network_interface}\" does not exist on this system or the network interface is down."
		yellow_info_message "Available and UP interfaces are:"
		echo "$available_interfaces" | tr ' ' '\n'
	exit 1

	fi

	interface="${network_interface}"
	echo "Network interface chosen: "${interface}"" | gum style --foreground 212
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
	if [[ ${file_of_hosts_to_include} = "yes" ]]; then
		cut -d" " -f1 "${hosts_file}" > "${temp_dir}"/ips_list.txt
		gum spin --spinner dot --title.foreground 6 --title "Let's check how many hosts are online; please be patient." -- \
			nmap -n -sP -T5 --min-parallelism 100 --max-parallelism 256 -iL "${temp_dir}"/ips_list.txt | grep -B1 "Host is up" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > "${temp_dir}"/live_hosts.txt
			if [[ $? != "0" ]]; then
				warning_message_with_border "No host detected online. The script is ended."
				rm -rf "${temp_dir}"/live_hosts.txt "${temp_dir}"/"${hosts}"_parsed
				time_elapsed			
				exit 1
			fi
		task_completion_message "Pre-scanning phase is ended."
		rm -rf "${temp_dir}"/ips_list.txt 2>/dev/null
		nb_hosts_to_scan="$(grep -c . "${temp_dir}/live_hosts.txt")"
		blue_info_message "${nb_hosts_to_scan} ip(s) to scan."
	elif [[ ${host_parameter} = "yes" ]]; then
		gum spin --spinner dot --title.foreground 6 --title "Let's check how many hosts are online; please be patient." -- \
			nmap -n -sP -T5 --min-parallelism 100 --max-parallelism 256 ${hosts} | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > "${temp_dir}"/live_hosts.txt
		if [[ $? != "0" ]]; then
			warning_message_with_border "No host detected online. The script is ended."
			time_elapsed			
			exit 1
		fi

		task_completion_message "Pre-scanning phase is ended."
		nb_hosts_to_scan="$(grep -c . "${temp_dir}/live_hosts.txt")"
		blue_info_message "${nb_hosts_to_scan} ip(s) to scan."
	fi		
fi

########################################
# 2/4 Using Masscan to find open ports #
########################################

if [[ -s "${temp_dir}/live_hosts.txt" ]]; then
	hosts="${temp_dir}/live_hosts.txt"
elif [[ ${host_parameter} = "yes" ]]; then
	echo ${hosts} > ${temp_dir}/ips_list.txt
	hosts="${temp_dir}/ips_list.txt"
else
	cut -d" " -f1 "${hosts_file}" > "${temp_dir}"/ips_list.txt 2>/dev/null
	hosts="${temp_dir}/ips_list.txt"
fi

if [[ ${exclude_file} == "" ]] && [[ $(id -u) = "0" ]]; then
#	gum spin --spinner dot --title.foreground 6 --title "Let's check the number of hosts with open ports; please be patient." -- \
		masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" --wait 5 | tee "${temp_dir}"/masscan-output.txt
elif [[ ${exclude_file} != "" ]] && [[ $(id -u) = "0" ]]; then
#	gum spin --spinner dot --title.foreground 6 --title "Let's check the number of hosts with open ports; please be patient." -- \
		masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --excludefile "${xhosts_file}" --max-rate "${rate}" --wait 5 | tee "${temp_dir}"/masscan-output.txt
fi

if [[ $? != "0" ]]; then
	clear
	warning_message_with_border "One or more parameters/arguments are incorrect."
	rm -rf "${temp_dir}"/masscan-output.txt
	exit 1
fi

task_completion_message "Masscan phase is ended."

if [[ ! -s ${temp_dir}/masscan-output.txt ]]; then
        warning_message_with_border "No ip with open TCP/UDP ports found, so, exit! ->"
	rm -rf "${temp_dir}"/masscan-output.txt "${temp_dir}"/hosts_converted.txt "${temp_dir}"/ips_list.txt
	time_elapsed
	exit 0
	else
		tcp_ports="$(grep -c "^Discovered open port.*tcp" "${temp_dir}"/masscan-output.txt)"
		udp_ports="$(grep -c "^Discovered open port.*udp" "${temp_dir}"/masscan-output.txt)"
		nb_ports="$(grep -c "^Discovered open port" "${temp_dir}"/masscan-output.txt)"
		nb_hosts_nmap="$(grep "^Discovered open port" "${temp_dir}"/masscan-output.txt | cut -d" " -f6 | sort | uniq -c | wc -l)"
		blue_info_message "${nb_hosts_nmap} host(s) concerning ${nb_ports} open ports."
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

# Preparing the input file for Nmap
nmap_file(){
proto="$1"

grep "Discovered open port .*\/${proto} on" "${temp_dir}"/masscan-output.txt | awk -v proto="$proto" '
{
	split($0, parts, " ");
	port = parts[4];
	ip = parts[6];
	sub(/\/.*$/, "", port);  # Remove "/tcp" or "/udp"
	if (!seen[ip]) {
		value[++i] = ip;
		seen[ip] = 1;
		ips_list[ip] = port;
	} else {
		ips_list[ip] = ips_list[ip] "," port;
	}
}
END {
	for (j = 1; j <= i; j++) {
		printf("%s:%s:%s\n", proto, value[j], ips_list[value[j]]);
    }
}' >> "${temp_dir}"/nmap-input.temp.txt
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
			blue_info_message "Vulners.com site is reachable on port 443."
			else
				warning_message_with_border "Warning: Vulners.com site is NOT reachable on port 443. Please, check your firewall rules, dns configuration and your Internet link." \
					"So, vulnerability check will be not possible, only opened ports will be present in the report."
		fi
	fi

	nb_nmap_process="$(sort -n "${temp_dir}"/nmap-input.txt | wc -l)"
	date="$(date +%F_%H-%M-%S)"

	# Keep the nmap input file?
	if [[ ${report} == "on" ]]; then
		if [[ ${host_parameter} = "yes" ]]; then
			sanitized_hosts_list="$(echo "${initial_hosts}" | tr '/\\:*?"<>,;' '_')"
			merge_ip_hostname
			mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${sanitized_hosts_list}"_open-ports_"${date}".txt
			yellow_info_message "The report is available here: ${report_folder}${sanitized_hosts_list}_open-ports_${date}.txt"
		else
			merge_ip_hostname
			mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${hosts_file_no_path}"_open-ports_"${date}".txt
			yellow_info_message "The report is available here: ${report_folder}${hosts_file_no_path}_open-ports_${date}.txt"
		fi
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
	echo -n -e "\rLast scan completed for: ${ip}:${port} (${proto})... ${pourcentage}%"

	}

	# Controlling the number of Nmap scanner to launch
	if [[ ${nb_nmap_process} -ge "50" ]]; then
		max_job="50"
		blue_info_message "Warning: A lot of Nmap process to launch: ${nb_nmap_process}" \
			"So, to no disturb your system, I will only launch ${max_job} Nmap process at time."
		else
			max_job="${nb_nmap_process}"
			blue_info_message "Launching ${nb_nmap_process} Nmap scanner(s)."
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

	while IFS=, read -r ip_to_scan; do
		new_job "$i"
		count="$(expr $count + 1)"
	done < "${temp_dir}"/nmap-input.txt

	wait

	sleep 1 && tset > /dev/null 2>&1

	echo -n -e "\r                                                                                                                                                               "
	echo -n -e "\r"
	task_completion_message "Nmap phase is ended."
	
	# Verifying vulnerable hosts
	vuln_hosts_count="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
	vuln_ports_count="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"
	vuln_hosts="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done)"
	vuln_hosts_ip="$(for i in "${temp_nmap}"/*.nmap; do tac "$i" | sed -n -e '/|_.*vulners.com\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"
	date="$(date +%F_%H-%M-%S)"

	if [[ ${vuln_hosts_count} != "0" ]]; then
		warning_message_with_border "${vuln_hosts_count} vulnerable (or potentially vulnerable) host(s) found."
		echo -e -n "${vuln_hosts_ip}\n" | while IFS=, read -r line; do
			host="$(dig @${dns} -x "${line}" +short)"
			echo "${line}" "${host}" >> "${temp_dir}"/vulnerable_hosts.txt
		done
	
		vuln_hosts_format="$(awk '{print $1 "\t" $NF}' "${temp_dir}"/vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"

		if [[ ${host_parameter} = "yes" ]]; then
  			sanitized_hosts_list="$(echo "${initial_hosts}" | tr '/\\:*?"<>,;' '_')"
     			hosts_file_no_path="${sanitized_hosts_list}"
		fi

		echo -e -n "\t----------------------------\n" > "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Report date: $(date)\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "${vuln_hosts_format}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "All the details below." >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "\n\t----------------------------\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
		echo -e -n "${vuln_hosts}\n" >> "${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
	else
		blue_info_message "No host seems to have any known vulnerabilities."

	fi

elif [[ ${no_nmap_scan} == "on" ]] && [[ ${report} == "on" ]]; then
	date="$(date +%F_%H-%M-%S)"

	if [[ ${host_parameter} = "yes" ]]; then
		sanitized_hosts_list="$(echo "${initial_hosts}" | tr '/\\:*?"<>,;' '_')"

		blue_info_message "No Nmap scan to perform."
		blue_info_message "Host(s) discovered with an open port(s):"
		merge_ip_hostname
		echo -e "$(cat "${temp_dir}"/IPs_hostnames_merged.txt)"
		mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${sanitized_hosts_list}"_open-ports_"${date}".txt
		yellow_info_message "The report is available here: ${report_folder}${sanitized_hosts_list}_open-ports_${date}.txt"
	else
		merge_ip_hostname
		mv "${temp_dir}"/IPs_hostnames_merged.txt "${report_folder}""${hosts_file_no_path}"_open-ports_"${date}".txt
		yellow_info_message "The report is available here: ${report_folder}${hosts_file_no_path}_open-ports_${date}.txt"
	fi
else
	blue_info_message "No Nmap scan to perform."
	blue_info_message "Host(s) discovered with an open port(s):"
	merge_ip_hostname
	echo -e "$(cat "${temp_dir}"/IPs_hostnames_merged.txt)"
fi

##########################
# 4/4 Generating reports #
##########################

if [[ ${host_parameter} = "yes" ]]; then
	sanitized_hosts_list="$(echo "${initial_hosts}" | tr '/\\:*?"<>,;' '_')"
 	hosts_file_no_path="${sanitized_hosts_list}"
fi

if [[ ${no_nmap_scan} != "on" ]]; then
	nmap_bootstrap="${dir_name}/stylesheet/nmap-bootstrap.xsl"
	global_report="${hosts_file_no_path}_global-report_${date}.html"

	if [[ -s ${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt ]]; then
		yellow_info_message "All details on the vulnerabilities: ${report_folder}${hosts_file_no_path}_vulnerable-hosts-details_${date}.txt"
	fi

	# Merging all the Nmap XML files to one big XML file
	echo "<?xml version=\"1.0\"?>" > "${temp_dir}"/nmap-output.xml
	echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> "${temp_dir}"/nmap-output.xml
	echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> "${temp_dir}"/nmap-output.xml
	echo "<!-- nmap results file generated by MassVulScan.sh -->" >> "${temp_dir}"/nmap-output.xml
	echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n --script ${script} [ip(s)]\" \
		scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> "${temp_dir}"/nmap-output.xml
	echo "<!--Generated by MassVulScan.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> "${temp_dir}"/nmap-output.xml

	for i in "${temp_nmap}"/*.xml; do
		sed -n -e '/<host /,/<\/host>/p' "$i" >> "${temp_dir}"/nmap-output.xml
	done

	echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
	      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> "${temp_dir}"/nmap-output.xml

	# Using bootstrap to generate a beautiful HTML file (report)
	xsltproc -o "${report_folder}${global_report}" "${nmap_bootstrap}" "${temp_dir}"/nmap-output.xml 2>/dev/null

	# End of script
	yellow_info_message "HTML report generated: ${report_folder}${global_report}"
	task_completion_message "End of script execution."
else
	blue_info_message "No HTML report generated."
	task_completion_message "End of script execution."

fi

# Cleaning files
rm -rf "${temp_dir}" "${temp_nmap}" paused.conf 2>/dev/null

time_elapsed

exit 0
