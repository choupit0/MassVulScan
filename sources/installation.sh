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
# Script Name    : installation.sh
# Description    : This script is part of MassVulScan.sh main script but it could be launch alone if needed.
#                  It install all the prerequisites needed for running the main script.
#                  It's only available for Debian OS family.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20250409
# Version        : 1.2
# Usage          : ./installation.sh
# Prerequisites  : N/A
#

yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
dir_name="$(dirname -- "$( readlink -f -- "$0"; )")"
script_start="$SECONDS"

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

###############################################################################
# We are verifying the disk space and that the Internet access is operational #
###############################################################################
check_before_install(){
# Checking available space disk
echo -n -e "${blue_color}\r[-] Before, verifying space disk available...${end_color}"
sleep 1

for folder in "/tmp" "/bin" "/usr"; do
space_m="$(df --output=avail -BM ${folder} | tail -n 1 | grep -o "[0-9]*M")"
space="$(df --output=avail -BM ${folder} | tail -n 1 | grep -o "[0-9]*")"
if [[ ${space} -lt "250" ]]; then
	echo -e "${red_color}\nThere is no enough space available in the ${folder} folder: ${space_m}${end_color}"
	exit 1
fi
done

echo -n -e "\r                                                "
echo -n -e "${blue_color}\r[-] Checking your Internet connexion...${end_color}"
sleep 1

# Checking the Internet connection
check_github_status="$(nc -z -v -w 1 github.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"
check_nmap_status="$(nc -z -v -w 1 nmap.org 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

if [[ ! ${check_github_status} == "open" ]] && [[ ! ${check_nmap_status} == "open" ]]; then
	echo -e "${red_color}\nI can't reach Internet sites (\"github.com\" and \"nmap.org\") for downloading the packages...${end_color}"
	echo -e "${blue_color}${bold_color}Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
	exit 1
fi
}

##########################################################
# We are installing the missing prerequisites (packages) #
##########################################################
package_installation(){
# Disable CTRL+C
trap '' SIGINT

echo -e "${red_color}${bold_color}Warning: do not try to cancel the installation at this point!!!${end_color}"
echo -e "${blue_color}${bold_color}Installation in progress...Please, be patient!${end_color}"

check_before_install

# Error status
proc_status(){
if [[ $? == "0" ]]; then
	echo -e "${yellow_color}Done.${end_color}"
else
	echo -e "${red_color}Failed attempt -> check the log file: ${log_file}${end_color}"
	exit 1
fi
}

# Creating the directory and log files
log_file="${dir_name}/log/log_$(date +%F_%H-%M-%S).txt"
if [[ ! -d "${dir_name}/log" ]]; then
	mkdir "${dir_name}"/log
fi

packages_to_install="${packages_to_install}"
packages_for_gum="$(echo "${packages_to_install}" | grep -oE '[^ ]+' | grep -E "curl|gpg" | tr '\n' ' ')"
packages_to_install_filtered="$(echo "${packages_to_install}" | grep -oE '[^ ]+' | grep -vE "nmap|masscan|vulners" | tr '\n' ' ')"


if [[ -z ${nmap_scripts_folder} ]]; then
	nmap_scripts_folder="/usr/local/share/nmap/scripts"
else
	nmap_scripts_folder="${nmap_scripts_folder}"
fi

# We are forcing the installation or update of all packages
if [[ -z ${packages_to_install} ]] || [[ ${auto_installation_latest} == "yes" ]]; then
	echo -n -e "\r                                                         "
	echo -n -e "${blue_color}\r[-] Updating and installing the requisites packages (APT)...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
	sudo mkdir -p /etc/apt/keyrings
	curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --yes --dearmor -o /etc/apt/keyrings/charm.gpg
	echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list > /dev/null 2>&1
	apt-get update &>> "${log_file}"
	apt-get install -y build-essential git curl wget gpg tar libpcre3-dev libssl-dev libpcap-dev net-tools xsltproc bind9-dnsutils netcat-traditional toilet boxes lolcat gum &>> "${log_file}"
	proc_status
	temp_dir_install="$(mktemp -d /tmp/temp_dir_install_all-XXXXXXXX)"
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Masscan\"...${end_color}" && echo "---- DOWNLOAD MASSCAN SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	git clone https://github.com/robertdavidgraham/masscan.git &>> "${log_file}"
	cd "${temp_dir_install}/masscan"
	echo -n -e "\r                                                                            "
	echo -n -e "${blue_color}\r[-] Compiling \"Masscan\" ...${end_color}" && echo "---- COMPILING MASSCAN ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Masscan\"...${end_color}" && echo "---- MASSCAN INSTALLATION ---" &>> "${log_file}"
	mv -f "bin/masscan" "/usr/bin/" &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Nmap\"...${end_color}" && echo "---- DOWNLOAD NMAP SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	wget "https://nmap.org/dist/nmap-7.95.tgz" &>> "${log_file}"
	tar -xzf nmap-7.95.tgz &>> "${log_file}"
	cd "nmap-7.95"
	echo -n -e "${blue_color}\r[-] Resolving dependencies for \"Nmap\"...${end_color}" && echo "---- DEPENDENCIES FOR NMAP ---" &>> "${log_file}"
	./configure &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Compiling \"Nmap\" (this may take time)...${end_color}" && echo "---- COMPILING NMAP ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	echo -n -e "\r                                                         "
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Nmap\"...${end_color}" && echo "---- NMAP INSTALLATION ---" &>> "${log_file}"
	make install &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Vulners.nse\"...${end_color}" && echo "---- DOWNLOAD VULNERS SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	git clone https://github.com/vulnersCom/nmap-vulners &>> "${log_file}"
	echo -n -e "\r                                                            "
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Vulners.nse\"...${end_color}" && echo "---- VULNERS.NSE INSTALLATION ---" &>> "${log_file}"
	mv -f "${temp_dir_install}/nmap-vulners/vulners.nse" "${nmap_scripts_folder}"
	proc_status
	echo -n -e "\r                                              "
	echo -n -e "${blue_color}\r[-] Updating the databases...${end_color}" && echo "---- DATABASES UPDATE ---" &>> "${log_file}"
	updatedb &>> "${log_file}"
	nmap --script-updatedb &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Removing temporary files and folders...${end_color}" && echo "---- REMOVE TEMP FOLDERS ---" &>> "${log_file}"
	rm -rf "${temp_dir_install}" &>> "${log_file}"
	proc_status
	echo -n -e "\r                                           "
	echo -n -e "${green_color}\r[V] Installation finished.\n${end_color}"
	echo -e "${yellow_color}${bold_color}You can now rerun the script and see the available options. Happy scanning!\n${end_color}"
	time_elapsed
	exit 0
fi

# APT update
if [[ ${packages_to_install_filtered} ]]; then
	echo -n -e "\r                                       "
	echo -n -e "${blue_color}\r[-] Updating your package lists...${end_color}" && echo "---- APT UPDATE ---" &> "${log_file}"
	apt-get update &>> "${log_file}"
fi

# We are installing the missing packages
if [[ "${packages_to_install_filtered}" =~ "gum" ]] && [[ ! "${packages_for_gum}" ]]; then
	echo -n -e "${blue_color}\r[-] Installing the requisites packages (APT)...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
	sudo mkdir -p /etc/apt/keyrings
	curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --yes --dearmor -o /etc/apt/keyrings/charm.gpg
	echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list > /dev/null 2>&1
	apt-get install -y ${packages_to_install_filtered} &>> "${log_file}"
	proc_status
elif [[ "${packages_to_install_filtered}" =~ "gum" ]] && [[ ${packages_for_gum} ]]; then	
	echo -n -e "${blue_color}\r[-] Installing the requisites packages (APT)...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
	apt-get install -y ${packages_for_gum} &>> "${log_file}"
	sudo mkdir -p /etc/apt/keyrings
	curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --yes --dearmor -o /etc/apt/keyrings/charm.gpg
	echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list > /dev/null 2>&1
	apt-get install -y ${packages_to_install_filtered} &>> "${log_file}"
	proc_status
elif [[ "${packages_to_install_filtered}" ]]; then	
	echo -n -e "${blue_color}\r[-] Installing the requisites packages (APT)...${end_color}" && echo "---- APT INSTALL ---" &>> "${log_file}"
	apt-get install -y ${packages_to_install_filtered} &>> "${log_file}"
	proc_status
fi

# We are installing Masscan
if [[ " ${packages_to_install} " =~ " masscan " ]]; then
	temp_dir_install="$(mktemp -d /tmp/temp_dir_install_masscan-XXXXXXXX)"
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Masscan\"...${end_color}" && echo "---- DOWNLOAD MASSCAN SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	git clone https://github.com/robertdavidgraham/masscan.git &>> "${log_file}"
	cd "${temp_dir_install}/masscan"
	echo -n -e "\r                                                                            "
	echo -n -e "${blue_color}\r[-] Compiling \"Masscan\" ...${end_color}" && echo "---- COMPILING MASSCAN ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Masscan\"...${end_color}" && echo "---- MASSCAN INSTALLATION ---" &>> "${log_file}"
	mv -f "bin/masscan" "/usr/bin/" &>> "${log_file}"
	proc_status
        echo -n -e "\r                                              "
        echo -n -e "${blue_color}\r[-] Updating the databases...${end_color}" && echo "---- DATABASES UPDATE ---" &>> "${log_file}"
        updatedb &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Removing temporary files and folders...${end_color}" && echo "---- REMOVE TEMP FOLDERS ---" &>> "${log_file}"
	rm -rf "${temp_dir_install}" &>> "${log_file}"
	proc_status
fi

# We are installing Nmap
if [[ " ${packages_to_install} " =~ " nmap " ]]; then
	temp_dir_install="$(mktemp -d /tmp/temp_dir_install_nmap-XXXXXXXX)"
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Nmap\"...${end_color}" && echo "---- DOWNLOAD NMAP SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	wget https://nmap.org/dist/nmap-7.95.tgz &>> "${log_file}"
	tar -xzf nmap-7.95.tgz &>> "${log_file}"
	cd "nmap-7.95"
	echo -n -e "${blue_color}\r[-] Resolving dependencies for \"Nmap\"...${end_color}" && echo "---- DEPENDENCIES FOR NMAP ---" &>> "${log_file}"
	./configure &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Compiling \"Nmap\" (this may take time)...${end_color}" && echo "---- COMPILING NMAP ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	echo -n -e "\r                                                         "
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Nmap\"...${end_color}" && echo "---- NMAP INSTALLATION ---" &>> "${log_file}"
	make install &>> "${log_file}"
	proc_status
        echo -n -e "\r                                              "
        echo -n -e "${blue_color}\r[-] Updating the databases...${end_color}" && echo "---- DATABASES UPDATE ---" &>> "${log_file}"
        updatedb &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Removing temporary files and folders...${end_color}" && echo "---- REMOVE TEMP FOLDERS ---" &>> "${log_file}"
	rm -rf "${temp_dir_install}" &>> "${log_file}"
	proc_status
fi

# We are installing Vulners
if [[ " ${packages_to_install} " =~ " vulners " ]]; then
	temp_dir_install="$(mktemp -d /tmp/temp_dir_install_vulners-XXXXXXXX)"
	echo -n -e "${blue_color}\r[-] Getting the source packages \"Vulners.nse\"...${end_color}" && echo "---- DOWNLOAD VULNERS SOURCES ---" &>> "${log_file}"
	cd "${temp_dir_install}"
	git clone https://github.com/vulnersCom/nmap-vulners &>> "${log_file}"
	echo -n -e "\r                                                            "
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Vulners.nse\"...${end_color}" && echo "---- VULNERS.NSE INSTALLATION ---" &>> "${log_file}"
	mv -f "${temp_dir_install}/nmap-vulners/vulners.nse" "${nmap_scripts_folder}"
	proc_status
	echo -n -e "\r                                              "
	echo -n -e "${blue_color}\r[-] Updating the databases...${end_color}" && echo "---- DATABASES UPDATE ---" &>> "${log_file}"
	updatedb &>> "${log_file}"
	nmap --script-updatedb &>> "${log_file}"
	echo -n -e "${blue_color}\r[-] Removing temporary files and folders...${end_color}" && echo "---- REMOVE TEMP FOLDERS ---" &>> "${log_file}"
	rm -rf "${temp_dir_install}" &>> "${log_file}"
	proc_status
fi

echo -n -e "\r                                           "
echo -n -e "${green_color}\r[V] Installation finished.\n${end_color}"
echo -e "${yellow_color}${bold_color}You can now rerun the script and see the available options. Happy scanning!\n${end_color}"
installation_status="OK"
time_elapsed
}

# Automatic installation menu
auto_install_menu(){
if [[ $(command -v apt-get) ]]; then
	echo -e "${yellow_color}${bold_color}Warning: Running this script directly will install or update ALL packages to their latest versions.${end_color}"
	echo -e "${yellow_color}${bold_color}Run the main script \"MassVulScan.sh\" to identify only the packages that need to be installed or updated.${end_color}"
	echo -e "${blue_color}${bold_color}All packages listed below will be installed or updated (approximately 5 minutes). Do you agree?${end_color}"
	echo -e "${blue_color}\t--> From apt: build-essential git curl wget gpg tar libpcre3-dev libssl-dev libpcap-dev net-tools xsltproc bind9-dnsutils netcat-traditional toilet boxes lolcat gum ${end_color}"
	echo -e "${blue_color}\t--> From git: masscan (+ compilation) and NSE script vulners.nse${end_color}"
	echo -e "${blue_color}\t--> From source: nmap (+ compilation)${end_color}"
	echo -e "${yellow_color}${bold_color}Just typing \"Enter|Return\" key to exit or write \"YES\" to continue${end_color}"
	echo -e "${blue_color}${bold_color}${end_color}"
	read -p "Automatic installation? >> " -r -t 60 auto_install_answer
	if [[ -z ${auto_install_answer} ]] || [[ ${auto_install_answer} != "YES" ]];then
		echo -e "${yellow_color}Okay, exit.${end_color}"
		exit 0
	else
		auto_installation_latest="yes"
		root_user
		clear
		package_installation
		exit 0
	fi
else
	echo -e "${blue_color}${bold_color}No APT package manager found on your system.${end_color}"
	echo -e "${yellow_color}[I] The automatic installation feature is only available for Debian OS family.${end_color}"
	exit 1
fi
}

# Install or update only the necessary packages
if [[ ! -z ${packages_to_install} ]]; then
        root_user
        clear
	echo -e "Some packages are missing or need an update: ${blue_color}${packages_to_install}${end_color}"
	echo -e "${yellow_color}${bold_color}Just typing \"Enter|Return\" key to exit or write \"YES\" to continue${end_color}"
	read -p "Would you like me to install them for you?? >> " -r -t 60 auto_install_answer
	if [[ -z ${auto_install_answer} ]] || [[ ${auto_install_answer} != "YES" ]];then
		echo -e "${yellow_color}Okay, exit.${end_color}"
		exit 0
	else
		clear
		package_installation
		if [[ ${installation_status} == "OK" ]]; then
			touch .prerequisites_already_installed
		fi
	fi
        exit 0
# Install or update all packages to their latest versions
elif [[ $1 == "--auto-installation-latest" ]]; then
	auto_installation_latest="yes"
        root_user
        clear
	package_installation
        exit 0
# Interactive menu
else
	auto_install_menu
fi

exit 0
