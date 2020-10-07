#!/bin/bash

############################################################################################################################
#
# Script Name    : installation.sh
# Description    : This script is part of MassVulScan.sh main script but it could be launch alone if needed.
#                  It install all the prerequisites needed for running the main script.
#                  It's only available for Debian OS family.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20190724
# Version        : 1.0
# Usage          : ./installation.sh
# Prerequisites  : N/A
#
#############################################################################################################################

yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
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
echo -n -e "${blue_color}\r[-] Before, verifying space disk available...${end_color}"
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

echo -n -e "\r                                             "
echo -n -e "${blue_color}\r[-] Checking your Internet connexion...${end_color}"
sleep 1


# Checking the Internet connection
check_github_status="$(nc -z -v -w 1 github.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"
check_nmap_status="$(nc -z -v -w 1 nmap.org 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

if [[ ${check_github_status} == "open" ]] && [[ ${check_nmap_status} == "open" ]]; then
	temp_folder="$(mktemp -d /tmp/temp_folder-XXXXXXXX)"
	if [[ ! -d "./log" ]]; then
		mkdir "$(pwd)"/log
	fi
	log_file="$(pwd)/log/log_$(date +%F_%H-%M-%S).txt"
	echo -e "${yellow_color}\r[I] To view the detailled progression: tail -f ${bold_color}${log_file}${end_color}"
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
	wget https://nmap.org/dist/nmap-7.80.tgz &>> "${log_file}"
	cd "${temp_folder}/masscan"
	echo -n -e "\r                                                                            "
	echo -n -e "${blue_color}\r[-] Compiling \"Masscan\" ...${end_color}" && echo "---- COMPILING MASSCAN ---" &>> "${log_file}"
	make -j"$(nproc)" &>> "${log_file}"
	proc_status
	echo -n -e "${blue_color}\r[-] Installing/upgrading \"Masscan\"...${end_color}" && echo "---- MASSCAN INSTALLATION ---" &>> "${log_file}"
	mv -f "bin/masscan" "/usr/bin/" &>> "${log_file}"
	proc_status
	cd "${temp_folder}"
	tar -xzf nmap-7.80.tgz &>> "${log_file}"
	cd "nmap-7.80"
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
	mv -f "${temp_folder}/nmap-vulners/vulners.nse" "/usr/local/share/nmap/scripts/"
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
	time_elapsed
	echo -e "${blue_color}${bold_color}Please, now launch again the script to see options.\n${end_color}"
	exit 0
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
		exit 0
	else
		root_user
		echo -e "${blue_color}${bold_color}[-] Great, we starting the installation...please, be patient!${end_color}"
		# Clearing the screen
		clear
		prerequisites_install
		time_elapsed
		exit 0
	fi
else
	echo -e "${blue_color}${bold_color}No APT package manager found on your system.${end_color}"
	echo -e "${yellow_color}[I] The automatic installation feature is only available for Debian OS family.${end_color}"
	exit 1
fi
}

if [[ $1 == "-y" ]]; then
        root_user
        echo -e "${blue_color}${bold_color}[-] Great, we starting the installation...please, be patient!${end_color}"
        # Clearing the screen
        clear
        prerequisites_install
        time_elapsed
        exit 0
else
        auto_install_menu
fi
