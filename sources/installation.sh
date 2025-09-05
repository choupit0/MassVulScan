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
#    MassVulScan - installation helper (Debian & RedHat)
# 
# Script Name    : installation.sh
# Description    : This script is part of MassVulScan.sh main script but it could be launch alone if needed.
#                  It install all the prerequisites needed for running the main script.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Updated        : 2025-09-05
# License        : GPLv3
# Version        : 2.0
# Usage          : ./installation.sh
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

# Root check
root_user(){
  if [[ $(id -u) != "0" ]]; then
    echo -e "${red_color}You are not root.${end_color}"
    echo "Please relaunch with sudo."
    exit 1
  fi
}

# OS Detection Function
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

os_family=$(detect_os)

# We are verifying the disk space and that the Internet access is operational
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
check_port_open() {
local host=$1
local port=$2
local timeout=5

# Use /dev/tcp to check the port
timeout $timeout bash -c "exec 3<>/dev/tcp/$host/$port"
#exec 3<>/dev/tcp/$host/$port
local status=$?

if [ ! $status -eq 0 ]; then
        echo -e "${red_color}\n\"${host}\" is not reachable to download the packages...${end_color}"
        echo -e "${blue_color}${bold_color}Please, check your firewall policies, dns configuration or your Internet link.${end_color}"
        exit 1
fi

# Close the connection
exec 3<&-
exec 3>&-
}

echo -n -e "\r                                                "
echo -n -e "${blue_color}\r[-] Checking your Internet connexion...${end_color}"
sleep 1
for website in github.com nmap.org; do
        check_port_open ${website} 443
done
}

# Creating the directory and log files
log_file="${dir_name}/log/log_$(date +%F_%H-%M-%S).txt"
if [[ ! -d "${dir_name}/log" ]]; then
	mkdir "${dir_name}"/log
fi

# Detect package manager
detect_pkg_manager(){
  if [[ "${os_family}" == "debian" ]]; then
    pkg_install="apt-get install -y"
    pkg_update="apt-get update"
  elif [[ "${os_family}" == "redhat" ]]; then
    if command -v dnf >/dev/null 2>&1; then
      pkg_install="dnf install -y"
      pkg_update="dnf makecache"
    else
      pkg_install="yum install -y"
      pkg_update="yum makecache"
    fi
  else
    echo -e "${red_color}Unsupported OS family: ${os_family}${end_color}"
    exit 1
  fi
}

# Packages mapping
map_packages(){
  if [[ "$os_family" == "debian" ]]; then
    base_packages="iproute2 build-essential git wget curl gpg tar libpcre3-dev libssl-dev libpcap-dev net-tools xsltproc bind9-dnsutils netcat-traditional automake lolcat toilet boxes"
  else
    base_packages="iproute gcc gcc-c++ make git wget curl gpg tar pcre-devel openssl-devel libpcap-devel net-tools libxslt automake bind-utils nmap-ncat bzip2 toilet boxes"
  fi
}

# Install Masscan
install_masscan(){
  echo -n -e "\r                                                            "
  echo -n -e "${blue_color}\r[-] Installing Masscan...${end_color}"
  cd /tmp
  rm -rf masscan
  git clone https://github.com/robertdavidgraham/masscan.git &>> "${log_file}"
  cd masscan
  make -j"$(nproc)" &>> "${log_file}"
  cp bin/masscan /usr/local/bin/masscan
  updatedb &>> "${log_file}"
}

# Install Nmap
install_nmap(){
  echo -n -e "\r                                                            "
  echo -n -e "${blue_color}\r[-] Installing Nmap...${end_color}"
  cd /tmp
  rm -rf nmap-7.95
  wget https://nmap.org/dist/nmap-7.95.tar.bz2 &>> "${log_file}"
  tar xvjf nmap-7.95.tar.bz2 &>> "${log_file}"
  cd nmap-7.95
  ./configure --without-zenmap --without-nping --without-ndiff --without-ncat &>> "${log_file}"
  make -j"$(nproc)" &>> "${log_file}"
  make install &>> "${log_file}"
  updatedb &>> "${log_file}"
}

# Install Vulners NSE script
install_vulners(){
  echo -n -e "\r                                                            "
  echo -n -e "${blue_color}\r[-] Installing Vulners NSE...${end_color}"
  if [[ -z "${nmap_scripts_folder}" ]]; then
    if [[ $(which nmap) == */local/* ]];then
      nmap_scripts_folder="/usr/local/share/nmap/scripts/"
    else
      nmap_scripts_folder="/usr/share/nmap/scripts/"
    fi
  fi
  wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O "${nmap_scripts_folder}vulners.nse" &>> "${log_file}"
  nmap --script-updatedb &>> "${log_file}"
}

# Package installation
package_installation(){
  trap '' SIGINT

  echo -e "${red_color}${bold_color}Warning: do not try to cancel the installation at this point!!!${end_color}"
  echo -e "${blue_color}${bold_color}Installation in progress...Please, be patient!${end_color}"

  check_before_install
  detect_pkg_manager
  map_packages

  echo -n -e "${blue_color}\r[-] Installing required packages with ${pkg_install}...${end_color}"
  $pkg_update &>> "${log_file}"

  # Special case for RedHat
  if [[ "$os_family" == "redhat" ]]; then
    # Enable EPEL + Powertools/CRB
    $pkg_install epel-release &>> "${log_file}"
    if command -v dnf >/dev/null 2>&1; then
      dnf config-manager --set-enabled powertools &>> "${log_file}" || true
      dnf config-manager --set-enabled crb &>> "${log_file}" || true
    else
      yum config-manager --set-enabled powertools &>> "${log_file}" || true
    fi
  fi

  $pkg_install $base_packages &>> "${log_file}"
  if [[ $? -ne 0 ]]; then
    echo -e "${red_color}Package installation failed. See ${log_file}${end_color}"
    exit 1
  fi
  
# Additional packages and fixes for Debian
  if [[ "$os_family" == "debian" ]]; then
    # Install gum via official repo for Debian
    if ! command -v gum >/dev/null 2>&1; then
	  echo -n -e "\r                                                            "
      echo -n -e "${blue_color}\r[-] Adding Charm repo and installing gum...${end_color}"
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://repo.charm.sh/apt/gpg.key | gpg --yes --dearmor -o /etc/apt/keyrings/charm.gpg
      echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | tee /etc/apt/sources.list.d/charm.list > /dev/null 2>&1
      apt-get update &>> "${log_file}"
      apt-get install -y gum &>> "${log_file}"
    fi
  fi

  # Extra packages for RedHat
  if [[ "$os_family" == "redhat" ]]; then
    # lolcat via Ruby gem
    if ! command -v lolcat &>/dev/null; then
      $pkg_install ruby &>> "${log_file}"
      gem install lolcat &>> "${log_file}"
    fi

    # gum via Charm official repo
    if ! command -v gum &>/dev/null; then
	  echo -n -e "\r                                                              "
      echo -n -e "${blue_color}\r[-] Adding Charm repo and installing gum...${end_color}"
      cat <<EOF | tee /etc/yum.repos.d/charm.repo >/dev/null
[charm]
name=Charm
baseurl=https://repo.charm.sh/yum/
enabled=1
gpgcheck=1
gpgkey=https://repo.charm.sh/yum/gpg.key
EOF
      rpm --import https://repo.charm.sh/yum/gpg.key &>> "${log_file}"
      $pkg_install gum &>> "${log_file}"
    fi
  fi

  # --- Masscan, Nmap, Vulners ---
  if [[ ! $(which masscan 2>/dev/null) ]]; then
    install_masscan
  fi

  if [[ ! $(which nmap 2>/dev/null) ]]; then
    install_nmap
  fi

  if [[ ! -f "${nmap_scripts_folder}vulners.nse" ]]; then
    install_vulners
  fi

  clear
  echo -e "${green_color}All prerequisites installed successfully!${end_color}"
  installation_status="OK"
  echo -e "${yellow_color}${bold_color}You can now rerun the script and see the available options.\n${end_color}"
  time_elapsed
}

# Main
if [[ -z "$os_family" ]]; then
  echo -e "${yellow_color}Warning: os_family not set. Defaulting to Debian.${end_color}"
  os_family="debian"
fi

# Install or update only the necessary packages
if [[ ! -z ${packages_to_install} ]]; then
        root_user
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
elif [[ $1 == "-auto-installation" ]]; then
        root_user
        clear
        package_installation
        if [[ ${installation_status} == "OK" ]]; then
                touch .prerequisites_already_installed
        fi
        exit 0
# Exit
else
        echo -e "${yellow_color}${bold_color}Nothing to do -> Exit${end_color}"
fi

exit 0
