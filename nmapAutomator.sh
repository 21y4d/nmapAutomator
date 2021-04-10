#!/bin/sh
#by @21y4d

# Define ANSI color variables
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
origIFS="${IFS}"

# Start timer
elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
REMOTE=false

# Parse flags
while [ $# -gt 0 ]; do
        key="$1"

        case "${key}" in
        -H | --host)
                HOST="$2"
                shift
                shift
                ;;
        -t | --type)
                TYPE="$2"
                shift
                shift
                ;;
        -d | --dns)
                DNS="$2"
                shift
                shift
                ;;
        -o | --output)
                OUTPUTDIR="$2"
                shift
                shift
                ;;
        -s | --static-nmap)
                NMAPPATH="$2"
                shift
                shift
                ;;
        -r | --remote)
                REMOTE=true
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done
set -- ${POSITIONAL}

# Legacy flags support, if run without -H/-t
if [ -z "${HOST}" ]; then
        HOST="$1"
fi

if [ -z "${TYPE}" ]; then
        TYPE="$2"
fi

# Legacy types support, if quick/basic used
if expr "${TYPE}" : '^\([Qq]uick\)$' >/dev/null; then
        TYPE="Port"
elif expr "${TYPE}" : '^\([Bb]asic\)$' >/dev/null; then
        TYPE="Script"
fi

# Set DNS or default to system DNS
if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
        DNSSTRING="--dns-server=${DNSSERVER}"
else
        DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
        DNSSTRING="--system-dns"
fi

# Set output dir or default to host-based dir
if [ -z "${OUTPUTDIR}" ]; then
        OUTPUTDIR="${HOST}"
fi

# Set path to nmap binary or default to nmap in $PATH, or resort to --remote mode
if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk {'print $NF'})"
elif [ -n "${NMAPPATH}" ]; then
        NMAPPATH="$(cd "$(dirname ${NMAPPATH})" && pwd -P)/$(basename ${NMAPPATH})"
        # Ensure static binary is executable and is nmap
        if [ ! -x $NMAPPATH ]; then
                printf "${RED}\nFile is not executable! Attempting chmod +x...${NC}\n"
                chmod +x $NMAPPATH 2>/dev/null || (printf "${RED}Could not chmod. Running in Remote mode...${NC}\n\n" && REMOTE=true)
        elif [ $($NMAPPATH -h | head -c4) != "Nmap" ]; then
                printf "${RED}\nStatic binary does not appear to be Nmap! Running in Remote mode...${NC}\n\n" && REMOTE=true
        fi
        printf "${GREEN}\nUsing static nmap binary at ${NMAPPATH}${NC}\n"
else
        printf "${RED}\nNmap is not installed and -s is not used. Running in Remote mode...${NC}\n\n" && REMOTE=true
fi

# Print usage menu and exit. Used when issues are encountered
# No args needed
usage() {
        echo
        printf "${RED}Usage: $(basename $0) -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>${RED}\n"
        printf "${YELLOW}Optional: [-r/--remote ${NC}<REMOTE MODE>${YELLOW}] [-d/--dns ${NC}<DNS SERVER>${YELLOW}] [-o/--output ${NC}<OUTPUT DIRECTORY>${YELLOW}] [-s/--static-nmap ${NC}<STATIC NMAP PATH>${YELLOW}]\n\n"
        printf "Scan Types:\n"
        printf "${YELLOW}\tNetwork : ${NC}Shows all live hosts in the host's network ${YELLOW}(~15 seconds)\n"
        printf "${YELLOW}\tPort    : ${NC}Shows all open ports ${YELLOW}(~15 seconds)\n"
        printf "${YELLOW}\tScript  : ${NC}Runs a script scan on found ports ${YELLOW}(~5 minutes)\n"
        printf "${YELLOW}\tFull    : ${NC}Runs a full range port scan, then runs a script scan on new ports ${YELLOW}(~5-10 minutes)\n"
        printf "${YELLOW}\tUDP     : ${NC}Runs a UDP scan \"requires sudo\" ${YELLOW}(~5 minutes)\n"
        printf "${YELLOW}\tVulns   : ${NC}Runs CVE scan and nmap Vulns scan on all found ports ${YELLOW}(~5-15 minutes)\n"
        printf "${YELLOW}\tRecon   : ${NC}Suggests recon commands, then prompts to automatically run them\n"
        printf "${YELLOW}\tAll     : ${NC}Runs all the scans ${YELLOW}(~20-30 minutes)\n"
        printf "${NC}\n"
        exit 1
}

# Print initial header and set initial variables before scans start
# No args needed
header() {
        echo

        # Print scan type
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "${YELLOW}Running all scans on ${NC}${HOST}"
        else
                printf "${YELLOW}Running a ${TYPE} scan on ${NC}${HOST}"
        fi

        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlIP="$(host -4 -W 1 ${HOST} ${DNSSERVER} 2>/dev/null | grep ${HOST} | head -n 1 | awk {'print $NF'})"
                if [ -n "${urlIP}" ]; then
                        printf "${YELLOW} with IP ${NC}${urlIP}\n\n"
                else
                        printf ".. ${RED}Could not resolve IP of ${NC}${HOST}\n\n"
                fi
        else
                printf "\n"
        fi

        if $REMOTE; then
                printf "${YELLOW}Running in Remote mode! Some scans will be limited.\n"
        fi

        # Set $subnet variable
        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
        fi

        # Set $nmapType variable based on ping
        kernel="$(uname -s)"
        checkPing="$(checkPing "${urlIP:-$HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        # Set if host is pingable 'for ping scans'
        if expr "${nmapType}" : ".*-Pn$" >/dev/null; then
                pingable=false
                printf "${NC}\n"
                printf "${YELLOW}No ping detected.. Will not use ping scans!\n"
                printf "${NC}\n"
        else
                pingable=true

        fi

        # OS Detection
        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                printf "${NC}\n"
                printf "${GREEN}Host is likely running ${osType}\n"
        fi

        echo
        echo
}

# Used Before and After each nmap scan, to keep found ports consistent across the script
# $1 is $HOST
assignPorts() {
        # Set $commonPorts based on Port scan
        if [ -f "nmap/Port_$1.nmap" ]; then
                commonPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_$1.nmap" | sed 's/.$//')"
        fi

        # Set $allPorts based on Full scan or both Port and Full scans
        if [ -f "nmap/Full_$1.nmap" ]; then
                if [ -f "nmap/Port_$1.nmap" ]; then
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Port_$1.nmap" "nmap/Full_$1.nmap" | sed 's/.$//')"
                else
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Full_$1.nmap" | sed 's/.$//')"
                fi
        fi

        # Set $udpPorts based on UDP scan
        if [ -f "nmap/UDP_$1.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_$1.nmap" | sed 's/.$//')"
                if [ "${udpPorts}" = "Al" ]; then
                        udpPorts=""
                fi
        fi
}

# Test whether the host is pingable, and return $nmapType and $ttl
# $1 is $HOST
checkPing() {
        # If ping is not returned within a second, then ping scan is disabled with -Pn
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -${TW} 1 "$1" 2>/dev/null | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "${NMAPPATH} -Pn"
        else
                echo "${NMAPPATH}"
                if expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

# Detect OS based on $ttl
# $1 is $ttl
checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78]) echo "Windows" ;;
        6[34]) echo "Linux" ;;
        *) echo "Unknown OS!" ;;
        esac
}

# Add any extra ports found in Full scan
# No args needed
cmpPorts() {
        extraPorts="$(echo ",${allPorts}," | sed 's/,\('"$(echo "${commonPorts}" | sed 's/,/,\\|/g')"',\)\+/,/g; s/^,\|,$//g')"
}

# Print nmap progress bar
# $1 is $scanType, $2 is $percent, $3 is $elapsed, $4 is $remaining
progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        printf "In progress: $1 Scan ($3 elapsed - $4 remaining)   \n"
        printf "[${fill}>${empty}] $2%% done   \n"
        printf "\e[2A"
}

# Calculate current progress bar status based on nmap stats (with --stats-every)
# $1 is nmap command to be run, $2 is progress bar $refreshRate
nmapProgressBar() {
        refreshRate="${2:-1}"
        outputFile="$(echo $1 | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpOutputFile="${outputFile}.tmp"

        # Run the nmap command
        if [ ! -e "${outputFile}" ]; then
                $1 --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
        fi

        # Keep checking nmap stats and calling progressBar() every $refreshRate
        while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}"; } && { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}"; }; do
                scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
                progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
                sleep "${refreshRate}"
        done
        printf "\033[0K\r\n\033[0K\r\n"

        # Print final output, remove extra nmap noise
        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outputFile}" | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

# Nmap scan for live hosts
networkScan() {
        printf "${GREEN}---------------------Starting Network Scan---------------------\n"
        printf "${NC}\n"

        origHOST="${HOST}"
        HOST="${urlIP:-$HOST}"
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi

        if ! $REMOTE; then
                # Discover live hosts with nmap
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 -n -sn -oN nmap/Network_${HOST}.nmap ${subnet}/24"
                printf "${YELLOW}Found the following live hosts:${NC}\n\n"
                cat nmap/Network_${HOST}.nmap | grep -v '#' | grep "$(echo $subnet | sed 's/..$//')" | awk {'print $5'}
        elif $pingable; then
                # Discover live hosts with ping
                echo >"nmap/Network_${HOST}.nmap"
                for ip in $(seq 0 254); do
                        (ping -c 1 -${TW} 1 "$(echo $subnet | sed 's/..$//').$ip" 2>/dev/null | grep 'stat' -A1 | xargs | grep -v ', 0.*received' | awk {'print $2'} >>"nmap/Network_${HOST}.nmap") &
                done
                wait
                sed -i '/^$/d' "nmap/Network_${HOST}.nmap"
                sort -t . -k 3,3n -k 4,4n "nmap/Network_${HOST}.nmap"
        else
                printf "${YELLOW}No ping detected.. TCP Network Scan is not implemented yet in Remote mode.\n${NC}"
        fi

        HOST="${origHOST}"

        echo
        echo
        echo
}

# Port Nmap port scan
portScan() {
        printf "${GREEN}---------------------Starting Port Scan-----------------------\n"
        printf "${NC}\n"

        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --open -oN nmap/Port_${HOST}.nmap ${HOST} ${DNSSTRING}"
                assignPorts "${HOST}"
        else
                printf "${YELLOW}Port Scan is not implemented yet in Remote mode.\n${NC}"
        fi

        echo
        echo
        echo
}

# Nmap version and default script scan on found ports
scriptScan() {
        printf "${GREEN}---------------------Starting Script Scan-----------------------\n"
        printf "${NC}\n"

        if ! $REMOTE; then
                if [ -z "${commonPorts}" ]; then
                        printf "${YELLOW}No ports in port scan.. Skipping!\n"
                else
                        nmapProgressBar "${nmapType} -sCV -p${commonPorts} --open -oN nmap/Script_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi

                # Modify detected OS if Nmap detects a different OS
                if [ -f "nmap/Script_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Script_${HOST}.nmap"; then
                        serviceOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "nmap/Script_${HOST}.nmap")"
                        if [ "${osType}" != "${serviceOS}" ]; then
                                osType="${serviceOS}"
                                printf "${NC}\n"
                                printf "${NC}\n"
                                printf "${GREEN}OS Detection modified to: ${osType}\n"
                                printf "${NC}\n"
                        fi
                fi
        else
                printf "${YELLOW}Script Scan is not supported in Remote mode.\n${NC}"
        fi

        echo
        echo
        echo
}

# Nmap scan on all ports
fullScan() {
        printf "${GREEN}---------------------Starting Full Scan------------------------\n"
        printf "${NC}\n"

        if ! $REMOTE; then
                nmapProgressBar "${nmapType} -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v --open -oN nmap/Full_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"

                # Nmap version and default script scan on found ports if Script scan was not run yet
                if [ -z "${commonPorts}" ]; then
                        echo
                        echo
                        printf "${YELLOW}Making a script scan on all ports\n"
                        printf "${NC}\n"
                        nmapProgressBar "${nmapType} -sCV -p${allPorts} --open -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        assignPorts "${HOST}"
                # Nmap version and default script scan if any extra ports are found
                else
                        cmpPorts
                        if [ -z "${extraPorts}" ]; then
                                echo
                                echo
                                allPorts=""
                                printf "${YELLOW}No new ports\n"
                                printf "${NC}\n"
                        else
                                echo
                                echo
                                printf "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')\n"
                                printf "${NC}\n"
                                nmapProgressBar "${nmapType} -sCV -p${extraPorts} --open -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                                assignPorts "${HOST}"
                        fi
                fi
        else
                printf "${YELLOW}Full Scan is not implemented yet in Remote mode.\n${NC}"
        fi

        echo
        echo
        echo
}

# Nmap UDP scan
UDPScan() {
        printf "${GREEN}----------------------Starting UDP Scan------------------------\n"
        printf "${NC}\n"

        if ! $REMOTE; then
                # Ensure UDP scan runs with root priviliges
                if [ "${USER}" != 'root' ]; then
                        echo "UDP needs to be run as root, running with sudo..."
                        sudo -v
                        echo
                fi

                nmapProgressBar "sudo ${nmapType} -sU --max-retries 1 --open --open -oN nmap/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                assignPorts "${HOST}"

                # Nmap version and default script scan on found UDP ports
                if [ -n "${udpPorts}" ]; then
                        echo
                        echo
                        printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
                        printf "${NC}\n"
                        if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        else
                                sudo -v
                                nmapProgressBar "sudo ${nmapType} -sCVU -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        fi
                else
                        echo
                        echo
                        printf "${YELLOW}No UDP ports are open\n"
                        printf "${NC}\n"
                fi
        else
                printf "${YELLOW}UDP Scan is not implemented yet in Remote mode.\n${NC}"
        fi

        echo
        echo
        echo
}

# Nmap vulnerability detection script scan
vulnsScan() {
        printf "${GREEN}---------------------Starting Vulns Scan-----------------------\n"
        printf "${NC}\n"

        if ! $REMOTE; then
                # Set ports to be scanned (common or all)
                if [ -z "${allPorts}" ]; then
                        portType="common"
                        ports="${commonPorts}"
                else
                        portType="all"
                        ports="${allPorts}"
                fi

                # Ensure the vulners script is available, then run it with nmap
                if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                        printf "${RED}Please install 'vulners.nse' nmap script:\n"
                        printf "${RED}https://github.com/vulnersCom/nmap-vulners\n"
                        printf "${RED}\n"
                        printf "${RED}Skipping CVE scan!\n"
                        printf "${NC}\n"
                else
                        printf "${YELLOW}Running CVE scan on ${portType} ports\n"
                        printf "${NC}\n"
                        nmapProgressBar "${nmapType} -sV --script vulners --script-args mincvss=7.0 -p${ports} --open -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                        echo
                fi

                # Nmap vulnerability detection script scan
                echo
                printf "${YELLOW}Running Vuln scan on ${portType} ports\n"
                printf "${YELLOW}This may take a while, depending on the number of detected services..\n"
                printf "${NC}\n"
                nmapProgressBar "${nmapType} -sV --script vuln -p${ports} --open -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        else
                printf "${YELLOW}Vulns Scan is not supported in Remote mode.\n${NC}"
        fi

        echo
        echo
        echo
}

# Run reconRecommend(), ask user for tools to run, then run runRecon()
recon() {
        IFS="
"

        # Run reconRecommend()
        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

        # Detect any missing tools
        for tool in ${allRecon}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTools="$(echo ${missingTools} ${tool} | awk '{$1=$1};1')"
                fi
        done

        # Exclude missing tools, and print help for installing them
        if [ -n "${missingTools}" ]; then
                printf "${RED}Missing tools: ${NC}${missingTools}\n"
                printf "\n${RED}You can install with:\n"
                printf "${YELLOW}sudo apt install ${missingTools} -y\n"
                printf "${NC}\n\n"

                availableRecon="$(echo "${allRecon}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
        fi

        secs=30
        count=0

        # Ask user for which recon tools to run, default to All if no answer is detected in 30s
        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        printf "${YELLOW}\n"
                        printf "Which commands would you like to run?${NC}\nAll (Default), ${availableRecon}, Skip <!>\n\n"
                        while [ ${count} -lt ${secs} ]; do
                                tlimit=$((secs - count))
                                printf "\033[2K\rRunning Default in (${tlimit})s: "

                                # Waits 1 second for user's input - POSIX read -t
                                reconCommand="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1))
                                [ -n "${reconCommand}" ] && break
                        done
                        if expr "${reconCommand}" : '^\([Aa]ll\)$' >/dev/null || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"
                                reconCommand="!"
                        elif expr " ${availableRecon}," : ".* ${reconCommand}," >/dev/null; then
                                runRecon "${HOST}" "${reconCommand}"
                                reconCommand="!"
                        elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                                reconCommand="!"
                                echo
                                echo
                                echo
                        else
                                printf "${NC}\n"
                                printf "${RED}Incorrect choice!\n"
                                printf "${NC}\n"
                        fi
                done
        else
                printf "${YELLOW}No Recon Recommendations found...\n"
                printf "${NC}\n\n\n"
        fi

        IFS="${origIFS}"
}

# Recommend recon tools/commands to be run on found ports
reconRecommend() {
        printf "${GREEN}---------------------Recon Recommendations---------------------\n"
        printf "${NC}\n"

        IFS="
"

        # Set $ports and $file variables
        if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
                ports="${allPorts}"
                file="$(cat "nmap/Script_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
        elif [ -f "nmap/Script_${HOST}.nmap" ]; then
                ports="${commonPorts}"
                file="$(grep "open" "nmap/Script_${HOST}.nmap" | grep -v "#")"

        fi

        # SMTP recon
        if echo "${file}" | grep -q "25/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}SMTP Recon:\n"
                printf "${NC}\n"
                echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""
                echo
        fi

        # DNS Recon
        if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
                printf "${NC}\n"
                printf "${YELLOW}DNS Recon:\n"
                printf "${NC}\n"
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""
                echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"recon/dnsrecon_${HOST}.txt\""
                echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"recon/dnsrecon-local_${HOST}.txt\""
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"recon/dig_${HOST}.txt\""
                echo
        fi

        # Web recon
        if echo "${file}" | grep -i -q http; then
                printf "${NC}\n"
                printf "${YELLOW}Web Servers Recon:\n"
                printf "${NC}\n"

                # HTTP recon
                for line in ${file}; do
                        if echo "${line}" | grep -i -q http; then
                                port="$(echo "${line}" | cut -d "/" -f 1)"
                                if echo "${line}" | grep -q ssl/http; then
                                        urlType='https://'
                                        echo "sslscan \"${HOST}\" | tee \"recon/sslscan_${HOST}_${port}.txt\""
                                        echo "nikto -host \"${urlType}${HOST}:${port}\" -ssl | tee \"recon/nikto_${HOST}_${port}.txt\""
                                else
                                        urlType='http://'
                                        echo "nikto -host \"${urlType}${HOST}:${port}\" | tee \"recon/nikto_${HOST}_${port}.txt\""
                                fi
                                if type ffuf >/dev/null 2>&1; then
                                        extensions="$(echo 'index' >./index && ffuf -s -w ./index:FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                        echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '${extensions}' -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                                else
                                        extensions="$(echo 'index' >./index && gobuster dir -w ./index -t 30 -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -u "${urlType}${HOST}:${port}" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                        echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -ekx '${extensions}' -u \"${urlType}${HOST}:${port}\" -o \"recon/gobuster_${HOST}_${port}.txt\""
                                fi
                                echo
                        fi
                done
                # CMS recon
                if [ -f "nmap/Script_${HOST}.nmap" ]; then
                        cms="$(grep http-generator "nmap/Script_${HOST}.nmap" | cut -d " " -f 2)"
                        if [ -n "${cms}" ]; then
                                for line in ${cms}; do
                                        port="$(sed -n 'H;x;s/\/.*'"${line}"'.*//p' "nmap/Script_${HOST}.nmap")"

                                        # case returns 0 by default (no match), so ! case returns 1
                                        if ! case "${cms}" in Joomla | WordPress | Drupal) false ;; esac then
                                                printf "${NC}\n"
                                                printf "${YELLOW}CMS Recon:\n"
                                                printf "${NC}\n"
                                        fi
                                        case "${cms}" in
                                        Joomla!) echo "joomscan --url \"${HOST}:${port}\" | tee \"recon/joomscan_${HOST}_${port}.txt\"" ;;
                                        WordPress) echo "wpscan --url \"${HOST}:${port}\" --enumerate p | tee \"recon/wpscan_${HOST}_${port}.txt\"" ;;
                                        Drupal) echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"recon/droopescan_${HOST}_${port}.txt\"" ;;
                                        esac
                                done
                        fi
                fi
        fi

        # SNMP recon
        if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
                printf "${NC}\n"
                printf "${YELLOW}SNMP Recon:\n"
                printf "${NC}\n"
                echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
                echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""
                echo
        fi

        # LDAP recon
        if echo "${file}" | grep -q "389/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}ldap Recon:\n"
                printf "${NC}\n"
                echo "ldapsearch -x -h \"${HOST}\" -s base | tee \"recon/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -h \"${HOST}\" -b \"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"recon/ldapsearch_DC_${HOST}.txt\""
                echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d \\" \\" -f2)\"' \"${HOST}\" -oN \"recon/nmap_ldap_${HOST}.txt\""
                echo
        fi

        # SMB recon
        if echo "${file}" | grep -q "445/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}SMB Recon:\n"
                printf "${NC}\n"
                echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
                if [ "${osType}" = "Windows" ]; then
                        echo "nmap -Pn -p445 --script vuln -oN \"recon/SMB_vulns_${HOST}.txt\" \"${HOST}\""
                elif [ "${osType}" = "Linux" ]; then
                        echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
                fi
                echo
        elif echo "${file}" | grep -q "139/tcp" && [ "${osType}" = "Linux" ]; then
                printf "${NC}\n"
                printf "${YELLOW}SMB Recon:\n"
                printf "${NC}\n"
                echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
                echo
        fi

        # Oracle DB recon
        if echo "${file}" | grep -q "1521/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}Oracle Recon:\n"
                printf "${NC}\n"
                echo "odat sidguesser -s \"${HOST}\" -p 1521"
                echo "odat passwordguesser -s \"${HOST}\" -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
                echo
        fi

        IFS="${origIFS}"

        echo
        echo
        echo
}

# Run chosen recon commands
runRecon() {
        echo
        echo
        echo
        printf "${GREEN}---------------------Running Recon Commands--------------------\n"
        printf "${NC}\n"

        IFS="
"

        mkdir -p recon/

        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
        fi

        # Run each line
        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
                fileName="$(echo "${line}" | awk -F "recon/" '{print $2}')"
                if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
                        printf "${NC}\n"
                        printf "${YELLOW}Starting ${currentScan} scan\n"
                        printf "${NC}\n"
                        eval "${line}"
                        printf "${NC}\n"
                        printf "${YELLOW}Finished ${currentScan} scan\n"
                        printf "${NC}\n"
                        printf "${YELLOW}=========================\n"
                fi
        done

        IFS="${origIFS}"

        echo
        echo
        echo
}

# Print footer with total elapsed time
footer() {

        printf "${GREEN}---------------------Finished all scans------------------------\n"
        printf "${NC}\n\n"

        elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        elapsedSeconds=$((elapsedEnd - elapsedStart))

        if [ ${elapsedSeconds} -gt 3600 ]; then
                hours=$((elapsedSeconds / 3600))
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
        elif [ ${elapsedSeconds} -gt 60 ]; then
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
        else
                printf "${YELLOW}Completed in ${elapsedSeconds} seconds\n"
        fi
        printf "${NC}\n"
}

# Choose run type based on chosen flags
main() {
        assignPorts "${HOST}"

        header

        case "${TYPE}" in
        [Nn]etwork) networkScan "${HOST}" ;;
        [Pp]ort) portScan "${HOST}" ;;
        [Ss]cript)
                [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"
                scriptScan "${HOST}"
                ;;
        [Ff]ull) fullScan "${HOST}" ;;
        [Uu]dp) UDPScan "${HOST}" ;;
        [Vv]ulns)
                [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"
                vulnsScan "${HOST}"
                ;;
        [Rr]econ)
                [ ! -f "nmap/Port_${HOST}.nmap" ] && portScan "${HOST}"
                [ ! -f "nmap/Script_${HOST}.nmap" ] && scriptScan "${HOST}"
                recon "${HOST}"
                ;;
        [Aa]ll)
                portScan "${HOST}"
                scriptScan "${HOST}"
                fullScan "${HOST}"
                UDPScan "${HOST}"
                vulnsScan "${HOST}"
                recon "${HOST}"
                ;;
        esac

        footer
}

# Ensure host and type are passed as arguments
if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then
        usage
fi

# Ensure $HOST is an IP or a URL
if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
        printf "${RED}\n"
        printf "${RED}Invalid IP or URL!\n"
        usage
fi

# Ensure selected scan type is among available choices, then run the selected scan
if ! case "${TYPE}" in [Nn]etwork | [Pp]ort | [Ss]cript | [Ff]ull | UDP | udp | [Vv]ulns | [Rr]econ | [Aa]ll) false ;; esac then
        mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
        main | tee "nmapAutomator_${HOST}_${TYPE}.txt"
else
        printf "${RED}\n"
        printf "${RED}Invalid Type!\n"
        usage
fi
