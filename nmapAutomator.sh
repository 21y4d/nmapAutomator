#!/bin/bash
#by @21y4d

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

SECONDS=0

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
        --default)
                DEFAULT=YES
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done
set -- ${POSITIONAL}

if [ -z "${HOST}" ]; then
        HOST="$1"
fi

if [ -z "${TYPE}" ]; then
        TYPE="$2"
fi

if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
else
        DNSSERVER="1.1.1.1"
fi
DNSSTRING="--dns-server=${DNSSERVER}"

if [ -z "${OUTPUTDIR}" ]; then
        OUTPUTDIR="${HOST}"
fi

usage() {
        echo
        printf "${RED}Usage: $0 -H/--host <TARGET-IP> -t/--type <TYPE> [-d/--dns <DNS SERVER> -o/--output <OUTPUT DIRECTORY>]\n"
        printf "${YELLOW}\n"
        printf "Scan Types:\n"
        printf "\tQuick: Shows all open ports quickly (~15 seconds)\n"
        printf "\tBasic: Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)\n"
        printf "\tUDP  : Runs \"Basic\" on UDP ports \"requires sudo\" (~5 minutes)\n"
        printf "\tFull : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)\n"
        printf "\tVulns: Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)\n"
        printf "\tRecon: Suggests recon commands, then prompts to automatically run them\n"
        printf "\tAll  : Runs all the scans (~20-30 minutes)\n"
        printf "${NC}\n"
        exit 1
}

header() {
        echo

        if [ "${TYPE}" = "All" ]; then
                printf "${YELLOW}Running all scans on ${HOST}\n"
        else
                printf "${YELLOW}Running a ${TYPE} scan on ${HOST}\n"
        fi

        subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"

        checkPing="$(checkPing "${HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        if [ "${nmapType}" != "nmap" ]; then
                printf "${NC}\n"
                printf "${YELLOW}No ping detected.. Running with -Pn option!\n"
                printf "${NC}\n"
        fi

        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                printf "${NC}\n"
                printf "${GREEN}Host is likely running ${osType}\n"
                printf "${NC}\n"
        fi

        echo
        echo
}

assignPorts() {
        if [ -f "nmap/Quick_${HOST}.nmap" ]; then
                basicPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Quick_${HOST}.nmap" | sed 's/.$//')"
        fi

        if [ -f "nmap/Full_${HOST}.nmap" ]; then
                if [ -f "nmap/Quick_${HOST}.nmap" ]; then
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Quick_${HOST}.nmap" "nmap/Full_${HOST}.nmap" | sed 's/.$//')"
                else
                        allPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/Full_${HOST}.nmap" | sed 's/.$//')"
                fi
        fi

        if [ -f "nmap/UDP_${HOST}.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_${HOST}.nmap" | sed 's/.$//')"
                if [ "${udpPorts}" = "Al" ]; then
                        udpPorts=""
                fi
        fi
}

checkPing() {
        pingTest="$(ping -c 1 -W 3 "${HOST}" | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "nmap -Pn"
        else
                echo "nmap"
                if expr "${HOST}" : '^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$' > /dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78]) echo "Windows" ;;
        6[34]) echo "Linux" ;;
        *) echo "Unknown OS!" ;;
        esac
}

cmpPorts() {
        # To understand this magic, suppose $allPorts=22,80,445,8080 and $basicPorts=22,80
        # This is how it looks like with the inner sub-shell and variables expanded:
        # extraPorts="$(echo ,22,80,445,8080, | sed 's/,\(22,\|80,\)\+/,/g; s/^,\|,$//g')"
        # The result of the expansion: extraPorts="445,8080"
        extraPorts="$(echo ",${allPorts}," | sed 's/,\('"$(echo "${basicPorts}" | sed 's/,/,\\|/g')"',\)\+/,/g; s/^,\|,$//g')"
}

progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        printf "In progress: $1 Scan ($3 elapsed - $4 remaining)   \n"
        printf "[${fill}>${empty}] $2%% done   \n"
        printf "\e[2A"
}

nmapProgressBar() {
        refreshRate="${2:-1}"
        outputFile="$(echo $1 | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpOutputFile="${outputFile}.tmp"
        if [ ! -e "${outputFile}" ]; then
                $1 --stats-every "${refreshRate}s" > "${tmpOutputFile}" 2>&1 &
        fi

        while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}"; } && { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}"; }; do
                scanType="$(tail -n 2 "${tmpOutputFile}" | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percent="$(tail -n 2 "${tmpOutputFile}" | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpOutputFile}" | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                remaining="$(tail -n 2 "${tmpOutputFile}" | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
                progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
                sleep "${refreshRate}"
        done
        printf "\033[0K\r\n\033[0K\r\n"
        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/^$/p' "${outputFile}"
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

quickScan() {
        printf "${GREEN}---------------------Starting Nmap Quick Scan---------------------\n"
        printf "${NC}\n"

        nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Quick_${HOST}.nmap ${HOST} ${DNSSTRING}"
        assignPorts "${HOST}"

        echo
        echo
        echo
}

basicScan() {
        printf "${GREEN}---------------------Starting Nmap Basic Scan---------------------\n"
        printf "${NC}\n"

        if [ -z "${basicPorts}" ]; then
                printf "${YELLOW}No ports in quick scan.. Skipping!\n"
        else
                nmapProgressBar "${nmapType} -sCV -p${basicPorts} -oN nmap/Basic_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
        fi

        if [ -f "nmap/Basic_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Basic_${HOST}.nmap"; then
                    serviceOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "nmap/Basic_${HOST}.nmap")"
                if [ "${osType}" != "${serviceOS}" ]; then
                        osType="${serviceOS}"
                        printf "${NC}\n"
                        printf "${NC}\n"
                        printf "${GREEN}OS Detection modified to: ${osType}\n"
                        printf "${NC}\n"
                fi
        fi

        echo
        echo
        echo
}

UDPScan() {
        printf "${GREEN}----------------------Starting Nmap UDP Scan----------------------\n"
        printf "${NC}\n"

        if [ "${USER}" != 'root' ]; then
                echo "UDP needs to be run as root, running with sudo..."
                sudo -v
                echo
        fi

        nmapProgressBar "sudo ${nmapType} -sU --max-retries 1 --open -oN nmap/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        assignPorts "${HOST}"

        if [ -n "${udpPorts}" ]; then
                echo
                echo
                printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
                printf "${NC}\n"
                if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                        nmapProgressBar "${nmapType} -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                else
                        nmapProgressBar "${nmapType} -sCVU -p${udpPorts} -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi
        else
                echo
                echo
                printf "${YELLOW}No UDP ports are open\n"
                printf "${NC}\n"
        fi

        echo
        echo
        echo
}

fullScan() {
        printf "${GREEN}---------------------Starting Nmap Full Scan----------------------\n"
        printf "${NC}\n"

        nmapProgressBar "${nmapType} -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Full_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        assignPorts "${HOST}"

        if [ -z "${basicPorts}" ]; then
                echo
                echo
                printf "${YELLOW}Making a script scan on all ports\n"
                printf "${NC}\n"
                nmapProgressBar "${nmapType} -sCV -p${allPorts} -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                assignPorts "${HOST}"
        else
                cmpPorts "${HOST}"
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
                        nmapProgressBar "${nmapType} -sCV -p${extraPorts} -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        assignPorts "${HOST}"
                fi
        fi

        echo
        echo
        echo
}

vulnsScan() {
        printf "${GREEN}---------------------Starting Nmap Vulns Scan---------------------\n"
        printf "${NC}\n"

        if [ -z "${allPorts}" ]; then
                portType="basic"
                ports="${basicPorts}"
        else
                portType="all"
                ports="${allPorts}"
        fi

        if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                printf "${RED}Please install 'vulners.nse' nmap script:\n"
                printf "${RED}https://github.com/vulnersCom/nmap-vulners\n"
                printf "${RED}\n"
                printf "${RED}Skipping CVE scan!\n"
                printf "${NC}\n"
        else
                printf "${YELLOW}Running CVE scan on ${portType} ports\n"
                printf "${NC}\n"
                nmapProgressBar "${nmapType} -sV --script vulners --script-args mincvss=7.0 -p${ports} -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                echo
        fi

        echo
        printf "${YELLOW}Running Vuln scan on ${portType} ports\n"
        printf "${YELLOW}This may take a while, depending on the number of detected services..\n"
        printf "${NC}\n"
        nmapProgressBar "${nmapType} -sV --script vuln -p${ports} -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        echo
        echo
        echo
}

recon() {

        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

        for tool in ${allRecon}; do
                if ! type "${tool}" 2>/dev/null | grep -q bin; then
                        missingTools="${missingTools} ${tool}"
                fi
        done

        if [ -n "${missingTools}" ]; then
                printf "${RED}Missing tools:${NC}${missingTools}\n"
                printf "\n${RED}You can install with:\n"
                printf "${YELLOW}sudo apt install${missingTools} -y\n"
                printf "${NC}\n\n"

                availableRecon="$(echo "${allRecon}" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g')"
        fi

        secs=30
        count=0

        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        printf "${YELLOW}\n"
                        printf "Which commands would you like to run?${NC}\nAll (Default), ${availableRecon}Skip <!>\n\n"
                        while [ ${count} -lt ${secs} ]; do
                                tlimit=$((secs - count))
                                printf "\rRunning Default in (${tlimit}) s: \c\n"

                                # Waits 1 second for user's input - POSIX read -t
                                reconCommand="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1))
                                [ -n "${reconCommand}" ] && break
                        done
                        if [ "${reconCommand}" = "All" ] || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"
                                reconCommand="!"
                        elif expr " ${availableRecon}," : ".* ${reconCommand}," > /dev/null; then
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

}

reconRecommend() {
        printf "${GREEN}---------------------Recon Recommendations----------------------\n"
        printf "${NC}\n"

        oldIFS="${IFS}"
        IFS="
"

        if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
                ports="${allPorts}"
                file="$(cat "nmap/Basic_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | sort | uniq)"
        else
                ports="${basicPorts}"
                file="$(grep "open" "nmap/Basic_${HOST}.nmap")"

        fi

        if echo "${file}" | grep -i -q http; then
                printf "${NC}\n"
                printf "${YELLOW}Web Servers Recon:\n"
                printf "${NC}\n"
        fi

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
                        if type ffuf | grep -q bin; then
                                extensions="$(echo 'index' >./index && ffuf -s -w ./index:FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '${extensions}' -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                        else
                                extensions="$(echo 'index' >./index && gobuster dir -w ./index -t 30 -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -u "${urlType}${HOST}:${port}" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -elkx '${extensions}' -u \"${urlType}${HOST}:${port}\" -o \"recon/gobuster_${HOST}_${port}.txt\""
                        fi
                        echo
                fi
        done

        if [ -f "nmap/Basic_${HOST}.nmap" ]; then
                cms="$(grep http-generator "nmap/Basic_${HOST}.nmap" | cut -d " " -f 2)"
                if [ -n "${cms}" ]; then
                        for line in ${cms}; do
                                port="$(sed -n 'H;x;s/\/.*'"${line}"'.*//p' "nmap/Basic_${HOST}.nmap")"

                                # case returns 0 by default (no match), so ! case returns 1
                                if ! case "${cms}" in Joomla|WordPress|Drupal) false;; esac; then
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

        if echo "${file}" | grep -q "25/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}SMTP Recon:\n"
                printf "${NC}\n"
                echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""
                echo
        fi

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

        if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
                printf "${NC}\n"
                printf "${YELLOW}SNMP Recon:\n"
                printf "${NC}\n"
                echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
                echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "53/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}DNS Recon:\n"
                printf "${NC}\n"
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""
                echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"recon/dnsrecon_${HOST}.txt\""
                echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"recon/dnsrecon-local_${HOST}.txt\""
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"recon/dig_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "389/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}ldap Recon:\n"
                printf "${NC}\n"
                echo "ldapsearch -x -h \"${HOST}\" -s base | tee \"recon/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -h \"${HOST}\" -b \"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"recon/ldapsearch_DC_${HOST}.txt\""
                echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d \\" \\" -f2)\"' \"${HOST}\" -oN \"recon/nmap_ldap_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "1521/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}Oracle Recon:\n"
                printf "${NC}\n"
                echo "odat sidguesser -s \"${HOST}\" -p 1521"
                echo "odat passwordguesser -s \"${HOST}\" -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
                echo
        fi

        IFS="${oldIFS}"

        echo
        echo
        echo
}

runRecon() {
        echo
        echo
        echo
        printf "${GREEN}---------------------Running Recon Commands----------------------\n"
        printf "${NC}\n"

        oldIFS="${IFS}"
        IFS="
"

        mkdir -p recon/

        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
        fi

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

        IFS="${oldIFS}"

        echo
        echo
        echo
}

footer() {

        printf "${GREEN}---------------------Finished all Nmap scans---------------------\n"
        printf "${NC}\n"
        echo

        if [ ${SECONDS} -gt 3600 ]; then
                hours=$((SECONDS / 3600))
                minutes=$(((SECONDS % 3600) / 60))
                seconds=$(((SECONDS % 3600) % 60))
                printf "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
        elif [ ${SECONDS} -gt 60 ]; then
                minutes=$(((SECONDS % 3600) / 60))
                seconds=$(((SECONDS % 3600) % 60))
                printf "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
        else
                printf "${YELLOW}Completed in ${SECONDS} seconds\n"
        fi
        echo
}

main() {
        assignPorts "${HOST}"

        header "${HOST}" "${TYPE}"

        case "${TYPE}" in
        Quick | quick) quickScan "${HOST}" ;;
        Basic | basic)
                [ ! -f "nmap/Quick_${HOST}.nmap" ] && quickScan "${HOST}"
                basicScan "${HOST}"
                ;;
        UDP | udp) UDPScan "${HOST}" ;;
        Full | full) fullScan "${HOST}" ;;
        Vulns | vulns)
                [ ! -f "nmap/Quick_${HOST}.nmap" ] && quickScan "${HOST}"
                vulnsScan "${HOST}"
                ;;
        Recon | recon)
                [ ! -f "nmap/Quick_${HOST}.nmap" ] && quickScan "${HOST}"
                [ ! -f "nmap/Basic_${HOST}.nmap" ] && basicScan "${HOST}"
                recon "${HOST}"
                ;;
        All | all)
                quickScan "${HOST}"
                basicScan "${HOST}"
                UDPScan "${HOST}"
                fullScan "${HOST}"
                vulnsScan "${HOST}"
                recon "${HOST}"
                ;;
        esac

        footer
}

if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then
        usage
fi

if ! expr "${HOST}" : '^\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\|\([[:alnum:]-]\{1,63\}\.\)\+[[:alpha:]]\{2,6\}\)$' > /dev/null; then
        printf "${RED}\n"
        printf "${RED}Invalid IP or URL!\n"
        printf "${RED}\n"
        usage
fi

# case returns 0 by default (no match), so ! case returns 1; ! false -> true
if ! case "${TYPE}" in [Qq]uick|[Bb]asic|UDP|udp|[Ff]ull|[Vv]ulns|[Rr]econ|[Aa]ll) false;; esac; then
        mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
        main | tee "nmapAutomator_${HOST}_${TYPE}.txt"
else
        printf "${RED}\n"
        printf "${RED}Invalid Type!\n"
        printf "${RED}\n"
        usage
fi
