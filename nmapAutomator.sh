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
                POSITIONAL+=("$1")
                shift
                ;;
        esac
done
set -- "${POSITIONAL[@]}"

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
        echo -e "${RED}Usage: $0 -H/--host <TARGET-IP> -t/--type <TYPE> [-d/--dns <DNS SERVER> -o/--output <OUTPUT DIRECTORY>]"
        echo -e "${YELLOW}"
        echo -e "Scan Types:"
        echo -e "\tQuick: Shows all open ports quickly (~15 seconds)"
        echo -e "\tBasic: Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)"
        echo -e "\tUDP  : Runs \"Basic\" on UDP ports \"requires sudo\" (~5 minutes)"
        echo -e "\tFull : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)"
        echo -e "\tVulns: Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)"
        echo -e "\tRecon: Suggests recon commands, then prompts to automatically run them"
        echo -e "\tAll  : Runs all the scans (~20-30 minutes)"
        echo -e "${NC}"
        exit 1
}

header() {
        echo

        if [ "${TYPE}" = "All" ]; then
                echo -e "${YELLOW}Running all scans on ${HOST}"
        else
                echo -e "${YELLOW}Running a ${TYPE} scan on ${HOST}"
        fi

        subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"

        checkPing="$(checkPing "${HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        if [ "${nmapType}" != "nmap" ]; then
                echo -e "${NC}"
                echo -e "${YELLOW}No ping detected.. Running with -Pn option!"
                echo -e "${NC}"
        fi

        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                echo -e "${NC}"
                echo -e "${GREEN}Host is likely running ${osType}"
                echo -e "${NC}"
        fi

        echo
        echo
}

assignPorts() {
        if [ -f "nmap/Quick_${HOST}.nmap" ]; then
                basicPorts="$(grep open "nmap/Quick_${HOST}.nmap" | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)"
        fi

        if [ -f "nmap/Full_${HOST}.nmap" ]; then
                if [ -f "nmap/Quick_${HOST}.nmap" ]; then
                        allPorts="$(cat "nmap/Quick_${HOST}.nmap" "nmap/Full_${HOST}.nmap" | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1)"
                else
                        allPorts="$(grep open "nmap/Full_${HOST}.nmap" | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1)"
                fi
        fi

        if [ -f "nmap/UDP_${HOST}.nmap" ]; then
                udpPorts="$(grep "open " "nmap/UDP_${HOST}.nmap" | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)"
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
                if [[ "${HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
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
        oldIFS="${IFS}"
        IFS=','
        touch "nmap/cmpPorts_${HOST}.txt"

        for i in ${allPorts}; do
                if ! [[ "${i}" =~ ^("$(echo "${basicPorts}" | sed 's/,/\|/g')")$ ]]; then
                        echo -n "${i}," >> "nmap/cmpPorts_${HOST}.txt"
                fi
        done

        extraPorts="$(tr "\n" "," < "nmap/cmpPorts_${HOST}.txt" | head -c-1)"
        rm "nmap/cmpPorts_${HOST}.txt"
        IFS="${oldIFS}"
}

progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#")"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        echo -e "In progress: $1 Scan ($3 elapsed - $4 remaining)   "
        echo -e "[${fill// /\#}>${empty// / }] $2% done   "
        echo -ne "\e[2A"
}

nmapProgressBar() {
        refreshRate="${2:-0.5}"
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
        echo -e "\033[0K\r\n\033[0K\r"
        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/Nmap done at.*/p' "${outputFile}" | head -n-2
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

quickScan() {
        echo -e "${GREEN}---------------------Starting Nmap Quick Scan---------------------"
        echo -e "${NC}"

        nmapProgressBar "${nmapType} -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Quick_${HOST}.nmap ${HOST} ${DNSSTRING}"
        assignPorts "${HOST}"

        echo
        echo
        echo
}

basicScan() {
        echo -e "${GREEN}---------------------Starting Nmap Basic Scan---------------------"
        echo -e "${NC}"

        if [ -z "${basicPorts}" ]; then
                echo -e "${YELLOW}No ports in quick scan.. Skipping!"
        else
                nmapProgressBar "${nmapType} -sCV -p${basicPorts} -oN nmap/Basic_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
        fi

        if [ -f "nmap/Basic_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Basic_${HOST}.nmap"; then
                serviceOS="$(grep "Service Info: OS:" "nmap/Basic_${HOST}.nmap" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1)"
                if [ "${osType}" != "${serviceOS}" ]; then
                        osType="${serviceOS}"
                        echo -e "${NC}"
                        echo -e "${NC}"
                        echo -e "${GREEN}OS Detection modified to: ${osType}"
                        echo -e "${NC}"
                fi
        fi

        echo
        echo
        echo
}

UDPScan() {
        echo -e "${GREEN}----------------------Starting Nmap UDP Scan----------------------"
        echo -e "${NC}"

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
                echo -e "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')"
                echo -e "${NC}"
                if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                        nmapProgressBar "${nmapType} -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                else
                        nmapProgressBar "${nmapType} -sCVU -p${udpPorts} -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi
        else
                echo
                echo
                echo -e "${YELLOW}No UDP ports are open"
                echo -e "${NC}"
        fi

        echo
        echo
        echo
}

fullScan() {
        echo -e "${GREEN}---------------------Starting Nmap Full Scan----------------------"
        echo -e "${NC}"

        nmapProgressBar "${nmapType} -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Full_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        assignPorts "${HOST}"

        if [ -z "${basicPorts}" ]; then
                echo
                echo
                echo -e "${YELLOW}Making a script scan on all ports"
                echo -e "${NC}"
                nmapProgressBar "${nmapType} -sCV -p${allPorts} -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                assignPorts "${HOST}"
        else
                cmpPorts "${HOST}"
                if [ -z "${extraPorts}" ]; then
                        echo
                        echo
                        allPorts=""
                        echo -e "${YELLOW}No new ports"
                        echo -e "${NC}"
                else
                        echo
                        echo
                        echo -e "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')"
                        echo -e "${NC}"
                        nmapProgressBar "${nmapType} -sCV -p${extraPorts} -oN nmap/Full_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                        assignPorts "${HOST}"
                fi
        fi

        echo
        echo
        echo
}

vulnsScan() {
        echo -e "${GREEN}---------------------Starting Nmap Vulns Scan---------------------"
        echo -e "${NC}"

        if [ -z "${allPorts}" ]; then
                portType="basic"
                ports="${basicPorts}"
        else
                portType="all"
                ports="${allPorts}"
        fi

        if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                echo -e "${RED}Please install 'vulners.nse' nmap script:"
                echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
                echo -e "${RED}"
                echo -e "${RED}Skipping CVE scan!"
                echo -e "${NC}"
        else
                echo -e "${YELLOW}Running CVE scan on ${portType} ports"
                echo -e "${NC}"
                nmapProgressBar "${nmapType} -sV --script vulners --script-args mincvss=7.0 -p${ports} -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                echo
        fi

        echo
        echo -e "${YELLOW}Running Vuln scan on ${portType} ports"
        echo -e "${YELLOW}This may take a while, depending on the number of detected services.."
        echo -e "${NC}"
        nmapProgressBar "${nmapType} -sV --script vuln -p${ports} -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        echo
        echo
        echo
}

recon() {

        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort -u)"

        for tool in ${allRecon}; do
                if ! type "${tool}" 2>/dev/null | grep -q bin; then
                        missingTools="${missingTools} ${tool}"
                fi
        done

        if [ -n "${missingTools}" ]; then
                echo -e "${RED}Missing tools:${NC}${missingTools}"
                echo -e "\n${RED}You can install with:"
                echo -e "${YELLOW}sudo apt install${missingTools} -y"
                echo -e "${NC}\n"

                availableRecon="$(echo "${allRecon}" | tr " " "\n" | grep -vE $(echo "${missingTools}" | tr " " "|") | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)"
        else
                availableRecon="$(echo "${allRecon}" | sed 's/\ /,\ /g')"
        fi

        secs=30
        count=0

        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        echo -e "${YELLOW}"
                        echo -e "Which commands would you like to run?${NC}\nAll (Default), ${availableRecon}, Skip <!>\n"
                        while [ ${count} -lt ${secs} ]; do
                                tlimit=$((secs - count))
                                echo -e "\rRunning Default in (${tlimit}) s: \c"
                                read -t 1 reconCommand
                                count=$((count + 1))
                                [ -n "${reconCommand}" ] && break
                        done
                        if [ "${reconCommand}" = "All" ] || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"
                                reconCommand="!"
                        elif [[ "${reconCommand}" =~ ^("$(echo "${availableRecon}" | tr ", " "|")")$ ]]; then
                                runRecon "${HOST}" "${reconCommand}"
                                reconCommand="!"
                        elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                                reconCommand="!"
                                echo
                                echo
                                echo
                        else
                                echo -e "${NC}"
                                echo -e "${RED}Incorrect choice!"
                                echo -e "${NC}"
                        fi
                done
        else
                echo -e "${YELLOW}No Recon Recommendations found..."
                echo -e "${NC}\n\n"
        fi

}

reconRecommend() {
        echo -e "${GREEN}---------------------Recon Recommendations----------------------"
        echo -e "${NC}"

        oldIFS="${IFS}"
        IFS=$'\n'

        if [ -f "nmap/Full_Extra_${HOST}.nmap" ]; then
                ports="${allPorts}"
                file="$(cat "nmap/Basic_${HOST}.nmap" "nmap/Full_Extra_${HOST}.nmap" | grep "open" | sort -u)"
        else
                ports="${basicPorts}"
                file="$(grep "open" "nmap/Basic_${HOST}.nmap")"

        fi

        if echo "${file}" | grep -i -q http; then
                echo -e "${NC}"
                echo -e "${YELLOW}Web Servers Recon:"
                echo -e "${NC}"
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
                                extensions="$(echo 'index' >./index && ffuf -s -w ./index:FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -F 'index' '{print $2}' | tr '\n' ',' | head -c-1 && rm ./index)"
                                echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '${extensions}' -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                        else
                                extensions="$(echo 'index' >./index && gobuster dir -w ./index -t 30 -qnkx '.asp,.aspx,.html,.jsp,.php' -s '200,302' -u "${urlType}${HOST}:${port}" 2>/dev/null | awk -F 'index' '{print $2}' | tr '\n' ',' | head -c-1 && rm ./index)"
                                echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 -elkx '${extensions}' -u \"${urlType}${HOST}:${port}\" -o \"recon/gobuster_${HOST}_${port}.txt\""
                        fi
                        echo
                fi
        done

        if [ -f "nmap/Basic_${HOST}.nmap" ]; then
                cms="$(grep http-generator "nmap/Basic_${HOST}.nmap" | cut -d " " -f 2)"
                if [ -n "${cms}" ]; then
                        for line in ${cms}; do
                                port="$(grep "${line}" -B1 "nmap/Basic_${HOST}.nmap" | grep "open" | cut -d "/" -f 1)"
                                if [[ "${cms}" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
                                        echo -e "${NC}"
                                        echo -e "${YELLOW}CMS Recon:"
                                        echo -e "${NC}"
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
                echo -e "${NC}"
                echo -e "${YELLOW}SMTP Recon:"
                echo -e "${NC}"
                echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "445/tcp"; then
                echo -e "${NC}"
                echo -e "${YELLOW}SMB Recon:"
                echo -e "${NC}"
                echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
                if [ "${osType}" = "Windows" ]; then
                        echo "nmap -Pn -p445 --script vuln -oN \"recon/SMB_vulns_${HOST}.txt\" \"${HOST}\""
                elif [ "${osType}" = "Linux" ]; then
                        echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
                fi
                echo
        elif echo "${file}" | grep -q "139/tcp" && [ "${osType}" = "Linux" ]; then
                echo -e "${NC}"
                echo -e "${YELLOW}SMB Recon:"
                echo -e "${NC}"
                echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
                echo
        fi

        if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
                echo -e "${NC}"
                echo -e "${YELLOW}SNMP Recon:"
                echo -e "${NC}"
                echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
                echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "53/tcp"; then
                echo -e "${NC}"
                echo -e "${YELLOW}DNS Recon:"
                echo -e "${NC}"
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""
                echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"recon/dnsrecon_${HOST}.txt\""
                echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"recon/dnsrecon-local_${HOST}.txt\""
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"recon/dig_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "389/tcp"; then
                echo -e "${NC}"
                echo -e "${YELLOW}ldap Recon:"
                echo -e "${NC}"
                echo "ldapsearch -x -h \"${HOST}\" -s base | tee \"recon/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -h \"${HOST}\" -b \"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"recon/ldapsearch_DC_${HOST}.txt\""
                echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d \\" \\" -f2)\"' \"${HOST}\" -oN \"recon/nmap_ldap_${HOST}.txt\""
                echo
        fi

        if echo "${file}" | grep -q "1521/tcp"; then
                echo -e "${NC}"
                echo -e "${YELLOW}Oracle Recon:"
                echo -e "${NC}"
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
        echo -e "${GREEN}---------------------Running Recon Commands----------------------"
        echo -e "${NC}"

        oldIFS="${IFS}"
        IFS=$'\n'

        mkdir -p recon/

        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
        fi

        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d " " -f 1 | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)"
                fileName="$(echo "${line}" | awk -F "recon/" '{print $2}' | head -c-1)"
                if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
                        echo -e "${NC}"
                        echo -e "${YELLOW}Starting ${currentScan} scan"
                        echo -e "${NC}"
                        eval "${line}"
                        echo -e "${NC}"
                        echo -e "${YELLOW}Finished ${currentScan} scan"
                        echo -e "${NC}"
                        echo -e "${YELLOW}========================="
                fi
        done

        IFS="${oldIFS}"

        echo
        echo
        echo
}

footer() {

        echo -e "${GREEN}---------------------Finished all Nmap scans---------------------"
        echo -e "${NC}"
        echo

        if [ ${SECONDS} -gt 3600 ]; then
                let "hours=SECONDS/3600"
                let "minutes=(SECONDS%3600)/60"
                let "seconds=(SECONDS%3600)%60"
                echo -e "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)"
        elif [ ${SECONDS} -gt 60 ]; then
                let "minutes=(SECONDS%3600)/60"
                let "seconds=(SECONDS%3600)%60"
                echo -e "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)"
        else
                echo -e "${YELLOW}Completed in ${SECONDS} seconds"
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

if ! [[ "${HOST}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "${HOST}" =~ ^([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6}$ ]]; then
        echo -e "${RED}"
        echo -e "${RED}Invalid IP or URL!"
        echo -e "${RED}"
        usage
fi

if [[ "${TYPE}" =~ ^(Quick|Basic|UDP|Full|Vulns|Recon|All|quick|basic|udp|full|vulns|recon|all)$ ]]; then
        mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
        main | tee "nmapAutomator_${HOST}_${TYPE}.txt"
else
        echo -e "${RED}"
        echo -e "${RED}Invalid Type!"
        echo -e "${RED}"
        usage
fi
