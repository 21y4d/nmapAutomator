#!/bin/bash
#by 21y4d

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

SECONDS=0

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -H|--host)
    HOST="$2"
    shift
    shift
    ;;
    -t|--type)
    TYPE="$2"
    shift
    shift
    ;;
    -d|--dns)
    DNS="$2"
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

#--compatible with old syntax--
if [ -z "$HOST" ]
then
        HOST="$1"
fi

if [ -z "$TYPE" ]
then
        TYPE="$2"
fi
#--compatible with old syntax--

#--default use 1.1.1.1 DNS--
if [[ ! -z "$DNS" ]]
then
        DNSSTRING="--dns-server="$DNS
        DNSSERVER=$DNS
else
        DNSSTRING="--dns-server=1.1.1.1"
        DNSSERVER="1.1.1.1"
fi
#--default use 1.1.1.1 DNS--

usage(){
echo -e ""
echo -e "${RED}Usage: $0 --host <TARGET-IP> --type <TYPE> [--dns <DNS SERVER>]"
echo -e "${YELLOW}"
echo -e "Scan Types:"
echo -e "\tQuick:       Shows all open ports quickly (~15 seconds)"
echo -e "\tBasic:       Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)"
echo -e "\tUDP: Runs \"Basic\" on UDP ports \"requires sudo\" (~5 minutes)"
echo -e "\tFull:        Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)"
echo -e "\tVulns:       Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)"
echo -e "\tRecon:       Suggests recon commands, then prompts to automatically run them"
echo -e "\tAll: Runs all the scans (~20-30 minutes)"
echo -e "${NC}"
exit 1
}

header(){
echo -e ""

if [ ${TYPE}  == "All" ]; then
        echo -e "${YELLOW}Running all scans on ${HOST}"
else
        echo -e "${YELLOW}Running a ${TYPE} scan on ${HOST}"
fi

subnet=$(echo ${HOST} | cut -d "." -f 1,2,3)".0"

checkPing=$(checkPing ${HOST})
nmapType="nmap -Pn"

: '
#nmapType=`echo "${checkPing}" | head -n 1`

if [ "$nmapType" != "nmap" ]; then 
        echo -e "${NC}"
        echo -e "${YELLOW}No ping detected.. Running with -Pn option!"
        echo -e "${NC}"
fi
'

ttl=$(echo "${checkPing}" | tail -n 1)
if [[  $(echo "${ttl}") != "nmap -Pn" ]]; then
        osType="$(checkOS "$ttl")"
        echo -e "${NC}"
        echo -e "${GREEN}Host is likely running $osType"
        echo -e "${NC}"
fi

echo -e ""
echo -e ""
}

assignPorts(){
if [ -f nmap/Quick_${HOST}.nmap ]; then
        basicPorts=$(cat nmap/Quick_${HOST}.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
fi

if [ -f nmap/Full_${HOST}.nmap ]; then
        if [ -f nmap/Quick_${HOST}.nmap ]; then
                allPorts=$(cat nmap/Quick_"${HOST}".nmap nmap/Full_"${HOST}".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1)
        else
                allPorts=$(cat nmap/Full_"${HOST}".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1)
        fi
fi

if [ -f nmap/UDP_"${HOST}".nmap ]; then
        udpPorts=$(cat nmap/UDP_"${HOST}".nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
        if [[ "$udpPorts" == "Al" ]]; then
                udpPorts=""
        fi
fi
}

checkPing(){
pingTest=$(ping -c 1 -W 3 "${HOST}" | grep ttl)
if [[ -z $pingTest ]]; then
        echo "nmap -Pn"
else
        echo "nmap"
        ttl=$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)
        echo "${ttl}"
fi
}

checkOS(){
if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
        echo "OpenBSD/Cisco/Oracle"
elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
        echo "Windows"
elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
        echo "Linux"
else
        echo "Unknown OS!"
fi
}

cmpPorts(){
oldIFS=$IFS
IFS=','
touch nmap/cmpPorts_"${HOST}".txt

for i in $(echo "${allPorts}")
do
        if [[ "$i" =~ ^($(echo "${basicPorts}" | sed 's/,/\|/g'))$ ]]; then
               :
        else
                echo -n "$i," >> nmap/cmpPorts_"${HOST}".txt
        fi
done

extraPorts=$(cat nmap/cmpPorts_"${HOST}".txt | tr "\n" "," | head -c-1)
rm nmap/cmpPorts_"${HOST}".txt
IFS=$oldIFS
}

quickScan(){
echo -e "${GREEN}---------------------Starting Nmap Quick Scan---------------------"
echo -e "${NC}"

$nmapType -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Quick_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
assignPorts "${HOST}"

echo -e ""
echo -e ""
echo -e ""
}

basicScan(){
echo -e "${GREEN}---------------------Starting Nmap Basic Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${basicPorts}") ]; then
        echo -e "${YELLOW}No ports in quick scan.. Skipping!"
else
        $nmapType -sCV -p$(echo "${basicPorts}") -oN nmap/Basic_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
fi

if [ -f nmap/Basic_"${HOST}".nmap ] && [[ ! -z $(cat nmap/Basic_"${HOST}".nmap | grep -w "Service Info: OS:") ]]; then
        serviceOS=$(cat nmap/Basic_"${HOST}".nmap | grep -w "Service Info: OS:" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1)
        if [[ "$osType" != "$serviceOS"  ]]; then
                osType=$(echo "${serviceOS}")
                echo -e "${NC}"
                echo -e "${NC}"
                echo -e "${GREEN}OS Detection modified to: $osType"
                echo -e "${NC}"
        fi
fi

echo -e ""
echo -e ""
echo -e ""
}

UDPScan(){
echo -e "${GREEN}----------------------Starting Nmap UDP Scan----------------------"
echo -e "${NC}"

$nmapType -sU --max-retries 1 --open -oN nmap/UDP_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
assignPorts "${HOST}"

if [ ! -z $(echo "${udpPorts}") ]; then
        echo ""
        echo ""
        echo -e "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')"
        echo -e "${NC}"
        if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                $nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
        else
                $nmapType -sCVU -p$(echo "${udpPorts}") -oN nmap/UDP_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
        fi
fi

echo -e ""
echo -e ""
echo -e ""
}

fullScan(){
echo -e "${GREEN}---------------------Starting Nmap Full Scan----------------------"
echo -e "${NC}"

$nmapType -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Full_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
assignPorts "${HOST}"

if [ -z $(echo "${basicPorts}") ]; then
        echo ""
        echo ""
        echo -e "${YELLOW}Making a script scan on all ports"
        echo -e "${NC}"
        $nmapType -sCV -p$(echo "${allPorts}") -oN nmap/Full_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
        assignPorts "${HOST}"
else
        cmpPorts "${HOST}"
        if [ -z $(echo "${extraPorts}") ]; then
                echo ""
                echo ""
                allPorts=""
                echo -e "${YELLOW}No new ports"
                rm nmap/Full_"${HOST}".nmap
                echo -e "${NC}"
        else
                echo ""
                echo ""
                echo -e "${YELLOW}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')"
                echo -e "${NC}"
                $nmapType -sCV -p$(echo "${extraPorts}") -oN nmap/Full_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
                assignPorts "${HOST}"
        fi
fi

echo -e ""
echo -e ""
echo -e ""
}

vulnsScan(){
echo -e "${GREEN}---------------------Starting Nmap Vulns Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${allPorts}") ]; then
        portType="basic"
        ports=$(echo "${basicPorts}")
else
        portType="all"
        ports=$(echo "${allPorts}")
fi


if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
        echo -e "${RED}Please install 'vulners.nse' nmap script:"
        echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
        echo -e "${RED}"
        echo -e "${RED}Skipping CVE scan!"
        echo -e "${NC}"
else    
        echo -e "${YELLOW}Running CVE scan on $portType ports"
        echo -e "${NC}"
        $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
        echo ""
fi

echo ""
echo -e "${YELLOW}Running Vuln scan on $portType ports"
echo -e "${NC}"
$nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"${HOST}".nmap "${HOST}" "${DNSSTRING}"
echo -e ""
echo -e ""
echo -e ""
}

recon(){

reconRecommend "${HOST}" | tee nmap/Recon_"${HOST}".nmap

availableRecon=$(cat nmap/Recon_"${HOST}".nmap | grep "${HOST}" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)

secs=30
count=0

reconCommand=""

if [ ! -z "$availableRecon"  ]; then
        while [ ! $(echo "${reconCommand}") == "!" ]; do
                echo -e "${YELLOW}"
                echo -e "Which commands would you like to run?${NC}\nAll (Default), $availableRecon, Skip <!>\n"
                while [[ ${count} -lt ${secs} ]]; do
                        tlimit=$(( $secs - $count ))
                        echo -e "\rRunning Default in (${tlimit}) s: \c"
                        read -t 1 reconCommand
                        [ ! -z "$reconCommand" ] && { break ;  }
                        count=$((count+1))
                done
                if [ "$reconCommand" == "All" ] || [ -z $(echo "${reconCommand}") ]; then
                        runRecon "${HOST}" "All"
                        reconCommand="!"
                elif [[ "$reconCommand" =~ ^($(echo "${availableRecon}" | tr ", " "|"))$ ]]; then
                        runRecon "${HOST}" $reconCommand
                        reconCommand="!"
                elif [ "$reconCommand" == "Skip" ] || [ "$reconCommand" == "!" ]; then
                        reconCommand="!"
                        echo -e ""
                        echo -e ""
                        echo -e ""
                else
                        echo -e "${NC}"
                        echo -e "${RED}Incorrect choice!"
                        echo -e "${NC}"
                fi
        done
fi

}

reconRecommend(){
echo -e "${GREEN}---------------------Recon Recommendations----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [ -f nmap/Full_"${HOST}".nmap ] && [ -f nmap/Basic_"${HOST}".nmap ]; then
        ports=$(echo "${allPorts}")
        file=$(cat nmap/Basic_"${HOST}".nmap nmap/Full_"${HOST}".nmap | grep -w "open")
elif [ -f nmap/Full_"${HOST}".nmap ]; then
        ports=$(echo "${allPorts}")
        file=$(cat nmap/Quick_"${HOST}".nmap nmap/Full_"${HOST}".nmap | grep -w "open")
elif [ -f nmap/Basic_"${HOST}".nmap ]; then
        ports=$(echo "${basicPorts}")
        file=$(cat nmap/Basic_"${HOST}".nmap | grep -w "open")
else
        ports=$(echo "${basicPorts}")
        file=$(cat nmap/Quick_"${HOST}".nmap | grep -w "open")

fi

if [[ ! -z $(echo "${file}" | grep -i http) ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}Web Servers Recon:"
        echo -e "${NC}"
fi

for line in $file; do
        if [[ ! -z $(echo "${line}" | grep -i http) ]]; then
                port=$(echo "${line}" | cut -d "/" -f 1)
                if [[ ! -z $(echo "${line}" | grep -w "IIS") ]]; then
                        pages=".html,.asp,.aspx,.php"
                else
                        pages=".html,.php"
                fi
                if [[ ! -z $(echo "${line}" | grep ssl/http) ]]; then
                        #echo "sslyze --regular ${HOST} | tee recon/sslyze_${HOST}_$port.txt"
                        echo "sslscan ${HOST} | tee recon/sslscan_${HOST}_$port.txt"
                        echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u https://${HOST}:$port -o recon/gobuster_${HOST}_$port.txt"
                        echo "nikto -host https://${HOST}:$port -ssl | tee recon/nikto_${HOST}_$port.txt"
                else
                        echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u http://${HOST}:$port -o recon/gobuster_${HOST}_$port.txt"
                        echo "nikto -host ${HOST}:$port | tee recon/nikto_${HOST}_$port.txt"
                fi
                echo ""
        fi
done

if [ -f nmap/Basic_"${HOST}".nmap ]; then
        cms=$(cat nmap/Basic_"${HOST}".nmap | grep http-generator | cut -d " " -f 2)
        if [ ! -z $(echo "${cms}") ]; then
                for line in $cms; do
                        port=$(cat nmap/Basic_"${HOST}".nmap | grep "$line" -B1 | grep -w "open" | cut -d "/" -f 1)
                        if [[ "$cms" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
                                echo -e "${NC}"
                                echo -e "${YELLOW}CMS Recon:"
                                echo -e "${NC}"
                        fi
                        case "$cms" in
                                Joomla!) echo "joomscan --url ${HOST}:$port | tee recon/joomscan_${HOST}_$port.txt";;
                                WordPress) echo "wpscan --url ${HOST}:$port --enumerate p | tee recon/wpscan_${HOST}_$port.txt";;
                                Drupal) echo "droopescan scan drupal -u ${HOST}:$port | tee recon/droopescan_${HOST}_$port.txt";;
                        esac
                done
        fi
fi

if [[ ! -z $(echo "${file}" | grep -w "445/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}SMB Recon:"
        echo -e "${NC}"
        echo "smbmap -H ${HOST} | tee recon/smbmap_${HOST}.txt"
        echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee recon/smbclient_${HOST}.txt"
        if [[ $osType == "Windows" ]]; then
                echo "nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_${HOST}.txt ${HOST}"
        fi
        if [[ $osType == "Linux" ]]; then
                echo "enum4linux -a ${HOST} | tee recon/enum4linux_${HOST}.txt"
        fi
        echo ""
elif [[ ! -z $(echo "${file}" | grep -w "139/tcp") ]] && [[ $osType == "Linux" ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}SMB Recon:"
        echo -e "${NC}"
        echo "enum4linux -a ${HOST} | tee recon/enum4linux_${HOST}.txt"
        echo ""
fi


if [ -f nmap/UDP_"${HOST}".nmap ] && [[ ! -z $(cat nmap/UDP_"${HOST}".nmap | grep open | grep -w "161/udp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}SNMP Recon:"
        echo -e "${NC}"
        echo "snmp-check ${HOST} -c public | tee recon/snmpcheck_${HOST}.txt"
        echo "snmpwalk -Os -c public -v1 ${HOST} | tee recon/snmpwalk_${HOST}.txt"
        echo ""
fi



if [[ ! -z $(echo "${file}" | grep -w "53/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}DNS Recon:"
        echo -e "${NC}"
        echo "host -l ${HOST} ${DNSSERVER} | tee recon/hostname_${HOST}.txt"
        echo "dnsrecon -r $subnet/24 -n ${DNSSERVER} | tee recon/dnsrecon_${HOST}.txt"
        echo "dnsrecon -r 127.0.0.0/24 -n ${DNSSERVER} | tee recon/dnsrecon-local_${HOST}.txt"
        echo "dig -x ${HOST} @${DNSSERVER} | tee recon/dig_${HOST}.txt"
        echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "389/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}ldap Recon:"
        echo -e "${NC}"
        echo "ldapsearch -x -h ${HOST} -s base | tee recon/ldapsearch_${HOST}.txt"
        echo "ldapsearch -x -h ${HOST} -b \$(cat recon/ldapsearch_${HOST}.txt | grep rootDomainNamingContext | cut -d ' ' -f2) | tee recon/ldapsearch_DC_${HOST}.txt"
        echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(cat recon/ldapsearch_${HOST}.txt | grep rootDomainNamingContext | cut -d \\" \\" -f2)\"' ${HOST} -oN recon/nmap_ldap_${HOST}.txt"
        echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "1521/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}Oracle Recon \"Exc. from Default\":"
        echo -e "${NC}"
        echo "cd /opt/odat/;#${HOST};"
        echo "./odat.py sidguesser -s ${HOST} -p 1521"
        echo "./odat.py passwordguesser -s ${HOST} -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
        echo "cd -;#${HOST};"
        echo ""
fi

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

runRecon(){
echo -e ""
echo -e ""
echo -e ""
echo -e "${GREEN}---------------------Running Recon Commands----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [[ ! -d recon/ ]]; then
        mkdir recon/
fi

if [ "$2" == "All" ]; then
        reconCommands=$(cat nmap/Recon_"${HOST}".nmap | grep "${HOST}" | grep -v odat)
else
        reconCommands=$(cat nmap/Recon_"${HOST}".nmap | grep "${HOST}" | grep "$2")
fi

for line in $(echo "${reconCommands}"); do
        currentScan=$(echo "$line" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)
        fileName=$(echo "${line}" | awk -F "recon/" '{print $TYPE}' | head -c-1)
        if [ ! -z recon/$(echo "${fileName}") ] && [ ! -f recon/$(echo "${fileName}") ]; then
                echo -e "${NC}"
                echo -e "${YELLOW}Starting $currentScan scan"
                echo -e "${NC}"
                echo "$line" | /bin/bash
                echo -e "${NC}"
                echo -e "${YELLOW}Finished $currentScan scan"
                echo -e "${NC}"
                echo -e "${YELLOW}========================="
        fi
done

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

footer(){

echo -e "${GREEN}---------------------Finished all Nmap scans---------------------"
echo -e "${NC}"
echo -e ""

if (( $SECONDS > 3600 )) ; then
    let "hours=SECONDS/3600"
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${YELLOW}Completed in $hours hour(s), $minutes minute(s) and $seconds second(s)" 
elif (( $SECONDS > 60 )) ; then
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${YELLOW}Completed in $minutes minute(s) and $seconds second(s)"
else
    echo -e "${YELLOW}Completed in $SECONDS seconds"
fi
echo -e ""
}

if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then
        usage
fi

#--ip/url regex check if no dns provided--
if [[ ${HOST} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ ${HOST} =~ ^([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,6}$ ]]; then
        :
else
        echo -e "${RED}"
        echo -e "${RED}Invalid IP or URL!"
        echo -e "${RED}"
        usage
fi
#--ip/url regex check if no dns provided--


if [[ "${TYPE}" =~ ^(Quick|Basic|UDP|Full|Vulns|Recon|All|quick|basic|udp|full|vulns|recon|all)$ ]]; then
        if [[ ! -d ${HOST} ]]; then
                mkdir "${HOST}"
        fi

        cd "${HOST}" || exit

        if [[ ! -d nmap/ ]]; then
                mkdir nmap/
        fi

        assignPorts "${HOST}"

        header "${HOST}" "${TYPE}"

        case "${TYPE}" in
                Quick | quick)  quickScan "${HOST}";;
                Basic | basic)  if [ ! -f nmap/Quick_"${HOST}".nmap ]; then quickScan "${HOST}"; fi
                                basicScan "${HOST}";;
                UDP | udp)      UDPScan "${HOST}";;
                Full | full)    fullScan "${HOST}";;
                Vulns | vulns)  if [ ! -f nmap/Quick_"${HOST}".nmap ]; then quickScan "${HOST}"; fi
                                vulnsScan "${HOST}";;
                Recon | recon)  if [ ! -f nmap/Quick_"${HOST}".nmap ]; then quickScan "${HOST}"; fi
                                if [ ! -f nmap/Basic_"${HOST}".nmap ]; then basicScan "${HOST}"; fi
                                recon "${HOST}";;
                All | all)      quickScan "${HOST}"
                                basicScan "${HOST}"
                                UDPScan "${HOST}"
                                fullScan "${HOST}"
                                vulnsScan "${HOST}"
                                recon "${HOST}";;
        esac

        footer
else
        echo -e "${RED}"
        echo -e "${RED}Invalid Type!"
        echo -e "${RED}"
        usage
fi
