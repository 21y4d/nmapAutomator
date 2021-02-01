# nmapAutomator
A script that you can run in the background!
  
  
# Summary
I have created this script as I was preparing for my OSCP exam.  
The main goal for this script is to automate all of the process of recon/enumeration that is run every time, and instead focus our attention on real pen testing.  
  
This will ensure two things:  
	1) Automate nmap scans. 
	2) Always have some recon running in the background. 

Once you find the inital ports in around 10 seconds, you then can start manually looking into those ports, and let the rest run in the background with no interaction from your side whatsoever.  
  
  
# Features:
1. **Quick:**	Shows all open ports quickly (~15 seconds)  
1. **Basic:**	Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)  
1. **UDP:**	  Runs "Basic" on UDP ports (~5 minutes)  
1. **Full:** 	Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)  
1. **Vulns:**	Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)  
1. **Recon:**	Runs "Basic" scan "if not yet run", then suggests recon commands "i.e. gobuster, nikto, smbmap" based on the found ports, then prompts to automatically run them  
1. **All:**  	Runs all the scans consecutively (~20-30 minutes)  
  
I tried to make the script as efficient as possible, so that you would get the results as fast as possible, without duplicating any work.  

Feel free to send your pull requests and contributions :)
  
  
# Requirements:
**Required:** Gobuster v3.0 or higher, as it is not backward compatible.  
You can update gobuster on kali using:  
```bash
apt-get update
apt-get install gobuster --only-upgrade  
```

Other Recon tools used within the script include:
* [nmap Vulners](https://github.com/vulnersCom/nmap-vulners)
* [sslscan](https://github.com/rbsec/sslscan)
* [nikto](https://github.com/sullo/nikto)
* [joomscan](https://github.com/rezasp/joomscan)
* [wpscan](https://github.com/wpscanteam/wpscan)
* [droopescan](https://github.com/droope/droopescan)
* [smbmap](https://github.com/ShawnDEvans/smbmap)
* [enum4linux](https://github.com/portcullislabs/enum4linux)
* [dnsrecon](https://github.com/darkoperator/dnsrecon)
* [odat](https://github.com/quentinhardy/odat)
  
  
# Examples of use:
```bash
./nmapAutomator.sh <TARGET-IP> <TYPE>  
./nmapAutomator.sh 10.1.1.1 All  
./nmapAutomator.sh 10.1.1.1 Basic  
./nmapAutomator.sh 10.1.1.1 Recon  
```

**If you want to use it anywhere on the system, create a shortcut using:**  
`ln -s /PATH-TO-FOLDER/nmapAutomator.sh /usr/local/bin/`


# TODO features list
_**pull requests are more than welcome :)**_
- [x] Support DNS resolution "use of urls/domains instead of IPs" - Done, thanks @KatsuragiCSL
- [ ] Properly identify url extensions "testing index extensions for code 200"
- [ ] Add more port-based automatic recon options
- [ ] Add an nmap progress bar
