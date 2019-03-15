# nmapAutomator
A script that you can run in the background!
  
  
# Summary
I have created this script as I was preparing for my OSCP exam.  
The main goal for this script is to automate all of the process of recon/enumeration that is run every time, and instead focus our attention on real pen testing.  
  
This will ensure two things:  
	1) Automate nmap scans. 
	2) Always have some recon running in the background. 

Once you find the inital ports in around 10 seconds, you then can start manulally looking into those ports, and let the rest run in the background with no interaction from your side whatsoever.  
  
  
# Features:
1. **Quick:**	Shows all open ports quickly (~15 seconds)  
1. **Basic:**	Runs Quick Scan, then a runs more thorough scan on found ports (~5 minutes)  
1. **UDP:**	  Runs "Basic" on UDP ports (~5 minutes)  
1. **Full:** 	Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)  
1. **Vulns:**	Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)  
1. **Recon:**	Runs "Basic" scan "if not yet run", then suggests recon commands "i.e. gobuster, nikto, smbmap" based on the found ports, then prompts to automatically run them  
1. **All:**  	Runs all the scans consecutively (~20-30 minutes)  
  
I tried to make the script as efficient as possible, so that you would get the results as fast as possible, without duplicating any work.  
  
  
# Requirements:
Recommended: nmap vulners scrip "for CVE scan"  
https://github.com/vulnersCom/nmap-vulners  
  
  
# Examples of use:
./nmapAutomator.sh <TARGET-IP> <TYPE>  
./nmapAutomator.sh 10.1.1.1 All  
./nmapAutomator.sh 10.1.1.1 Basic  
./nmapAutomator.sh 10.1.1.1 Recon  
