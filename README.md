# nmapAutomator

A script you can run in the background!
  
![nmapAutomator](https://i.imgur.com/3cMJIPr.gif)
  
## Summary

The main goal for this script is to automate the process of enumeration & recon that is run every time, and instead focus our attention on real pentesting.  
  
This will ensure two things:  
1. Automate nmap scans. 
2. Always have some recon running in the background. 

Once initial ports are found '*in 5-10 seconds*', we can start manually looking into those ports, and let the rest run in the background with no interaction from our side whatsoever.  

## Features

### Scans
1. **Network** : Shows all live hosts in the host's network (~15 seconds)
2. **Port**    : Shows all open ports (~15 seconds)
3. **Script**  : Runs a script scan on found ports (~5 minutes)
4. **Full**    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
5. **UDP**     : Runs a UDP scan "requires sudo" (~5 minutes)
6. **Vulns**   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
7. **Recon**   : Suggests recon commands, then prompts to automatically run them
8. **All**     : Runs all the scans (~20-30 minutes)

*Note: This is a reconnaissance tool, and it does not perform any exploitation.*

### Automatic Recon
With the `recon` option, nmapAutomator will automatically recommend and run the best recon tools for each found port.  
If a recommended tool is missing from your machine, nmapAutomator will suggest how to install it.

### Runs on any shell
nmapAutomator is 100% POSIX compatible, so it can run on any `sh` shell, and on any unix-based machine (*even a 10 YO router!*), which makes nmapAutomator ideal for lateral movement recon.

If you want to run nmapAutomator on a remote machine, simply download a static nmap binary from [this link](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap), or with [static-get](https://github.com/minos-org/minos-static), and transfer it to the remote machine. You can then use `-s/--static-nmap` to specify the path to the static nmap binary.

### Remote Mode (Beta)
With the `-r/--remote` flag nmapAutomator will run in Remote Mode, which is designed to run using POSIX shell commands only, without relying on any external tools.  
Remote Mode is still under development. Only following scans currently work with `-r`:
- [x] Network Scan (currently ping only)
- [ ] Port Scan
- [ ] Full Scan
- [ ] UDP Scan
- [ ] Recon Scan

### Output
nmapAutomator saves the output of each type of scan is saved into a separate file, under the output directory.  
The entire script output is also saved, which you can view with `less -r outputDir/nmapAutomator_host_type.txt`, or you can simply `cat` it.

-----
  
## Requirements & Dependency Installation

`nmapAutomator` automatically detects missing tools and notifies you. Below are setup commands for **Kali Linux** and **macOS**.

### 1. Kali Linux / Debian / Ubuntu

Most recon tools come pre-installed in [Kali Linux](https://www.kali.org) and [Parrot OS](https://www.parrotsec.org). To install or update all required and optional recon tools:

```bash
sudo apt update && sudo apt install -y \
  nmap ffuf gobuster nikto sslscan joomscan \
  wpscan smbmap enum4linux dnsrecon snmp ldap-utils
```

### 2. macOS (Homebrew)

`nmapAutomator` fully supports macOS (with both native BSD `sed` or Homebrew `gnu-sed`). Install dependencies using [Homebrew](https://brew.sh):

```bash
brew update && brew install \
  nmap ffuf gobuster nikto sslscan wpscan gnu-sed
```

### Other Recon Tools Supported:
|[nmap Vulners](https://github.com/vulnersCom/nmap-vulners)|[sslscan](https://github.com/rbsec/sslscan)|[nikto](https://github.com/sullo/nikto)|[joomscan](https://github.com/rezasp/joomscan)|[wpscan](https://github.com/wpscanteam/wpscan)|
|:-:|:-:|:-:|:-:|:-:|
|[droopescan](https://github.com/droope/droopescan)|[smbmap](https://github.com/ShawnDEvans/smbmap)|[enum4linux](https://github.com/portcullislabs/enum4linux)|[dnsrecon](https://github.com/darkoperator/dnsrecon)|[odat](https://github.com/quentinhardy/odat)|
|[smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)|snmp-check|snmpwalk|ldapsearch||

*If any recommended recon tools are missing, they will be automatically omitted during scans and reported via `na -c`.*

-----

## Installation & Global Alias Setup

### 1. Clone the Repository
```bash
git clone https://github.com/21y4d/nmapAutomator.git
cd nmapAutomator
```

### 2. Make it Globally Executable
Create a symbolic link in `/usr/local/bin`:
```bash
sudo ln -s $(pwd)/nmapAutomator.sh /usr/local/bin/nmapAutomator
```

### 3. Add `na` Short Alias
To run `nmapAutomator` using the short `na` command:

**Option A: Create a direct symlink (`na`)** *(Recommended)*
```bash
sudo ln -s $(pwd)/nmapAutomator.sh /usr/local/bin/na
```

**Option B: Add a shell alias (`~/.bashrc` or `~/.zshrc`)**
```bash
# For Bash (Linux / macOS)
echo "alias na='nmapAutomator.sh'" >> ~/.bashrc && source ~/.bashrc

# For Zsh (macOS / Kali default)
echo "alias na='nmapAutomator.sh'" >> ~/.zshrc && source ~/.zshrc
```

-----

## Usage:
```
na -h
Usage: nmapAutomator.sh -H/--host <TARGET-IP> -t/--type <TYPE>
Optional: [-r/--remote <REMOTE MODE>] [-d/--dns <DNS SERVER>] [-o/--output <OUTPUT DIRECTORY>] [-s/--static-nmap <STATIC NMAP PATH>] [-c/--check-deps] [-m/--min-rate <RATE>]

Scan Types:
	Network : Shows all live hosts in the host's network (~15 seconds)
	Port    : Shows all open ports (~15 seconds)
	Script  : Runs a script scan on found ports (~5 minutes)
	Full    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
	UDP     : Runs a UDP scan "requires sudo" (~5 minutes)
	Vulns   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
	Recon   : Suggests recon commands, then prompts to automatically run them
	All     : Runs all the scans (~20-30 minutes)
```

**Check installed dependencies**:
```bash
na -c
# or
na --check-deps
```

**Example scans**:
```bash
# Fast Shorthand: Runs All scans with high speed (default 1000 pps)
na 10.1.1.1

# High Speed Scan (2500 pps for fast lab environments):
na 10.1.1.1 -m 2500

# Explicit scans:
na --host 10.1.1.1 --type All
na -H 10.1.1.1 -t Port
na -H academy.htb -t Recon -d 1.1.1.1
na -H 10.10.10.10 -t Network -s ./nmap
```

------

## Upcoming Features
- [x] Support URL/DNS - Thanks @KatsuragiCSL
- [x] Add extensions fuzzing for http recon
- [x] Add an nmap progress bar
- [x] List missing tools in recon
- [x] Add option to change output folder
- [x] Save full script output to a file
- [x] Improve performance and efficiency of the script - Thanks @caribpa
- [x] Make nmapAutomater 100% POSIX compatible. - Massive Thanks to @caribpa
- [x] Add network scanning type, so nmapAutomator can discover live hosts on the network.
- [ ] Enable usage of multiple scan types in one scan.
- [ ] Enable scanning of multiple hosts in one scan.
- [ ] Fully implement Remote Mode on all scans


**Feel free to send your pull requests :)**  
*For any pull requests, please try to follow these [Contributing Guidelines](CONTRIBUTING.md).*
