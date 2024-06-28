# RTB - Recon The Box
❀  An automated recon tool for HTB  ❀

****

RTB is conducting Nmap scan on the target IP, adding the lab's domain to the Hosts file, conducting subdomain enumeration, and then directory enumeration on the domain & the discovered subdomains.

****

⚠️ Note - The tool adds the domain to the Hosts file by extracting the domain from the Nmap output. In most cases, the domain name appears in the Nmap output, however, sometimes the domain name doesn't appear in the Nmap output. In this case, just add the lab's IP and domain name to the Hosts file manually and run the tool again.

****

### Installation
❀ git clone https://github.com/MichalApl/RTB.git

❀ sudo apt install feroxbuster

❀ cd RTB

❀ chmod +x rtb.sh

### Usage
❀ ./rtb.sh [LAB-IP] [LAB-NAME]

![image](https://github.com/MichalApl/RTB/assets/123867268/32d1c6b5-f0da-4dd7-846f-8d0ffb5256ac)

![image](https://github.com/MichalApl/RTB/assets/123867268/dd699dd9-e8bd-4d90-9a23-e6c1132f793c)
