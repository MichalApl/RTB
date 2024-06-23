#!/bin/bash

ip=$1
lab=$2
PINK="\033[1;35m"
PINKY="\033[1;45m"
GREENY="\033[1;42m"
GREEN="\033[1;32m"
RESET="\033[0m"

echo -e "${GREEN}╭────────────────────────────────────────────────────────╮ 
│ .-------.           ,---------.         _______        │
│ |  _ _   \\          \\          \\       \\  ____  \\      │
│ | ( ' )  |           \`--.  ,---'       | |    \\ |      │
│ |(_ o _) /              |   \\          | |____/ /      │
│ | (_,_).' __            :_ _:          |   _ _ '.      │
│ |  |\\ \\  |  |           (_I_)          |  ( ' )  \\     │
│ |  | \\ \`'   /          (_(=)_)         | (_{;}_) |     │
│ |  |  \\    /            (_I_)          |  (_,_)  /     │
│ ''-'   \`'-'             '---'          /_______.'      │                                     
╭────────────────────────────────────────────────────────╮
│                  🌸 Recon The Box 🌸                   │
╰────────────────────────────────────────────────────────╯
${RESET}"

echo -e "❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀"

valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ $valid_ip_regex ]]; then
        for octet in ${ip//./ }; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

if [ "$1" == "" ] || [ "$2" == "" ] || ! is_valid_ip "$ip"; then
	echo -e "${PINK} 🥀 Incorrect syntax! 🥀${RESET}"
	echo -e "${GREEN} Please provide a valid IP address as the first argument and the name of the lab as the second argument.${RESET}"
	echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│  🪻 Example syntax: sudo ./rtb.sh 6.6.6.6 Flowerlab 🪻 │
╰────────────────────────────────────────────────────────╯
${RESET}"
	exit 1

else
	subdomains_path=$lab/subdomains
	directories_path=$lab/directories
	scans_path=$lab/scans

	if [ ! -d "$lab" ];then
		mkdir $lab
	fi

	if [ ! -d "$subdomains_path" ];then
		mkdir $subdomains_path
	fi

	if [ ! -d "$scans_path" ];then
		mkdir $scans_path
	fi

	echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│              🪻 Starting port scanning 🪻              │
╰────────────────────────────────────────────────────────╯
${RESET}"

	extract_base_domain() {
	    local url=$1
	    echo $url | awk -F[/:] '{print $1}' | awk -F. '{
	        if (NF<=2) {
	            print $0
	        } else {
	            print $(NF-1)"."$NF
	        }
	    }'
	}

	echo -e "${GREEN} 🪷 Launching nmap ...${RESET}"
	nmap -Pn -sVC -p- -T5 -v --min-rate=1000 -oN $scans_path/nmap_output.txt $ip
	
	cat $scans_path/nmap_output.txt | grep 'http-title' | awk -F'http://' '{print $2}' | awk -F'/' '{print $1}' | grep -v '^$' > $scans_path/temp_domains.txt

	> $scans_path/domain.txt
	while IFS= read -r line; do
	    domain_without_port=$(echo $line | awk -F':' '{print $1}')
	    echo $domain_without_port >> $scans_path/domain.txt
	    base_domain=$(extract_base_domain "$domain_without_port")
	    echo $base_domain >> $scans_path/domain.txt
	done < $scans_path/temp_domains.txt

	sort -u $scans_path/domain.txt -o $scans_path/domain.txt

	grep -iE '^[0-9]+/tcp.*(http|ssl|nagios)' $scans_path/nmap_output.txt | awk '{print $1}' | cut -d'/' -f1 > $scans_path/http_ports.txt
	web_ports=$(cat $scans_path/http_ports.txt)

	echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│                 🪻 Domains found: 🪻                   │
╰────────────────────────────────────────────────────────╯
${RESET}"

	awk -F'.' '{print $(NF-1)"."$NF}' $scans_path/domain.txt | sort -u | tr '\n' ' ' | sed 's/ $/\n/' > $scans_path/temp && mv $scans_path/temp $scans_path/domain.txt
	domain=$(cat $scans_path/domain.txt)	
	existing_domains_file="$scans_path/domain.txt"
	new_domains_file="$scans_path/tr_domain.txt"
	tr '\n' ' ' < "$existing_domains_file" > "$new_domains_file"
	domains1=$(cat $new_domains_file)

	if grep -q "$ip" /etc/hosts; then
		grep "$ip" /etc/hosts | awk '{print $2}' | grep -v '^$' | sort -u > $scans_path/tempdomain.txt
		awk -F'.' '{print $(NF-1)"."$NF}' $scans_path/tempdomain.txt | sort -u | tr '\n' ' ' | sed 's/ $/\n/' > $scans_path/temp && mv $scans_path/temp $scans_path/domain.txt
     	domain2=$(cat $scans_path/domain.txt)
     	for d in $domain2; do
			echo -e "${GREEN} 🌐 $d${RESET}"
		done
    	echo -e "${PINK} 🪷 IP $ip already exists in /etc/hosts. Skipping addition...${RESET}"
	else
		if [ -z "$domain" ]; then
			echo -e "${GREEN} 🥀 No domain found. Exiting ...${RESET}"
			exit 1
		else
			for dm in $domain; do
				echo -e "${PINK} 🌐 $dm${RESET}"
			done
			echo -e "${GREEN} 🪷 Adding $domains1 to the /etc/hosts file ...${RESET}"
			echo -e "\n$ip $domains1" | sudo tee -a /etc/hosts
		
		fi
	fi

		echo -e "${PINK}\n 🪷 Identified web services running on ports:${RESET}"
		for port in $web_ports; do			
			echo -e "${GREEN} ⚡ $port${RESET}"
		done
			
		echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│          🪻 Starting subdomain enumeration 🪻          │
╰────────────────────────────────────────────────────────╯
${RESET}"

		echo -e "${GREEN} 🪷 Launching gobuster ...${RESET}"
		if [ -z "$domain" ]; then
			gobuster vhost -u $domain2 -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t 100 -q | awk '{print $2}' > $subdomains_path/found_subdomains.txt
		else 
			gobuster vhost -u $domain -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t 100 -q | awk '{print $2}' > $subdomains_path/found_subdomains.txt
		fi
		#echo -e "${PINK} 🪷 Launching subfinder ... ${RESET}"
		#subfinder -d $domain >> $subdomains_path/found_subdomains.txt

		#echo -e "${PINK} 🪷 Launching assetfinder ...${RESET}"
		#if [ -z "$domain" ]; then
			#assetfinder $domain2 | grep $domain2 >> $subdomains_path/found_subdomains.txt
		#else 
			#assetfinder $domain | grep $domain >> $subdomains_path/found_subdomains.txt
		#fi

		#echo -e "${GREEN} 🪷 Launching amass ... ${RESET}"
		#amass enum -d $domain >> $subdomains_path/found_subdomains.txt

		echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│                 🪻 Subdomains found: 🪻                │
╰────────────────────────────────────────────────────────╯
${RESET}"

		subdomains=$(cat $subdomains_path/found_subdomains.txt | sort -u | tee -a $subdomains_path/final_subdomains.txt)
		subd_sort=$(cat $subdomains_path/found_subdomains.txt | sort -u > $subdomains_path/subd.txt)
		existing_subdomains_file="$subdomains_path/found_subdomains.txt"
		subdomain_file_2="$subdomains_path/subd.txt"
		new_subdomain_file_2="$subdomains_path/subd2.txt"
		tr '\n' ' ' < "$subdomain_file_2" > "$new_subdomain_file_2"
		new_subdomains_file="$subdomains_path/tr_subdomains.txt"
		tr '\n' ' ' < "$existing_subdomains_file" > "$new_subdomains_file"
		subdomains2=$(cat $new_subdomain_file_2)
		subdomains3=$(cat $new_subdomains_file)

		if [ -z "$subdomains" ]; then
			echo -e "${GREEN} 🥀 None${RESET}"
		else 
			for subd in $subdomains; do
				echo -e "${PINK} 🌐 $subd${RESET}"
			done
			if ! grep -q "$subdomains2" /etc/hosts; then
				echo -e "${GREEN} 🪷 Adding the subdomains to the /etc/hosts file ...${RESET}"
				sudo sed -i "\$ s/\$/$subdomains2/" /etc/hosts
			else
				echo -e "${GREEN} 🪷 The subdomains are already exists in /etc/hosts. Skipping addition...${RESET}"
			fi
		fi 
		
		if [ -z "$domain" ]; then
			echo $domain2 >> $subdomains_path/final_subdomains.txt
		else 
			echo $domain >> $subdomains_path/final_subdomains.txt
		fi

		echo -e "${PINK}
╭────────────────────────────────────────────────────────╮
│           🪻 Starting directory enumeration 🪻         │
╰────────────────────────────────────────────────────────╯
${RESET}"

		suubdomains=$(cat $subdomains_path/final_subdomains.txt | grep -vE '^\*|^\.')
        echo -e "${GREEN} 🪷 Launching feroxbuster ...${RESET}"
		for subdomain in $suubdomains; do
		    for port in $(cat $scans_path/http_ports.txt); do
		        echo -e "${PINK}\n\n 🪷 Scanning http://$subdomain:$port :${RESET}"
		        echo -e "${PINK}─────────────────────────────────────────────${RESET}"
		        mkdir -p $directories_path/$subdomain-$port
		        feroxbuster -u http://$subdomain:$port -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --no-state --time-limit 5m --threads 120 --auto-bail --silent -E -I css,svg,ico,png,jpg -r -C 404 -o $directories_path/$subdomain-$port/found_directories.txt
		    done
		done

		echo -e "${GREEN}
╭────────────────────────────────────────────────────────╮
│                  🌸 Recon is done 🌸                   │
╰────────────────────────────────────────────────────────╯
${RESET}"

		echo -e "❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀   ❀"
		rm $scans_path/temp_domains.txt
fi
