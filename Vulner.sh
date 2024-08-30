#!/bin/bash

#Made by Omer Shor

# the script will scan the target network ip address deliverd by the user.
# enumerate the service version and Brutforce auth service like SSH, FTP, and TELNET.
# NOTE - Make sure you have the privileg to run this script.
figlet Vulner
echo "[#] Welcome to the vulner PTool, the script will run scaning and enumertion on your target and run BA on auth service for your choice"
echo "[#] Please make sure you run this script with root account"

if [[ $(id -u) != 0 ]]
    then
        echo "[-] Please run the script with root acount"
        exit 1
    else
        echo "[+] You will move forward to start scaning your target, Enjoy"
fi
TS=$(date +%H:%M)
# set folder for the audit files
vuln_dir="vulenr_results_$TS"
mkdir -p $vuln_dir
cd $vuln_dir
# set the  report file
report_file="$vuln_dir/audit_file.$TS.txt"
# user enter target
# term to make sure the usser entering a valid nerwork/host
validate_ip() {
    local ip=$1
    local cidr=$2

# Regular expressions to validate IP address and CIDR notation
    local ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    local cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"

# Check if the IP address or CIDR notation matches the regular expressions
    if [[ $ip =~ $ip_regex ]] || [[ $cidr =~ $cidr_regex ]]; then
        return 0
    else
        return 1
    fi
}

# Loop to prompt the user to enter a valid IP address
while true; do
    read -p "[?] Please Enter a valid IP address for your target [network/host]: " target
    # Validate the entered IP address
    if validate_ip "$target" "$target"; then
        # Exit the loop if a valid IP address is entered
        break
    else
        echo -e "${RED}[-]${NC} Your IP address input is NOT valid, please enter a valid IP address"
    fi
done

if [[ "$target" == *"/"* ]]; then
		echo "[#] Please select one target from the targets list"
		targets=$(nmap -sn $target)
		nmap -O --top-ports 1 $target > targets2
		cat ./targets2 | grep -Ee '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' -e "OS details:" | awk '/Nmap scan report/ {print ++i ". " $NF} /OS details:/ {print}'
		read -p "[?] Please enter your choice here: " target
  		rm -r targets2
fi

# Allow the user to choose 'Basic' or 'Full'
read -p "[?] Please chose [B]aisc scan or [F]ull scan, basic scan is defualt, full include service version and vulnerbility on the target: " scan_type

# basic scan
if [ "$scan_type" == B ] || [ "$scan_type" == b ] ;
    then
        echo "[#] You chose to run a Basic scan on the target"
        echo "[#] The script will run a basic scan on the target $target"
        nmap -sV --top-ports=50 $target -oN $vuln_dir.scaning_resulte.$scan_type.$TS.txt -oX $vuln_dir.scaning_resulte.$scan_type.$TS.xml | grep -v "|" | grep -e open -e OS
        sleep 5
        echo "[#] the nmap scan on target $target is complete."
# full scan
# Mapping vulnerabilities should only take place if Full was chosen
# Display potential vulnerabilities via NSE and Searchsploit
elif [ "$scan_type" == F ] || [ "$scan_type" == f ] ;
    then
        echo "[#] You chose to run a full scan on the target include service version and vuln and OS fingerprint"
        echo "[#] The script will run a full scan on the target $target"
        echo "[#] The scaning will take 2-5 Min, Don't stop the script!"
        nmap -sV -p- -O --script=vuln $target -oN $vuln_dir.scaning_resulte.$scan_type.$TS.txt -oX $vuln_dir.scaning_resulte.$scan_type.$TS.xml | grep -v "|" | grep -e open -e OS
        sleep 10
        echo "[#] the nmap scan on target $target is complete."
        echo "[#] starting using searchsploit for Mapping vulnerabilities"
        for x in $(cat $vuln_dir.scaning_resulte.$scan_type.$TS.txt | grep CVE | awk -F / '{print $(NF-0)}' | grep ^[CVE] | cut -d - -f 3 | sort | uniq | sort -n ) ; do searchsploit $x ; done >> $vuln_dir.searchsploit$TS.txt
# when the input is not valid
    else
        echo "[-] Your input is NOT valid!! please chose B for Basic or F for Full scan"
        exit 1
fi


# function to check what services (ssh,ftp,telnet,rdp) if open or close
function service_check(){

    echo "[#] Checking for the open port aviable on the thrget with auth, like SSH, FTP and TELNET"
    open_ssh_port=$(cat $vuln_dir.scaning_resulte.$scan_type.$TS.txt | grep open | grep -Eo '[0-9]+' | grep -w 22)
    open_ftp_port=$(cat $vuln_dir.scaning_resulte.$scan_type.$TS.txt | grep open | grep -Eo '[0-9]+' | grep -w 21)
    open_telnet_port=$(cat $vuln_dir.scaning_resulte.$scan_type.$TS.txt | grep open | grep -Eo '[0-9]+' | grep -w 23)
    open_rdp_port=$(cat $vuln_dir.scaning_resulte.$scan_type.$TS.txt | grep open | grep -Eo '[0-9]+' | grep -w 3389)

    if [ "$open_ssh_port" == "22" ] > /dev/null;
        then
            echo "[+] SSH service found open on the target"
        else
            echo "[-] SSH service Closed on the target"
    fi

    if [ "$open_ftp_port" == "21" ] > /dev/null;
        then
            echo "[+] FTP service found open on the target"
        else
            echo "[-] FTP service Closed on the target"
    fi

    if [ "$open_telnet_port" == "23" ] > /dev/null;
        then
            echo "[+] TELNET service found open on the target"
        else
            echo "[-] TELNET service Closed on the target"
    fi

    if [ "$open_rdp_port" == "3389" ] > /dev/null;
        then
            echo "[+] RDP service found open on the target"
        else
            echo "[-] RDP service Closed on the target"

    fi

}

# Function to ask the user if they want to perform a brute force attack
function Brute_force() {

while true; do
        # Prompt the user for input
        read -p "[?] Would you like to perform a brute force attack? (Y/N): " user_choice

        # Convert input to lowercase to simplify comparisons
        user_choice=$(echo "$user_choice" | tr '[:upper:]' '[:lower:]')

        # Check the user's response
        if [ "$user_choice" = "y" ]; then
            echo "[#] You chose to perform a brute force attack."
            # Add code to perform the brute force attack here
            break
        elif [ "$user_choice" = "n" ]; then
            echo "[#] You chose not to perform a brute force attack. Exiting."
            exit
        else
            echo "[!] Invalid response. Please enter 'Y' or 'N'."
        fi
    done
}

# function to make sure that medusa is install on the machine and if not it's installing medusa
function Medusa_install() {

if ! command -v medusa &> /dev/null 2>&1;
        then
                echo "[-] medusa is not installed"
                echo "[*] start installing medusa"
                sudo apt install medusa &> /dev/null 2>&1
else
        echo "[+] medusa is installed!"

fi

}
# function to make sure that hydra is install on the machine and if not it's installing hydra
function Hydra_install() {

if ! command -v hydra &> /dev/null 2>&1;
        then
                echo "[-] hydra is not installed"
                echo "[*] start installing hydra"
                sudo apt install hydra &> /dev/null 2>&1
else
        echo "[+] hydra is installed!"

fi

}


# function for weak password scan
# Have a built-in password.lst to check for weak passwords
# Allow the user to supply their own password list
#  Login services to check include: SSH, RDP, FTP, and TELNET
#  At the end, show the user the found information
function BAT(){

    echo "[#] The tool will Burtforce attack on the target, To check weak passwords"
    echo "######################################################################"
    echo "######################################################################"
    echo "[!] Warning: Run this action with permission only!"
    echo "######################################################################"
    echo "######################################################################"
    echo "[#] You need to chose service to attack acording to the findings"
    echo "[#] Please chose the services to attack"
    read -p "[?] Please chose 1 for SSH, 2 for FTP, 3 for TELNET or 4 for RDP: " target_port
    if [ $target_port == 1 ];
        then
            attack_port="ssh"
            echo "[?] Do you want to use our weak password list or yours?"
            read -p "[?] For using your password list enter (1), Or enter (2) for using system password list: " pass_choice
            if [ $pass_choice == 1 ];
                then
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    read -p "[?] Please entar file path (full) for passwords: " passwords_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    medusa -h $target -U $users_list -P $passwords_list -M $attack_port > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep "SUCCESS"
                    echo "[#] The $attack_port password scan is complete"
            elif [ $pass_choice == 2 ];
                then
                    sudo git clone https://github.com/shawntns/top-100-worst-passwords.git &> /dev/null 2>&1
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    medusa -h $target -U $users_list -P ./top-100-worst-passwords/dic.txt -M $attack_port > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:"  > found_accounts.txt
                    cat found_accounts.txt | grep "SUCCESS"
                    echo "[#] The $attack_port password scan is complete"
            fi
    elif [ $target_port == 2 ];
        then
            attack_port="ftp"
            echo "[?] Do you want to use our weak password list or yours?"
            read -p "[?] For using your password list enter (1), Or enter (2) for using system password list: " pass_choice
            if [ $pass_choice == 1 ];
                then
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    read -p "[?] Please entar file path (full) for passwords: " passwords_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    medusa -h $target -U $users_list -P $passwords_list -M $attack_port > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep "SUCCESS"
                    echo "[#] The $attack_port password scan is complete"
            elif [ $pass_choice == 2 ];
                then
                    sudo git clone https://github.com/shawntns/top-100-worst-passwords.git &> /dev/null 2>&1
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    medusa -h $target -U $users_list -P ./top-100-worst-passwords/dic.txt -M $attack_port > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep "SUCCESS"
                    echo "[#] The $attack_port password scan is complete"
            fi

    elif [ $target_port == 3 ];
        then
            attack_port="telnet"
            echo "[?] Do you want to use our weak password list or yours?"
            read -p "[?] For using your password list enter (1), Or enter (2) for using system password list: " pass_choice
            if [ $pass_choice == 1 ];
                then
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    read -p "[?] Please entar file path (full) for passwords: " passwords_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    hydra -L $users_list -P $passwords_list telnet://$target > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep -e "login:" -e "password:"
                    echo "[#] The $attack_port password scan is complete"
            elif [ $pass_choice == 2 ];
                then
                    sudo git clone https://github.com/shawntns/top-100-worst-passwords.git &> /dev/null 2>&1
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    hydra -L $users_list -P ./top-100-worst-passwords/dic.txt telnet://$target > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep -e "login:" -e "password:"
                    echo "[#] The $attack_port password scan is complete"
            fi
    elif [ $target_port == 4 ];
        then
            attack_port="rdp"
            echo "[?] Do you want to use our weak password list or yours?"
            read -p "[?] For using your password list enter (1), Or enter (2) for using system password list: " pass_choice
            if [ $pass_choice == 1 ];
                then
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    read -p "[?] Please entar file path (full) for passwords: " passwords_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    hydra -L $users_list -P $passwords_list rdp://$target > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep -e "login:" -e "password:"
                    echo "[#] The $attack_port password scan is complete"
            elif [ $pass_choice == 2 ];
                then
                    sudo git clone https://github.com/shawntns/top-100-worst-passwords.git &> /dev/null 2>&1
                    read -p "[?] Please entar file path (full) for users account: " users_list
                    echo "[#] Starting the attack now, findings will be save to a file - found_accounts.txt"
                    hydra -L $users_list -P ./top-100-worst-passwords/dic.txt rdp://$target > audit_BAT.txt 2>&1
                    cat audit_BAT.txt | grep -B 1 -A 1 -ie "found" -e "login:" > found_accounts.txt
                    cat found_accounts.txt | grep -e "login:" -e "password:"
                    echo "[#] The $attack_port password scan is complete"
            fi
    fi

}

service_check
sleep 5
Brute_force
Medusa_install
Hydra_install
sleep 5
BAT
# Allow the user to search inside the results
chmod 777 *
chmod 777 *
#  Allow to save all results into a Zip file
echo "[#] Saving everying into a zip file"
cd ..
zip -r $vuln_dir $vuln_dir &> /dev/null 2>&1
