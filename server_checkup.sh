#!/bin/bash

# Define constants for styling and file output
# Colors with black text
CB="\033[1;46m\033[1;30m" # Highlight cyan background, black text
RD="\033[1;41m\033[1;30m" # Highlight red background, black text
GN="\033[1;42m\033[1;30m" # Highlight green background, black text
YL="\033[1;43m\033[1;30m" # Highlight yellow background, black text
PU="\033[1;45m\033[1;30m" # Highlight purple background, black text
BL="\033[1;44m\033[1;30m" # Highlight blue background, black text
CR="\033[0m" # Reset color (no color)
DT=$(date '+%Y-%m-%d_%H-%M-%S') # Current timestamp
OF="$HOME/hardware_info_${DT}.txt" # Output file name

# # Check and install required packages
# check_and_install() {
# 	for pkg in "$@"; do
# 		if ! dpkg -l | grep -qw "$pkg"; then
# 			echo "Installing missing package: $pkg"
# 			sudo apt-get install -y "$pkg"
# 		fi
# 	done
# }
# 
# check_and_install smartmontools jq lshw dmidecode ethtool fio sysstat

# Check and install required packages
check_and_install() {
    local missing_packages=()

    for pkg in "$@"; do
        if ! dpkg -l | grep -qw "$pkg"; then
            missing_packages+=("$pkg")
        fi
    done

    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        echo "Installing missing packages: ${missing_packages[*]}"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "${missing_packages[@]}" \
            -o Dpkg::Options::="--force-confold" \
            -o APT::Get::Assume-Yes=true \
            -q >/dev/null 2>&1
    fi
}

# Run package check and install
check_and_install smartmontools jq lshw dmidecode ethtool fio sysstat


# Notify the user about start
echo -e " "
sleep 1
echo -e "${GN}\n\n START SERVER CHECKUP : $(date '+%Y-%m-%d %H:%M:%S') \n${CR}\n"

sleep 3

{
    # Server time and location
    echo -e "${CB}\n SERVER TIME NOW${CR}"
    echo "$(date +"%A, %B %d, %Y %T") $(date +"%z") $(timedatectl show --property=Timezone --value)"

	echo -e "${CB}\n LOCATION${CR}"
	curl -s "http://ipinfo.io/$(hostname -I | awk '{print $1}')" | jq -r '
		"IP Address:     " + .ip,
		"City:           " + .city,
		"Region:         " + .region,
		"Country:        " + .country,
		"Timezone:       " + .timezone,
		"Coordinates:    " + .loc,
		"Organization:   " + .org
	'

    # System and CPU information
    echo -e "${CB}\n SYSTEM${CR}"
    if systemd-detect-virt | grep -q "none"; then
		echo " ✅ This is a physical (dedicated) server"
	else
		echo " ⚠️ This is a virtual machine ($(systemd-detect-virt))"
	fi
    hostnamectl

    echo -e "${CB}\n CPU${CR}"
	printf "%-25s %s\n" "Architecture:" "$(lscpu | grep -E '^Architecture:' | awk '{print $2}')"
	printf "%-25s %s\n" "CPU(s):" "$(lscpu | grep -E '^CPU\(s\):' | awk '{print $2}')"
	printf "%-25s %s\n" "Model name:" "$(lscpu | grep -E '^Model name:' | sed 's/Model name:[ ]*//')"
	printf "%-25s %s\n" "Thread(s) per core:" "$(lscpu | grep -E '^Thread\(s\) per core:' | awk '{print $4}')"
	printf "%-25s %s\n" "Core(s) per socket:" "$(lscpu | grep -E '^Core\(s\) per socket:' | awk '{print $4}')"
	printf "%-25s %s\n" "Socket(s):" "$(lscpu | grep -E '^Socket\(s\):' | awk '{print $2}')"
	echo "------------------------------------------"
	
	# Average CPU Frequency (convert from kHz to MHz)
	avg_freq_mhz=$(awk '{sum+=$1} END {print sum/NR/1000}' /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq)
	
	printf "%-25s %s\n" "Current Governor:" "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
	printf "%-25s %.2f MHz\n" "Average Frequency now:" "$avg_freq_mhz"
	printf "%-25s %.4f%%\n" "CPU Usage now:" "$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')"
	printf "%-25s %s\n" "Load Average (1 min):" "$(awk '{print $1}' /proc/loadavg)"

    # Server uptime
    echo -e "${CB}\n SERVER UPTIME${CR}"
    echo -e "$(who -b)\n$(uptime -p)\n$(uptime)" | sed 's/^[ \t]*//'
    
    # Who is logged in
    echo -e "${CB}\n WHO${CR}"
    who | column -t

    # Users on the server
    echo -e "${CB}\n USERS ON THIS SERVER${CR}"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd

    # RAM details
    echo -e "${CB}\n RAM DETAILS${CR}"
    sudo dmidecode --type memory | awk '
/Physical Memory Array/ {in_array = 1}
/Maximum Capacity:/ && in_array {max_capacity = $3 " " $4}
/Number Of Devices:/ && in_array {num_devices = $4}
/Size:/ && $2 ~ /^[0-9]+$/ {total += $2; count++; sizes[$2]++}
/Type:/ && !/Configured/ && $2 !~ /Error|Correction|<OUT/ {type=$2}
/Speed:/ && !/Configured/ && $2 ~ /^[0-9]+$/ {speeds[$2]++}
/Manufacturer:/ {manufacturers[$2 ~ /^(Unknown|NO)$/ ? "NOT USED" : $2]++}
/Part Number:/ {models[$3 ~ /^(Unknown|NO)$/ ? "NOT USED" : $3]++}
END {
    printf "RAM Total Size:   %d GB | Number of Modules: %d \n", total, count;
    if (max_capacity && num_devices) {
        printf "Maximum Capacity: %s | Number Of Devices: %d\n", max_capacity, num_devices;
    }
    printf "Module Sizes:\n";
    for (s in sizes) printf "  - %d GB (Count: %d)\n", s, sizes[s];
    printf "Speeds:\n";
    for (sp in speeds) printf "  - %d MT/s (Count: %d)\n", sp, speeds[sp];
    printf "Type: %s\n", (type ? type : "Unknown");
    printf "Manufacturers:\n";
    for (m in manufacturers) {
        printf "  - %s (Count: %d)\n", m, manufacturers[m];
    }
    printf "Models:\n";
    for (model in models) {
        printf "  - Model %s (Count: %d)\n", model, models[model];
    }
}'

	echo -e "${CB}\n NVME DISKS${CR}"
	for i in /dev/nvme*n1; do
		size=$(sudo fdisk -l $i | grep "Disk $i" | awk '{print $3, $4}' | tr -d ',')
		model=$(sudo smartctl -i $i | grep "Model Number" | awk -F: '{print $2}' | xargs)
		usage=$(sudo smartctl -a $i | grep 'Percentage Used' | awk '{print $3}' || echo "N/A")
		mountpoints=$(lsblk -no MOUNTPOINT $i 2>/dev/null | grep -v "^$" | paste -sd, - || echo "Not Mounted")
		echo -e "Disk $i: $size     $model     Percentage Used: ${usage:-0} \tMountpoints: $mountpoints"
	done
	
    echo -e "${CB}\n NOT MOUNTED DISKS${CR}"
    sudo parted -l | grep Error || echo "No more disks to be mounted"
    
    echo -e "${CB}\n MOUNTED DISKS TEST RESULTS${CR}"
	flag_fio_stop=false
	
	# Detect mounted filesystems (skip small partitions)
	mount_points=$(lsblk -ln -o MOUNTPOINT,SIZE | awk '$2+0 > 1 && $1 != "/boot/efi" {print $1}') # Skip partitions <1GB and /boot/efi
	
	if [[ -z "$mount_points" ]]; then
		echo "No suitable mounted filesystems detected for testing"
		flag_fio_stop=true
	fi
	
	if [[ "$flag_fio_stop" != "true" ]]; then
	
		# Розміри блоків
		block_sizes=("4k" "64k" "512k" "1m")
		
		format_iops() {
			local iops=$1
			# Перевірка, чи значення є числовим
			if [[ "$iops" =~ ^[0-9]+$ ]]; then
				if (( iops > 1000 )); then
					printf "%.1fk" "$(bc -l <<< "$iops / 1000")"
				else
					printf "%d" "$iops"
				fi
			else
				# Якщо значення некоректне, повертаємо "0.0k"
				echo "---"
			fi
		}
		
		for mount_point in $mount_points; do
			# Перевіряємо, чи можна писати у файлову систему
			temp_file="$mount_point/.fio_write_test"
			if sudo touch "$temp_file" 2>/dev/null; then
				sudo rm -f "$temp_file" # Видаляємо файл, якщо створено
				echo "fio Disk Speed Tests (Mixed R/W 50/50) (Partition $mount_point):"
				echo "---------------------------------"
				echo "Block Size  | Read           (IOPS)   | Write          (IOPS)"
				echo "  ------    | ---             ----    | ----            ----  "
		
				for bs in "${block_sizes[@]}"; do
					temp_file="$mount_point/fio_test_file"
					
					# Запускаємо fio для кожного розміру блоку
					result=$(sudo fio --name=test --filename="$temp_file" --rw=randrw --rwmixread=50 --bs=$bs --size=512M --numjobs=1 --iodepth=1 --direct=1 --runtime=10 --group_reporting)
					sudo rm -f "$temp_file" # Чистимо після тесту
		
					# Витягуємо MB/s з дужок і IOPS
					read_bw=$(echo "$result" | grep "read:" | awk -F'[()]' '{print $2}' | awk '{split($1, arr, /[a-zA-Z]/); printf "%s %s\n", arr[1], substr($1, length(arr[1])+1)}')
					read_iops=$(echo "$result" | grep "read:" | awk -F'IOPS=' '{print $2}' | awk '{print $1}' | tr -d ',')
					write_bw=$(echo "$result" | grep "write:" | awk -F'[()]' '{print $2}' | awk '{split($1, arr, /[a-zA-Z]/); printf "%s %s\n", arr[1], substr($1, length(arr[1])+1)}')
					write_iops=$(echo "$result" | grep "write:" | awk -F'IOPS=' '{print $2}' | awk '{print $1}' | tr -d ',')
		
					# Формат IOPS
					formatted_read_iops=$(format_iops "$read_iops")
					formatted_write_iops=$(format_iops "$write_iops")
		
					# Форматований вивід
					printf " %-10s | %-14s %-8s | %-14s %-8s\n" "$bs" "$read_bw" "($formatted_read_iops)" "$write_bw" "($formatted_write_iops)"
				done
# 			else
# 				echo -ne "\rSkipping read-only or inaccessible filesystem: $mount_point"
			fi
#			echo -e "\n"
		done
	fi

    echo -e "${CB}\n OUTPUT OF df -h${CR}"
    sudo df -h

    # Swap information
    echo -e "${CB}\n SWAP${CR}"
    sudo swapon --show
    
    # Ramdisk information
    echo -e "${CB}\n RAMDISK${CR}"
	# Знаходимо директорію з типом tmpfs
	ramdisk_dir=$(findmnt -t tmpfs -n -o TARGET | grep -m 1 "/mnt\|ramdisk")
	if [ -n "$ramdisk_dir" ]; then
		echo "Contents of the ramdisk:"
		du -h --max-depth=1 "$ramdisk_dir"
	else
		echo "No ramdisk found on this server"
	fi

    # Interface details
    echo -e "${BL}\n INTERFACE INFORMATION${CR}"
    printf "%-15s %-15s %-8s %-20s %-10s %-15s %-40s %-20s\n" \
           "Interface" "Physical Link" "State" "IP Address" "Speed" "Max Speed" "Adapter Model" "Vendor"

    for iface in $(ls /sys/class/net 2>/dev/null || echo "Unknown"); do 
        physical_link=$(sudo ethtool $iface 2>/dev/null | grep -i 'Link detected:' | awk '{print $3}' || echo "Unknown")
        status=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "Unknown"); 
        ip_addr=$(ip -brief address show $iface 2>/dev/null | awk '{print $3}' | paste -sd " " || echo "Unknown"); 
        speed=$(sudo ethtool $iface 2>/dev/null | grep -i 'Speed:' | awk '{print $2}' || echo "Unknown"); 
        max_speed=$(sudo lshw -class network -json 2>/dev/null | jq -r --arg iface "$iface" '.[]? | select(.logicalname == $iface) | .capacity // "Unknown"');
        adapter_model=$(sudo lshw -class network -json 2>/dev/null | jq -r --arg iface "$iface" '.[]? | select(.logicalname == $iface) | .product // "Unknown"');
        vendor=$(sudo lshw -class network -json 2>/dev/null | jq -r --arg iface "$iface" '.[]? | select(.logicalname == $iface) | .vendor // "Unknown"');
        printf "%-15s %-15s %-8s %-20s %-10s %-15s %-40s %-20s\n" \
               "$iface" "$physical_link" "$status" "${ip_addr:-Unknown}" "$speed" \
               "${max_speed:-Unknown}" "$adapter_model" "$vendor"
    done

    # System capabilities and bonding
    max_iface_speed=$(sudo lshw -class network 2>/dev/null | grep -i 'capacity:' | awk '{print $2}' | sort -nr | head -n 1 || echo "Unknown")
    pcie_bandwidths=$(sudo dmesg 2>/dev/null | grep 'PCIe bandwidth' | grep -o '[0-9.]* Gb/s available' | awk '{print $1 " " $2}' | sort -u || echo "Unknown")

    printf "Maximum interface speed: %s\n" "${max_iface_speed:-Unknown}"
    if [[ $pcie_bandwidths != "Unknown" ]]; then
        echo "System PCIe bandwidths detected:"
        echo "$pcie_bandwidths" | awk '{printf "- %s\n", $0}'
    else
        echo "Maximum system PCIe bandwidth: Unknown"
    fi

    bonding_dir="/proc/net/bonding"
    if [[ -d $bonding_dir ]]; then
        # echo -e "${BL}\n BONDING INFORMATION${CR}"
        for bond_file in "$bonding_dir"/*; do
            bond_name=$(basename "$bond_file")
            echo "Bond Interface: $bond_name"
            bonding_mode=$(grep -i "Bonding Mode" "$bond_file" | awk -F: '{print $2}' | xargs)
            mii_status=$(grep -i "MII Status" "$bond_file" | head -1 | awk -F: '{print $2}' | xargs)
            lacp_active=$(grep -i "LACP active" "$bond_file" | awk -F: '{print $2}' | xargs)
            lacp_rate=$(grep -i "LACP rate" "$bond_file" | awk -F: '{print $2}' | xargs)
            transmit_policy=$(grep -i "Transmit Hash Policy" "$bond_file" | awk -F: '{print $2}' | xargs)
            echo "  Bonding Mode: $bonding_mode"
            echo "  MII Status: $mii_status"
            echo "  LACP Active: $lacp_active"
            echo "  LACP Rate: $lacp_rate"
            echo "  Transmit Policy: $transmit_policy"
            echo "  Slave Interfaces:"
            awk '/^Slave Interface:/ {iface=$3; next} /^MII Status:/ {status=$3; next} /^Speed:/ {speed=$2; next} /^Duplex:/ {duplex=$2; next} /^Link Failure Count:/ {failures=$4; printf "    - %s: Status=%s, Speed=%s, Duplex=%s, Failures=%s\n", iface, status, speed, duplex, failures; iface=status=speed=duplex=failures=""}' "$bond_file"
        done
    fi

    # Default route and open ports
    # echo -e "${BL}\n DEFAULT ROUTE${CR}"
    ip route show default || echo "No default route found"
    
    echo -e "${BL}\n OPEN PORTS${CR}"
    ss -tunlp | grep LISTEN

    echo -e "${BL}\n FIREWALL STATUS${CR}"
    sudo ufw status || sudo iptables -L

    echo -e "${BL}\n DNS SERVERS${CR}"
    cat /etc/resolv.conf | grep -E '^nameserver'
    
    # Network Test
    echo -e "${BL}\n NETWORK TEST RESULTS${CR}"
    echo "Waiting 2-5 min for test..."
    curl -sL yabs.sh | bash -s -- -f -g | awk '/iperf3 Network Speed Tests \(/,/^$/'
    
    # Processes
    echo -e "${YL}\n TOP 20 PROCESSES LOADING THE SYSTEM NOW${CR}"
    ps -eo user:12,pid:10,%cpu:6,%mem:6,cmd --sort=-%cpu | head -n 20 | awk '{ if (length($0) > 150) $0 = substr($0, 1, 147) "…"; printf "%-12s %-10s %-6s %-6s  %s\n", $1, $2, $3, $4, substr($0, index($0, $5)) }'

    # All timers
    echo -e "${YL}\n ALL TIMERS NOW${CR}"
    sudo systemctl list-timers --all

    # Installed packages
    echo -e "${YL}\n INSTALLED PACKAGES${CR}"
    dpkg -l | wc -l


	# Checking Jito servers
	echo -e "${PU}\n JITO SERVERS${CR}"
	
	# Detect user location
	detect_continent() {
		local user_continent=$(curl -s "http://ipinfo.io/$(hostname -I | awk '{print $1}')" | jq -r '.timezone' | awk -F'/' '{print $1}')
		case "$user_continent" in
			"Europe"|"America"|"Asia") echo "$user_continent" ;;
			*) echo "Unknown" ;;
		esac
	}
	
	continent=$(detect_continent)
	echo -e "Detected location: $continent"
	
	# Function to find the fastest Jito server with real-time ping interruption
	find_fastest_server() {
		local network_name=$1
		shift  # Remove the first argument (network name), leaving only server list
	
		local fastest_time=9999999
		local fastest_server=""
		local fastest_city=""
		local continent=$(detect_continent)
	
		echo -e "Measuring latency for Jito $network_name servers...\n"
	
		local primary_servers=()
		local secondary_servers=()
	
		# Мапа основних серверів для кожного континенту
		declare -A continent_servers=(
			["Europe"]="frankfurt amsterdam"
			["America"]="ny slc dallas"
			["Asia"]="tokyo"
		)
		
		# Categorize servers based on continent
		for entry in "$@"; do
			local matched=0
			for region in ${continent_servers["$continent"]}; do
				if [[ "$entry" =~ "$region" ]]; then
					primary_servers+=("$entry")
					matched=1
					break
				fi
			done
			[[ $matched -eq 0 ]] && secondary_servers+=("$entry")
		done
		
		# Combine primary and secondary lists
		local sorted_servers=("${primary_servers[@]}" "${secondary_servers[@]}")
		
		for entry in "${sorted_servers[@]}"; do
			hostname="${entry%% *}"
			city="${entry##* }"
			city="${city//_/ }"  # Replace underscores with spaces
	
			# Display progress with correct spacing
			printf "  ➜ Pinging %-15s %-30s %-4s" "$city" "$hostname" $'\u00A0'
	
			# Set timeout for ping (+1 fastest time, but at least 1 second)
			timeout_value=$(echo "scale=2; ($fastest_time / 1000) + 1" | bc)
			if (( $(echo "$timeout_value < 1" | bc -l) )); then timeout_value=1; fi
	
			# Run ping with timeout
			avg_ping=$(timeout "${timeout_value}" ping -c 4 "$hostname" | grep 'avg' | awk -F'/' '{print $5}' 2>/dev/null)
	
			if [[ -n "$avg_ping" ]]; then
				echo -e "\t$avg_ping ms"
	
				# If the current ping is >= +1 ms of the fastest, skip further checks
				if (( $(echo "$fastest_time != 9999999 && $avg_ping >= ($fastest_time / 1000) + 1" | bc -l) )); then
					continue
				fi
	
				# Update the fastest server
				if (( $(echo "$avg_ping < $fastest_time" | bc -l) )); then
					fastest_time=$avg_ping
					fastest_server=$hostname
					fastest_city=$city
				fi
			else
				echo -e "\tStopped - slower than discovered (or unreachable)"
			fi
		done
	
		# Display result
		if [[ -n "$fastest_server" ]]; then
			echo -e "\nFastest $network_name server: $fastest_city : $fastest_server : ${fastest_time} ms\n"
		else
			echo -e "\nCould not determine the fastest server for $network_name.\n"
		fi
	}
	
	# List of mainnet servers
	mainnet_servers=(
		"ny.mainnet.block-engine.jito.wtf New_York"
		"slc.mainnet.block-engine.jito.wtf Salt_Lake_City"
		"frankfurt.mainnet.block-engine.jito.wtf Frankfurt"
		"amsterdam.mainnet.block-engine.jito.wtf Amsterdam"
		"tokyo.mainnet.block-engine.jito.wtf Tokyo"
	)
	
	# List of testnet servers
	testnet_servers=(
		"ny.testnet.block-engine.jito.wtf New_York"
		"dallas.testnet.block-engine.jito.wtf Dallas"
	)
	
	# Run tests for both networks
	find_fastest_server "Mainnet" "${mainnet_servers[@]}"
	find_fastest_server "Testnet" "${testnet_servers[@]}"
	
	# Provide additional information
	echo -e "Check Jito's https://docs.jito.wtf/lowlatencytxnsend/#api"

	if sudo systemctl is-active --quiet solana; then
		# Running Solana validator
		echo -e "${PU}\n SOLANA ACTIVE SINCE${CR}"
		sudo systemctl status solana | grep since
		
		echo -e "${PU}\n ARGS OF RUNNING SOLANA${CR}"
		ps -eo cmd --sort=-%cpu | grep -v "grep" | grep "agave-validator\|solana-validator" | sed 's/ --/ \n--/g' || echo "Solana not running now"
	
		echo -e "${PU}\n VALIDATOR MONITOR${CR}"
		solana -V >/dev/null 2>&1 || { echo "Solana CLI not installed"; false; }
		vc=$(ps -eo cmd --sort=-%cpu | grep -v "grep" | grep -E "agave-validator|solana-validator" | head -n 1) || { echo "Solana validator not running"; false; }
		lp=$(echo "$vc" | sed 's/ --/ \n--/g' | grep -oP '(?<=--ledger )\S+')
		ep=$(echo "$vc" | sed 's/ --/ \n--/g' | grep -oP '(?<=--entrypoint )\S+' | head -n 1)
		net=$(echo "$ep" | grep -oE 'testnet|mainnet|devnet' || echo "unknown")
		vc_cmd=$(echo "$vc" | grep -q "solana-validator" && echo "solana-validator" || echo "agave-validator")
		echo "Cluster: ${net^}"
		timeout 2 "$vc_cmd" -l "$lp" monitor
	
		echo -e "${PU}\n INSTALLED SOLANA VERSION${CR}"
		echo -e "$(solana -V 2>/dev/null || echo 'Solana CLI not installed')\n$(solana-validator -V 2>/dev/null || agave-validator -V 2>/dev/null || echo 'Solana validator not installed')"
	fi

} | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OF")

# Notify the user about the saved output file
echo -e "${GN}\n\n END SERVER CHECKUP : $(date '+%Y-%m-%d %H:%M:%S') \n HARDWARE INFORMATION SAVED TO $OF \n${CR}\n"
