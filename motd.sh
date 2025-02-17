#!/bin/bash

DARK_BLUE='\033[1;34m'
BRIGHT_BLUE='\033[1;36m'
ORANGE='\033[0;33m'
RESET='\033[0m'

echo -e "${ORANGE}"
echo -e "  __    __ _              _ __ _     _      _     _"
echo -e " / / /\ \ (_)_ __ ___  __| / _\ |__ (_) ___| | __| |"
echo -e " \ \/  \/ / | '__/ _ \/ _\` \ \| '_ \| |/ _ \ |/ _\` |"
echo -e "  \  /\  /| | | |  __/ (_| |\ \ | | | |  __/ | (_| |"
echo -e "   \/  \/ |_|_|  \___|\__,_\__/_| |_|_|\___|_|\__,_|"
echo -e "${RESET}"

hostname=$(hostname -f)
echo -e "${DARK_BLUE}Master:${RESET} ${BRIGHT_BLUE}$(echo $hostname | tr '[:lower:]' '[:upper:]')${RESET}"
echo -e "${DARK_BLUE}Disk Usage:${RESET} $(df -h / | awk 'NR==2 {print $3"/"$2}')"

ram_used=$(free -m | awk 'NR==2 {print $3}')
ram_total=$(free -m | awk 'NR==2 {print $2}')
ram_total_gb=$(echo "scale=1; $ram_total/1024" | bc)

if (( ram_used < 1024 )); then
    echo -e "${DARK_BLUE}RAM Usage:${RESET} ${ram_used}M/${ram_total_gb}GB"
else
    ram_used_gb=$(echo "scale=1; $ram_used/1024" | bc)
    echo -e "${DARK_BLUE}RAM Usage:${RESET} ${ram_used_gb}GB/${ram_total_gb}GB"
fi

echo -e "${DARK_BLUE}Swap Usage:${RESET} $(free -m | awk 'NR==3 {print $3"M/"$2"M"}')"

ipv4=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')
ipv6=$(ip -6 addr show | grep -oP '(?<=inet6 )[0-9a-fA-F:]+(?=/\d+)' | grep -vE '^(::1|fe80::)')

echo -e "${DARK_BLUE}IPv4:"
for ip in $ipv4; do
    echo -e "${RESET}   - ${BRIGHT_BLUE}$ip"
done

echo -e "${DARK_BLUE}IPv6:"
for ip in $ipv6; do
    echo -e "${RESET}   - ${BRIGHT_BLUE}$ip"
done

uptime_seconds=$(awk '{print int($1)}' /proc/uptime)
days=$((uptime_seconds / 86400))
hours=$(( (uptime_seconds % 86400) / 3600))
minutes=$(( (uptime_seconds % 3600) / 60))

uptime_formatted=""
if [ $days -gt 0 ]; then
    uptime_formatted="${days} day"
    if [ $days -gt 1 ]; then
        uptime_formatted="${uptime_formatted}s"
    fi
    uptime_formatted="${uptime_formatted}, "
fi

if [ $hours -gt 0 ] || [ $days -gt 0 ]; then
    uptime_formatted="${uptime_formatted}${hours} hour"
    if [ $hours -gt 1 ]; then
        uptime_formatted="${uptime_formatted}s"
    fi
    uptime_formatted="${uptime_formatted}, "
fi
uptime_formatted="${uptime_formatted}${minutes} minute"

if [ $minutes -gt 1 ]; then
    uptime_formatted="${uptime_formatted}s"
fi

echo -e "${DARK_BLUE}Uptime:${RESET} ${uptime_formatted}"
echo " "