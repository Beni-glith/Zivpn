#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

print_task() {
  echo -ne "${GRAY}•${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}✓${RESET} $1      "
}

run_silent() {
  local msg="$1"
  local cmd="$2"
  
  print_task "$msg"
  bash -c "$cmd" &>/tmp/zivpn_iptables.log
  if [ $? -eq 0 ]; then
    print_done "$msg"
  else
    print_done "$msg" 
  fi
}

clear
echo -e "${BOLD}ZiVPN IPtables Fixer${RESET}"
echo -e "${GRAY}AutoFTbot Edition${RESET}"
echo ""

iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
run_silent "Cleaning old rules" "iptables -t nat -D PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null"

run_silent "Applying new rules" "iptables -t nat -A PREROUTING -i $iface -p udp --dport 6000:19999 -j DNAT --to-destination :5667"

if [ -f /etc/iptables/rules.v4 ]; then
    run_silent "Saving to rules.v4" "iptables-save > /etc/iptables/rules.v4"
elif [ -f /etc/iptables.up.rules ]; then
    run_silent "Saving to iptables.up.rules" "iptables-save > /etc/iptables.up.rules"
else
    run_silent "Saving configuration" "netfilter-persistent save &>/dev/null || service iptables save &>/dev/null"
fi

echo ""
echo -e "${BOLD}Fix Complete${RESET}"
echo -e "${GRAY}IPtables rules have been refreshed.${RESET}"
echo ""
