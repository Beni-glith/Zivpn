#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

print_task() {
  echo -ne "${GRAY}â€¢${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}âœ“${RESET} $1      "
}

print_fail() {
  echo -e "\r${RED}âœ—${RESET} $1      "
  exit 1
}

run_silent() {
  local msg="$1"
  local cmd="$2"
  
  print_task "$msg"
  bash -c "$cmd" &>/tmp/zivpn_install.log
  if [ $? -eq 0 ]; then
    print_done "$msg"
  else
    print_fail "$msg (Check /tmp/zivpn_install.log)"
  fi
}

# Compare versions (semantic-ish) using sort -V
version_ge() {
  # returns 0 if $1 >= $2
  [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

install_go() {
  local go_ver="${1:-1.22.13}"
  local arch="amd64"
  local os="linux"
  local tar="go${go_ver}.${os}-${arch}.tar.gz"
  local url="https://go.dev/dl/${tar}"

  # Prefer curl, fallback to wget
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "/tmp/${tar}"
  elif command -v wget &>/dev/null; then
    wget -q "$url" -O "/tmp/${tar}"
  else
    return 1
  fi

  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${tar}" || return 1

  # Persist PATH
  mkdir -p /etc/profile.d
  cat <<'EOF' > /etc/profile.d/golang.sh
export PATH=/usr/local/go/bin:$PATH
EOF

  # Make available for current session too
  export PATH=/usr/local/go/bin:$PATH
  return 0
}

ensure_go_version() {
  local required="${1:-1.20.0}"
  local install_ver="${2:-1.22.13}"

  if ! command -v go &>/dev/null; then
    install_go "$install_ver" || return 1
  else
    local current
    current="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
    # If parsing fails, force reinstall
    if [[ -z "$current" ]]; then
      install_go "$install_ver" || return 1
    elif ! version_ge "$current" "$required"; then
      install_go "$install_ver" || return 1
    fi
  fi
  return 0
}

clear
echo -e "${BOLD}ZiVPN UDP Installer${RESET}"
echo -e "${GRAY}AutoFTbot Edition${RESET}"
echo ""

if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  print_fail "System not supported (Linux AMD64 only)"
fi

if [ -f /usr/local/bin/zivpn ]; then
  echo -e "${YELLOW}! ZiVPN detected. Reinstalling...${RESET}"
  systemctl stop zivpn.service &>/dev/null
  systemctl stop zivpn-api.service &>/dev/null
  systemctl stop zivpn-bot.service &>/dev/null
fi

run_silent "Updating system" "sudo apt-get update"
run_silent "Setting Timezone" "sudo timedatectl set-timezone Asia/Jakarta"

if ! command -v go &> /dev/null; then
  run_silent "Installing dependencies" "sudo apt-get install -y golang git net-tools"
else
  print_done "Dependencies ready"
fi

echo ""
echo -ne "${BOLD}Domain Configuration${RESET}\n"
while true; do
  read -p "Enter Domain: " domain
  if [[ -n "$domain" ]]; then
    break
  fi
done
echo ""

echo -ne "${BOLD}API Key Configuration${RESET}\n"
read -p "Enter API Key (leave empty to auto-generate): " input_key
if [[ -z "$input_key" ]]; then
  # 32 bytes => 64 hex chars
  api_key=$(openssl rand -hex 32)
else
  api_key="$input_key"
fi
# Never print the API key.
echo ""

systemctl stop zivpn.service &>/dev/null
run_silent "Downloading Core" "wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn && chmod +x /usr/local/bin/zivpn"

mkdir -p /etc/zivpn
echo "$domain" > /etc/zivpn/domain
echo "$api_key" > /etc/zivpn/apikey
chmod 600 /etc/zivpn/apikey
if [[ "$(id -u)" == "0" ]]; then
  chown root:root /etc/zivpn/apikey
fi
run_silent "Configuring" "wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/config.json -O /etc/zivpn/config.json"

run_silent "Generating SSL" "openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj '/C=ID/ST=Jawa Barat/L=Bandung/O=AutoFTbot/OU=IT Department/CN=$domain' -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt"

# Find a free API port
print_task "Finding available API Port"
API_PORT=8080
while netstat -tuln | grep -q ":$API_PORT "; do
    ((API_PORT++))
done
echo "$API_PORT" > /etc/zivpn/api_port
print_done "API Port selected: ${CYAN}$API_PORT${RESET}"

cat >> /etc/sysctl.conf <<END
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.core.optmem_max=65536
net.core.somaxconn=65535
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_fastopen=3
fs.file-max=1000000
net.core.netdev_max_backlog=16384
net.ipv4.udp_mem=65536 131072 262144
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
END
sysctl -p &>/dev/null

cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=ZIVPN UDP VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
LimitNOFILE=65535
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /etc/zivpn/api
run_silent "Setting up API" "wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/zivpn-api.go -O /etc/zivpn/api/zivpn-api.go && wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/go.mod -O /etc/zivpn/api/go.mod"

cd /etc/zivpn/api

# Ensure Go >= 1.20 (go.mod requires it)
print_task "Checking Go version"
if ensure_go_version "1.20.0" "1.22.13" &>>/tmp/zivpn_install.log; then
  print_done "Checking Go version"
else
  print_fail "Checking Go version (Check /tmp/zivpn_install.log)"
fi

if go build -o zivpn-api zivpn-api.go 2>/tmp/zivpn_api_build.log; then
  print_done "Compiling API"
else
  print_fail "Compiling API"
  echo -e "${YELLOW}Build log (last 30 lines):${RESET}"
  tail -n 30 /tmp/zivpn_api_build.log 2>/dev/null || true
fi

cat <<EOF > /etc/systemd/system/zivpn-api.service
[Unit]
Description=ZiVPN Golang API Service
After=network.target zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-api
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo -ne "${BOLD}Telegram Bot Configuration${RESET}\n"
echo -ne "${GRAY}(Leave empty to skip)${RESET}\n"
read -p "Bot Token: " bot_token
read -p "Admin ID : " admin_id

if [[ -n "$bot_token" ]] && [[ -n "$admin_id" ]]; then
  echo ""
  echo "Select Bot Type:"
  echo "1) Free (Admin Only / Public Mode)"
  echo "2) Paid (Pakasir Payment Gateway)"
  read -p "Choice [1]: " bot_type
  bot_type=${bot_type:-1}

  if [[ "$bot_type" == "2" ]]; then
    read -p "Pakasir Project Slug: " pakasir_slug
    read -p "Pakasir API Key     : " pakasir_key
    read -p "Daily Price (IDR)   : " daily_price
    
    echo "{\"bot_token\": \"$bot_token\", \"admin_id\": $admin_id, \"mode\": \"public\", \"domain\": \"$domain\", \"pakasir_slug\": \"$pakasir_slug\", \"pakasir_api_key\": \"$pakasir_key\", \"daily_price\": $daily_price}" > /etc/zivpn/bot-config.json
    bot_file="zivpn-paid-bot.go"
  else
    read -p "Bot Mode (public/private) [default: private]: " bot_mode
    bot_mode=${bot_mode:-private}
    
    echo "{\"bot_token\": \"$bot_token\", \"admin_id\": $admin_id, \"mode\": \"$bot_mode\", \"domain\": \"$domain\"}" > /etc/zivpn/bot-config.json
    bot_file="zivpn-bot.go"
  fi
  
  run_silent "Downloading Bot" "wget -q https://raw.githubusercontent.com/Beni-glith/ZiVPN/main/$bot_file -O /etc/zivpn/api/$bot_file"
  
  cd /etc/zivpn/api
  run_silent "Downloading Bot Deps" "go get github.com/go-telegram-bot-api/telegram-bot-api/v5"
  
  if go build -o zivpn-bot "$bot_file" 2>/tmp/zivpn_bot_build.log; then
    print_done "Compiling Bot"
    
    cat <<EOF > /etc/systemd/system/zivpn-bot.service
[Unit]
Description=ZiVPN Telegram Bot
After=network.target zivpn-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-bot
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable zivpn-bot.service &>/dev/null
    systemctl start zivpn-bot.service &>/dev/null
  else
    print_fail "Compiling Bot"
    echo -e "${YELLOW}Build log (last 30 lines):${RESET}"
    tail -n 30 /tmp/zivpn_bot_build.log 2>/dev/null || true
  fi
else
  print_task "Skipping Bot Setup"
  echo ""
fi

run_silent "Starting Services" "systemctl enable zivpn.service && systemctl start zivpn.service && systemctl enable zivpn-api.service && systemctl start zivpn-api.service"

# Setup Cron for Auto-Expire
echo -e "${YELLOW}Setting up Cron Job for Auto-Expire...${NC}"
cron_cmd="0 0 * * * /usr/bin/curl -s -X POST -H \"X-API-Key: \$(cat /etc/zivpn/apikey)\" http://127.0.0.1:\$(cat /etc/zivpn/api_port)/api/cron/expire >> /var/log/zivpn-cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "/api/cron/expire"; echo "$cron_cmd") | crontab -
print_done "Cron Job Configured"

iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
ufw allow 6000:19999/udp &>/dev/null
ufw allow 5667/udp &>/dev/null
ufw allow $API_PORT/tcp &>/dev/null

rm -f "$0" install.tmp install.log &>/dev/null

echo ""
echo -e "${BOLD}Installation Complete${RESET}"
echo -e "Domain  : ${CYAN}$domain${RESET}"
echo -e "API     : ${CYAN}$API_PORT${RESET}"
echo -e "Token   : ${CYAN}$api_key${RESET}"
echo -e "Dev     : ${CYAN}https://t.me/one_zero2${RESET}"
echo ""
