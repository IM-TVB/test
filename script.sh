#!/usr/bin/env bash

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root." 
  exit 1
fi

echo "=== Initializing UFW Crypto Mining Rules ==="

# 1. Define common mining pool ports (Stratum protocol and pool default ports)
MINING_PORTS=(
  3333   # Monero / Generic Stratum
  3334   # Monero SSL
  4444   # Generic Stratum / Ethereum
  5555   # Generic Stratum
  6666   # Generic Stratum
  7777   # Generic Stratum
  8888   # Generic Stratum
  9999   # Generic Stratum
  14444  # Monero Ocean / Custom Stratum
  14433  # Monero Ocean SSL
  45560  # Monero / XMRig SSL
  45700  # Generic Stratum
)

echo "[*] Blocking outbound connections on common mining ports..."
for PORT in "${MINING_PORTS[@]}"; do
  ufw deny out $PORT/tcp > /dev/null
  ufw deny out $PORT/udp > /dev/null
done
echo "[+] Blocked ${#MINING_PORTS[@]} common mining ports (TCP/UDP)."

# 2. Block well-known hardcoded mining pool domains/IPs
HARDCODED_POOLS=(
  "pool.supportxmr.com"
  "xmr.nanopool.org"
  "mine.c3pool.com"
  "gulf.moneroocean.stream"
  "pool.minexmr.com"
  "herominers.com"
  "unmineable.com"
  "hashvault.pro"
)

echo "[*] Resolving and blocking hardcoded mining pool domains..."
for DOMAIN in "${HARDCODED_POOLS[@]}"; do
  # Resolve domain to IPv4 addresses
  IPS=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
  for IP in $IPS; do
    ufw deny out to "$IP" > /dev/null
    echo "  - Blocked $DOMAIN ($IP)"
  done
done

# 3. Pull dynamic blocklist from URL Haus / Mining threat feeds
echo "[*] Fetching dynamic crypto mining IP blocklists..."
TEMP_LIST=$(mktemp)

# Download URLHaus malware/miner IP list
curl -s "https://urlhaus.abuse.ch/downloads/hostfile/" | grep "127.0.0.1" | awk '{print $2}' | grep -v "localhost" > "$TEMP_LIST"

# Filter and apply unique IP blocks (limit to top entries to avoid bloat)
ADDED_COUNT=0
while read -r HOST; do
  if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ufw deny out to "$HOST" > /dev/null
    ((ADDED_COUNT++))
  fi
  # Cap dynamic rule imports at 100 to maintain UFW performance
  if [ "$ADDED_COUNT" -ge 100 ]; then
    break
  fi
done < "$TEMP_LIST"

rm -f "$TEMP_LIST"
echo "[+] Added $ADDED_COUNT dynamic threat feed IP blocks."

# 4. Reload UFW to enforce changes
echo "[*] Reloading UFW firewall rules..."
ufw reload > /dev/null

echo "=== Protection Active ==="
echo "Run 'sudo ufw status verbose' to view your updated rule set."
