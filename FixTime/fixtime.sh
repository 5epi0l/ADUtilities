#!/bin/bash

# Author : PaiN05

# --- CONFIGURATION ---
WINRM_PORT="5985"

# --- ARGUMENT HANDLING ---
TARGET_IP="$1"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <TARGET_IP>"
    echo "Example: $0 10.10.14.77"
    exit 1
fi

echo "=================================================="
echo "[*] STARTING WINRM KERBEROS CLOCK SYNC"
echo "[*] Target Host: $TARGET_IP:$WINRM_PORT"
echo "=================================================="

# --- 1. Stop Automatic Time Synchronization ---
echo "[*] Stopping system time sync services (to allow manual setting)..."

sudo timedatectl set-ntp false 2>/dev/null

echo "[+] Time sync services disabled."

echo "[*] Querying target for system time via HTTP Date header..."

# Note: We use -k (insecure) because the default WinRM port 5985 is unencrypted HTTP.
DATE_STRING=$(curl -s -I -k -X OPTIONS "http://$TARGET_IP:$WINRM_PORT/wsman" | \
              grep -i '^Date:' | \
              awk '{$1=""; print $0}' | \
              xargs)

if [ -z "$DATE_STRING" ]; then
    echo "[-] ERROR: Failed to retrieve Date header from $TARGET_IP."
    echo "    Check connectivity or if WinRM is running on port $WINRM_PORT."
    # Re-enable sync if we fail
    
    exit 1
fi

echo "[+] Target reported time: $DATE_STRING (Reported as GMT/UTC)"

# --- 3. Set Local System Clock to Match Target UTC Time ---
# The HTTP Date format is universally GMT/UTC, which we use directly with 'date -u'.
echo "[*] Setting local clock to reported time..."

if sudo date -u --set="$DATE_STRING"; then
    echo "[+] SUCCESS: Local clock successfully synchronized to target's time."
else
    echo "[-] CRITICAL ERROR: Failed to set the date using the retrieved string."
    echo "    Did you run this script with 'sudo' or do you have sudo privileges?"
    # Re-enable sync if we fail
    
    exit 1
fi

# --- 4. Verification ---
echo -e "\n--- Verification ---"
echo "Current Local Time (Your Timezone): $(date)"
echo "Current UTC Time (System Base):    $(date -u)"
echo -e "\n[!] Kerberos clock skew is now fixed. You may now retry your attack command."

# --- Re-enable Time Sync (Recommended Cleanup) ---
echo "[*] Re-enabling system time sync services (recommended for stability)."
