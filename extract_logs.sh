#!/bin/bash
set -euo pipefail

# ─── Configuration ───
CONFIG_FILE="/home/cyber/config.ini"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi
source "$CONFIG_FILE"

# ─── Logging Functions ───
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$DEBUG_FILE"
}
log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "$DEBUG_FILE"
}

# ─── Start Clean ───
: > "$DEBUG_FILE"
log_info "Script started."
DATE_TODAY=$(date '+%d/%b/%Y')

# ─── Filter and Extract IPs ───
log_info "Filtering logs for today's date: $DATE_TODAY"
grep "$DATE_TODAY" "$LOG_FILE" > "$GENERAL_OUTPUT_FILE"
grep "$DATE_TODAY" "$LOG_FILE" | grep -E " cD | SD " > "$SPECIFIC_OUTPUT_FILE"

log_info "Extracting IP addresses from filtered logs."
grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' "$GENERAL_OUTPUT_FILE" > "$GENERAL_OUTPUT_FILE.tmp"
mv "$GENERAL_OUTPUT_FILE.tmp" "$GENERAL_OUTPUT_FILE"

grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' "$SPECIFIC_OUTPUT_FILE" > "$SPECIFIC_OUTPUT_FILE.tmp"
mv "$SPECIFIC_OUTPUT_FILE.tmp" "$SPECIFIC_OUTPUT_FILE"

# ─── Log Summary ───
ENTRY_COUNT=$(wc -l < "$GENERAL_OUTPUT_FILE")
log_info "General access attempts: $ENTRY_COUNT entries"
tail -n 20 "$GENERAL_OUTPUT_FILE" >> "$DEBUG_FILE"

ENTRY_COUNT=$(wc -l < "$SPECIFIC_OUTPUT_FILE")
log_info "Specific termination states: $ENTRY_COUNT entries"
tail -n 20 "$SPECIFIC_OUTPUT_FILE" >> "$DEBUG_FILE"

# ─── Combine and Count IPs ───
log_info "Combining, sorting, and counting unique IPs."
cat "$GENERAL_OUTPUT_FILE" "$SPECIFIC_OUTPUT_FILE" | sort | uniq -c |
    awk '{print $2 "-" $1}' > "$UNIQUE_IP_FILE"

ENTRY_COUNT=$(wc -l < "$UNIQUE_IP_FILE")
log_info "Unique IPs and their counts: $ENTRY_COUNT entries"
tail -n 20 "$UNIQUE_IP_FILE" >> "$DEBUG_FILE"

# ─── Clear Intermediate Files ───
: > "$ABUSE_IPS_FILE"
: > "$VALID_IPS_FILE"
: > "$PRIVATE_IP_COUNTS_FILE"
: > "$PUBLIC_IP_COUNTS_FILE"

# ─── IP Check Functions ───
is_private_ip() {
    local ip=$1
    [[ $ip =~ ^10\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]
}

check_ip_reputation() {
    local ip=$1
    local count=$2
    log_info "Checking reputation for $ip (count=$count)"

    local response
    response=$(curl -sG --connect-timeout 5 -m 10 https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=$ip" \
        -d maxAgeInDays=90 \
        -H "Key: $API_KEY" \
        -H "Accept: application/json")

    # Handle cases where curl might time out or fail
    if [[ -z "$response" ]]; then
        log_error "No response from AbuseIPDB API for IP: $ip"
        echo "{\"ip\": \"$ip\", \"count\": $count}" >> "$VALID_IPS_FILE"
        return
    fi

    local abuseScore totalReports
    # Use a single jq call to safely extract both values into shell variables
    eval "$(jq -r '.data | {abuseScore: .abuseConfidenceScore, totalReports: .totalReports} | to_entries | .[] | .key + "=" + (.value | @sh)' <<< "$response")"

    # Handle cases where values might be null from the API
    if [[ -z "$abuseScore" || "$abuseScore" == "null" ]]; then
        abuseScore=0
    fi
    if [[ -z "$totalReports" || "$totalReports" == "null" ]]; then
        totalReports=0
    fi

    if (( abuseScore > 0 )); then
        # Add the new fields 'score' and 'reports' to the JSON output for abusive IPs
        echo "{\"ip\": \"$ip\", \"count\": $count, \"score\": $abuseScore, \"reports\": $totalReports}" >> "$ABUSE_IPS_FILE"
        log_info "$ip classified as abusive (score $abuseScore, reports $totalReports)"
    else
        echo "{\"ip\": \"$ip\", \"count\": $count}" >> "$VALID_IPS_FILE"
        log_info "$ip classified as valid (score $abuseScore)"
    fi
}

# ─── Process and Lookup Each IP Sequentially ───
log_info "Processing each unique IP..."
while IFS= read -r line; do
    ip=${line%-*}
    count=${line#*-}

    if is_private_ip "$ip"; then
        echo "{\"ip\": \"$ip\", \"count\": $count}" >> "$PRIVATE_IP_COUNTS_FILE"
    else
        # Public IPs are split into "valid" and "abusive" inside the check_ip_reputation function
        echo "{\"ip\": \"$ip\", \"count\": $count}" >> "$PUBLIC_IP_COUNTS_FILE"
        check_ip_reputation "$ip" "$count"
    fi

done < "$UNIQUE_IP_FILE"

# ─── Assemble results.json ───
log_info "Assembling the final results.json file."
private_ips=$(jq -s . "$PRIVATE_IP_COUNTS_FILE")
public_ips=$(jq -s . "$PUBLIC_IP_COUNTS_FILE")
abuse_ips=$(jq -s . "$ABUSE_IPS_FILE")
valid_ips=$(jq -s . "$VALID_IPS_FILE")

results=$(jq -n \
  --argjson private_ips "$private_ips" \
  --argjson public_ips "$public_ips" \
  --argjson abuse_ips "$abuse_ips" \
  --argjson valid_ips "$valid_ips" \
  --arg last_run "$(date '+%Y-%m-%d %H:%M:%S')" \
  '{
      private_ips: $private_ips,
      public_ips: $public_ips,
      abuse_ips: $abuse_ips,
      valid_ips: $valid_ips,
      last_run: $last_run
  }')

# Atomically write the final JSON file to avoid race conditions with the node server
if jq -e . <<< "$results" > /dev/null; then
    echo "$results" > "/home/cyber/results.json.tmp" && mv "/home/cyber/results.json.tmp" "/home/cyber/results.json"
    log_info "results.json written successfully"
else
    log_error "Failed to generate valid results.json"
fi

log_info "Script finished."
echo "Results updated"
