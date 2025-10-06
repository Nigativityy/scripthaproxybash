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

# ─── Create a temporary file for today's logs to search against ---
log_info "Filtering logs for today's date: $DATE_TODAY"
TODAY_LOG_FILE=$(mktemp)
grep "$DATE_TODAY" "$LOG_FILE" > "$TODAY_LOG_FILE"

# --- Extract IPs from today's logs ---
log_info "Extracting IP addresses from filtered logs."
grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' "$TODAY_LOG_FILE" > "$GENERAL_OUTPUT_FILE"
grep -E " cD | SD " "$TODAY_LOG_FILE" | grep -oP '\b\d{1,3}(\.\d{1,3}){3}\b' > "$SPECIFIC_OUTPUT_FILE"

# ─── Combine and Count IPs ───
log_info "Combining, sorting, and counting unique IPs."
cat "$GENERAL_OUTPUT_FILE" "$SPECIFIC_OUTPUT_FILE" | sort | uniq -c |
    awk '{print $2 "-" $1}' > "$UNIQUE_IP_FILE"

# ─── Clear Intermediate Files ───
: > "$ABUSE_IPS_FILE"
: > "$VALID_IPS_FILE"
: > "$PRIVATE_IP_COUNTS_FILE"

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

    if [[ -z "$response" ]]; then
        log_error "No response from AbuseIPDB API for IP: $ip"
        # If the API fails, we treat the IP as valid by default
        response='{"data":{"abuseConfidenceScore":0, "totalReports":0}}'
    fi

    local abuseScore totalReports
    eval "$(jq -r '.data | {abuseScore: .abuseConfidenceScore, totalReports: .totalReports} | to_entries | .[] | .key + "=" + (.value | @sh)' <<< "$response")"

    if [[ -z "$abuseScore" || "$abuseScore" == "null" ]]; then abuseScore=0; fi
    if [[ -z "$totalReports" || "$totalReports" == "null" ]]; then totalReports=0; fi

    # --- Data for provider details is gathered for ALL public IPs before the if/else check. ---
    log_info "Fetching provider details for $ip"
    local details_response
    details_response=$(curl -s --connect-timeout 5 "http://ip-api.com/json/${ip}?fields=status,country,city,isp")

    local provider_details="N/A / N/A / N/A"
    if [[ -n "$details_response" ]] && [[ $(jq -r '.status' <<< "$details_response") == "success" ]]; then
        provider_details=$(jq -r '[.country, .city, .isp] | join(" / ")' <<< "$details_response")
    else
        log_error "Failed to get provider details for $ip"
    fi

    if (( abuseScore > 0 )); then
        # Build the JSON for an ABUSIVE IP by piping the large log data
        grep -- "$ip" "$TODAY_LOG_FILE" | jq -R . | jq -s . | jq \
          --arg ip "$ip" \
          --argjson count "$count" \
          --argjson score "$abuseScore" \
          --argjson reports "$totalReports" \
          --arg provider "$provider_details" \
          '{ip: $ip, count: $count, score: $score, reports: $reports, provider: $provider, actions: .}' >> "$ABUSE_IPS_FILE"

        log_info "$ip classified as abusive (score $abuseScore, provider: $provider_details)"
    else
        # Build the JSON for a VALID IP, using the data we already gathered
        grep -- "$ip" "$TODAY_LOG_FILE" | jq -R . | jq -s . | jq \
          --arg ip "$ip" \
          --argjson count "$count" \
          --arg provider "$provider_details" \
          '{ip: $ip, count: $count, provider: $provider, actions: .}' >> "$VALID_IPS_FILE"
        
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
        check_ip_reputation "$ip" "$count"
    fi
done < "$UNIQUE_IP_FILE"

# ─── Assemble results.json ───
log_info "Assembling the final results.json file."

# Use --slurpfile to have jq read the intermediate files directly.
# This is the robust way to handle large data and avoids "Argument list too long".
results=$(jq -n \
  --slurpfile private_ips "$PRIVATE_IP_COUNTS_FILE" \
  --slurpfile abuse_ips "$ABUSE_IPS_FILE" \
  --slurpfile valid_ips "$VALID_IPS_FILE" \
  --arg last_run "$(date '+%Y-%m-%d %H:%M:%S')" \
  '{
      private_ips: $private_ips,
      abuse_ips: $abuse_ips,
      valid_ips: $valid_ips,
      last_run: $last_run
  }')

if jq -e . <<< "$results" > /dev/null; then
    echo "$results" > "/home/cyber/results.json.tmp" && mv "/home/cyber/results.json.tmp" "/home/cyber/results.json"
    log_info "results.json written successfully"
else
    log_error "Failed to generate valid results.json"
fi

# --- Clean up temporary log file ---
rm "$TODAY_LOG_FILE"
log_info "Script finished."
echo "Results updated"
