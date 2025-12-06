#!/bin/bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
set -euo pipefail
IFS=$'\n\t'

# Paths to files with IP addresses
NEW_IP_FILE="/var/log/rugov_blacklist/blacklist.txt"
FMT_LOGS=""
if [[ -f "/etc/rsyslog.d/51-ufw-rugov.conf" ]]; then
	FMT_LOGS="do"
fi

# Download the new blacklist file
if ! sudo wget -O "$NEW_IP_FILE" https://github.com/C24Be/AS_Network_List/raw/main/blacklists/blacklist.txt; then
	echo "Failed to load new blacklist. Exiting."
	echo "$(date +"%Y-%m-%d %H:%M:%S") - Failed to load new blacklist. Exiting." >> /var/log/rugov_blacklist/blacklist_updater.log
	exit 1
fi

# Read IP addresses from the new file
new_addresses=()
while IFS= read -r ip || [[ -n "$ip" ]]; do
new_addresses+=("$ip")
done < "$NEW_IP_FILE"

# Add new addresses and remove old ones from the rules
added=0
removed=0

# Function to escape IP address for use in regex patterns
escape_ip_for_regex() {
	local ip="$1"
	# Escape dots for IPv4 and other regex special characters
	printf '%s' "$ip" | sed 's/\./\\./g; s/\[/\\[/g; s/\]/\\]/g; s/(/\\(/g; s/)/\\)/g; s/{/\\{/g; s/}/\\}/g; s/\*/\\*/g; s/+/\\+/g; s/?/\\?/g; s/^/\\^/g; s/$/\\$/g; s/|/\\|/g'
}

# Function to get current ufw rules for RUGOV blacklist
get_current_rules() {
	ufw status numbered 2>/dev/null | grep "DENY.*RUGOV blacklist" | sed 's/.*DENY.*from \([^ ]*\).*/\1/' | sort || true
}

# Function to add ufw rule (only if it doesn't exist)
add_ufw_rule() {
	local ip="$1"
	local escaped_ip
	escaped_ip=$(escape_ip_for_regex "$ip")
	# Check if rule already exists (escape IP for grep to handle special characters)
	if ufw status numbered 2>/dev/null | grep -q "DENY.*from $escaped_ip.*RUGOV blacklist"; then
		return 0
	fi
	# Add new rule with consistent comment (no date to avoid updates)
	# Suppress errors if rule already exists (ufw may return error for duplicates)
	if ! ufw deny from "$ip" comment "RUGOV blacklist" 2>/dev/null; then
		# If ufw returns error, check again - rule might have been added
		if ufw status numbered 2>/dev/null | grep -q "DENY.*from $escaped_ip.*RUGOV blacklist"; then
			return 0
		fi
		# If rule still doesn't exist, there was a real error
		return 1
	fi
	return 0
}

# Function to remove ufw rule by IP
remove_ufw_rule_by_ip() {
	local ip="$1"
	local escaped_ip
	escaped_ip=$(escape_ip_for_regex "$ip")
	# Find the rule number for this IP (escape IP to prevent regex matching issues)
	local rule_num=$(ufw status numbered 2>/dev/null | grep "DENY.*from $escaped_ip.*RUGOV blacklist" | head -1 | sed 's/\[\([0-9]*\)\].*/\1/' || true)
	if [[ -n "$rule_num" ]]; then
		# Suppress errors if rule was already deleted
		ufw --force delete "$rule_num" 2>/dev/null || true
		return 0
	fi
	return 1
}

# Get current rules from ufw
current_rules=()
while IFS= read -r rule || [[ -n "$rule" ]]; do
	current_rules+=("$rule")
done < <(get_current_rules)

# Find addresses to add (in new list but not in current rules)
for addr in "${new_addresses[@]}"; do
	# Use -F for fixed string matching to avoid regex issues with IP addresses
	if ! printf '%s\n' "${current_rules[@]}" | grep -Fxq "$addr"; then
		if add_ufw_rule "$addr"; then
			((added++)) || true
		fi
	fi
done

# Find addresses to remove (in current rules but not in new list)
for addr in "${current_rules[@]}"; do
	# Use -F for fixed string matching to avoid regex issues with IP addresses
	if ! printf '%s\n' "${new_addresses[@]}" | grep -Fxq "$addr"; then
		if remove_ufw_rule_by_ip "$addr"; then
			((removed++)) || true
		fi
	fi
done

# Display information about added and deleted addresses
echo "Added addresses to the blacklist: $added"
echo "Addresses removed from the blacklist: $removed"

# Add an entry to the log file
echo "$(date +"%Y-%m-%d %H:%M:%S") - Added addresses to the blacklist: $added, addresses removed from the blacklist: $removed" >> /var/log/rugov_blacklist/blacklist_updater.log
