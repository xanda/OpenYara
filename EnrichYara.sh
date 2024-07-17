#!/bin/bash
# SPDX-License-Identifier: 0BSD
#
# Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE.

# Check if two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <rules_file> <path_to_scan>"
    exit 1
fi

# Assign arguments to variables
rules_file=$1
path_to_scan=$2

# Execute yara and save the output to a variable
yara_output=$(yara -r "$rules_file" "$path_to_scan")

# Create a temporary file to store unique file paths
temp_file=$(mktemp)

# Extract unique file paths from yara output
echo "$yara_output" | awk '{print $2}' | sort | uniq > "$temp_file"

# Function to calculate MD5 checksum using either md5sum or md5
calculate_md5() {
    if command -v md5sum > /dev/null; then
        md5sum "$1" | awk '{print $1}'
    elif command -v md5 > /dev/null; then
        md5 -q "$1"
    else
        echo "Error: No MD5 command found" >&2
        exit 1
    fi
}

# Read each unique file path and process detections
while read -r file_path; do
    # Get file details using ls and awk
    file_info=$(ls -l "$file_path")
    user=$(echo "$file_info" | awk '{print $3}')
    group=$(echo "$file_info" | awk '{print $4}')
    filetimestamp=$(echo "$file_info" | awk '{print $6, $7, $8}')

    # Get all detections for the current file path
    detections=$(echo "$yara_output" | grep "$file_path" | awk '{print $1}' | tr '\n' ';' | sed 's/;$//')

    # Calculate MD5 checksum
    md5_checksum=$(calculate_md5 "$file_path")

    # Print the CSV line
    echo "$file_path,$user,$group,$filetimestamp,$detections,$md5_checksum"
done < "$temp_file" | sort | uniq

# Remove the temporary file
rm "$temp_file"

