#!/bin/bash

# Colors for pretty output
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Prompt for source and destination bucket names
read -p "Enter source bucket name: " SRC_BUCKET
read -p "Enter destination bucket name: " DST_BUCKET

# Validate input
if [[ -z "$SRC_BUCKET" || -z "$DST_BUCKET" ]]; then
    echo -e "${RED}Error:${NC} Both source and destination bucket names are required."
    exit 1
fi

echo -e "Copying from '${GREEN}$SRC_BUCKET${NC}' to '${GREEN}$DST_BUCKET${NC}'..."

# Run Docker with interactive copying, pipe output to less
docker run --rm \
    -v "${SRC_BUCKET}":/src \
    -v "${DST_BUCKET}":/dst \
    alpine sh -c '
        set -e
        for file in $(find /src -type f); do
            rel_path="${file#/src/}"
            dst_file="/dst/$rel_path"

            if [ -f "$dst_file" ]; then
                echo -e "\033[1;33mOverwriting:\033[0m $rel_path"
            else
                echo -e "\033[1;32mCopying:\033[0m $rel_path"
            fi

            mkdir -p "$(dirname "$dst_file")"
            cp -a "$file" "$dst_file"
        done
    ' | less -R

# Print completion message after exiting less
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}All files copied successfully!${NC}"
else
    echo -e "${RED}Error occurred during copy.${NC}"
    exit 1
fi
