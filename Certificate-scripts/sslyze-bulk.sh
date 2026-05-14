#!/bin/bash

# List of domains
DOMAINS=(
    "ihg.com"
)

# Output directory
OUTPUT_DIR="./sslyze_outputs"
mkdir -p "$OUTPUT_DIR"

# Options to use in the scan
OPTIONS="--certinfo --http_headers --heartbleed --robot --openssl_ccs --elliptic_curves --compression --reneg --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3"

# Run sslyze and extract info
for domain in "${DOMAINS[@]}"; do
    echo "🔍 Scanning $domain ..."
    OUTPUT_FILE="$OUTPUT_DIR/sslyze_${domain//./_}.log"
    sslyze $OPTIONS "$domain" > "$OUTPUT_FILE"

    echo -e "\n📄 Summary for $domain"

    # Extract Expiry Date (supports both formats)
    EXPIRY=$(grep -iE "Not After" "$OUTPUT_FILE" | head -n1 | sed -E 's/.*Not After *: *//')
    if [[ -n "$EXPIRY" ]]; then
        echo "  🕒 Expires on: $EXPIRY"
    else
        echo "  ⚠️ Expiration date not found"
    fi

    # Extract SANs from the "SubjAltName - DNS Names" section
    echo -n "  🧾 Subject Alt Names: "
    SAN_LINE=$(grep -i "SubjAltName - DNS Names:" "$OUTPUT_FILE" | sed -E 's/.*SubjAltName - DNS Names: *//')
    if [[ -n "$SAN_LINE" ]]; then
        echo
        IFS=',' read -ra SAN_ENTRIES <<< "$SAN_LINE"
        for san in "${SAN_ENTRIES[@]}"; do
            echo "    • ${san//DNS:/}"
        done
    else
        echo "Not found"
    fi

    echo
done

echo "✅ Done. Full logs are in $OUTPUT_DIR"
