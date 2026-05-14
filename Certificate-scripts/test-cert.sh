#!/bin/bash

# Define color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if exactly one argument is provided
if [[ $# -ne 1 ]]; then
    echo -e "${RED}Usage: $0 <certificate file (.pem/.crt/.cer)>${NC}"
    exit 1
fi

CERT_FILE="$1"
BASENAME="${CERT_FILE%.*}"
CSR_FILE="$BASENAME.csr"
KEY_FILE="$BASENAME.key"
CHAIN_FILE="$BASENAME.chain"

echo -e "\n${BLUE}🔍 Step 1: Checking for related files...${NC}"
for file in "$CSR_FILE" "$KEY_FILE" "$CHAIN_FILE"; do
    [[ -f "$file" ]] && echo -e "${GREEN}✅ Found: $file${NC}" || echo -e "${YELLOW}⚠️ Warning: File $file not found, skipping...${NC}"
done

echo -e "\n${BLUE}🔐 Step 2: Extracting modulus values...${NC}"
CERT_MODULUS=$(openssl x509 -noout -modulus -in "$CERT_FILE" 2>/dev/null | openssl md5)
KEY_MODULUS=$(openssl rsa -noout -modulus -in "$KEY_FILE" 2>/dev/null | openssl md5)
CSR_MODULUS=$(openssl req -noout -modulus -in "$CSR_FILE" 2>/dev/null | openssl md5)

echo -e "${BLUE}  📄 Certificate Modulus (MD5): ${NC}${CERT_MODULUS}"
[[ -f "$KEY_FILE" ]] && echo -e "${BLUE}  🔑 Key Modulus (MD5): ${NC}${KEY_MODULUS}"
[[ -f "$CSR_FILE" ]] && echo -e "${BLUE}  📝 CSR Modulus (MD5): ${NC}${CSR_MODULUS}"

echo -e "\n${BLUE}📊 Step 3: Comparing modulus values...${NC}"
[[ "$CERT_MODULUS" == "$KEY_MODULUS" ]] && echo -e "${GREEN}✅ Certificate and Key match! 🎉${NC}" || echo -e "${RED}❌ Certificate and Key do NOT match! ❌${NC}"
[[ "$CERT_MODULUS" == "$CSR_MODULUS" ]] && echo -e "${GREEN}✅ Certificate and CSR match! 🎉${NC}" || echo -e "${RED}❌ Certificate and CSR do NOT match! ❌${NC}"

CERT_ISSUER=$(openssl x509 -in "$CERT_FILE" -noout -issuer 2>/dev/null | sed 's/^issuer=//' | awk '{$1=$1};1')
echo -e "\n${BLUE}📜 Step 4: Extracting Certificate Issuer...${NC}"
echo -e "${BLUE}  The issuer of the main certificate is:${NC} ${CERT_ISSUER}"

CHAIN_VALID=true

if [[ -f "$CHAIN_FILE" ]]; then
    echo -e "\n${BLUE}🔗 Step 5: Parsing and validating the chain from leaf to root...${NC}"
    csplit -z -f cert_ "$CHAIN_FILE" '/-----BEGIN CERTIFICATE-----/' '{*}' > /dev/null 2>&1

    declare -A CERT_SUBJECTS CERT_ISSUERS CERT_ORIGINAL_POSITIONS
    CERT_FILES=()

    for cert in cert_*; do
        SUBJECT=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//' | awk '{$1=$1};1')
        ISSUER=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//' | awk '{$1=$1};1')
        POS=$((10#${cert#cert_} + 1))

        CERT_SUBJECTS["$cert"]="$SUBJECT"
        CERT_ISSUERS["$cert"]="$ISSUER"
        CERT_ORIGINAL_POSITIONS["$cert"]=$POS
        CERT_FILES+=("$cert")
    done

    echo -e "\n${BLUE}🔍 Building chain starting from issuer of the main certificate...${NC}"
    CURRENT_ISSUER="$CERT_ISSUER"
    ORDERED_CHAIN=()
    USED_CERTS=()

    while true; do
        FOUND=false
        for cert in "${CERT_FILES[@]}"; do
            if [[ "${CERT_SUBJECTS[$cert]}" == "$CURRENT_ISSUER" && ! " ${USED_CERTS[*]} " =~ " $cert " ]]; then
                ORDERED_CHAIN+=("$cert")
                USED_CERTS+=("$cert")
                CURRENT_ISSUER="${CERT_ISSUERS[$cert]}"
                FOUND=true
                break
            fi
        done
        [[ "$FOUND" == false ]] && break
    done

    echo -e "\n${BLUE}🔎 Step-by-step Chain Validation:${NC}"
    for i in "${!ORDERED_CHAIN[@]}"; do
        CURRENT_CERT="${ORDERED_CHAIN[$i]}"
        NEXT_CERT="${ORDERED_CHAIN[$((i+1))]}"
        SUBJECT="${CERT_SUBJECTS[$CURRENT_CERT]}"
        ISSUER="${CERT_ISSUERS[$CURRENT_CERT]}"
        POS="${CERT_ORIGINAL_POSITIONS[$CURRENT_CERT]}"

        echo -e "${BLUE}  Certificate $((i+1)) (Original Position: $POS):${NC}"
        echo -e "    📜 Subject: $SUBJECT"
        echo -e "    🔗 Issuer:  $ISSUER"

        openssl x509 -in "$CURRENT_CERT" -noout -text | grep -q "CA:TRUE" && echo -e "    🛡️  CA: TRUE" || echo -e "    ⚠️  Not marked as CA"

        EXPIRY=$(openssl x509 -in "$CURRENT_CERT" -noout -enddate | cut -d= -f2)
        EXPIRY_TS=$(date -d "$EXPIRY" +%s)
        NOW_TS=$(date +%s)
        if (( EXPIRY_TS < NOW_TS )); then
            echo -e "    ❌ Expired on $EXPIRY"
            CHAIN_VALID=false
        elif (( EXPIRY_TS < NOW_TS + 2592000 )); then
            echo -e "    ⚠️  Will expire soon on $EXPIRY"
        else
            echo -e "    ⏳ Valid until $EXPIRY"
        fi

        SIG_ALG=$(openssl x509 -in "$CURRENT_CERT" -noout -text | grep "Signature Algorithm" | head -1)
        echo -e "    🔏 Signature Algorithm: $SIG_ALG"

        if [[ -n "$NEXT_CERT" ]]; then
            EXPECTED_ISSUER="${CERT_SUBJECTS[$NEXT_CERT]}"
            if [[ "$ISSUER" == "$EXPECTED_ISSUER" ]]; then
                echo -e "    ✅ Link to next certificate is valid"
            else
                echo -e "    ❌ Invalid chain link!"
                CHAIN_VALID=false
            fi
        else
            [[ "$SUBJECT" == "$ISSUER" ]] && echo -e "    ✅ Root certificate is self-signed" || {
                echo -e "    ❌ Final certificate is not self-signed!"
                CHAIN_VALID=false
            }
        fi
    done

    echo -e "\n${BLUE}🔍 Step 6: Does the chain match the certificate issuer?${NC}"
    FIRST_CERT="${ORDERED_CHAIN[0]}"
    FIRST_SUBJECT="${CERT_SUBJECTS[$FIRST_CERT]}"
    if [[ "$FIRST_SUBJECT" == "$CERT_ISSUER" ]]; then
        echo -e "${GREEN}✅ Chain starts with correct issuer.${NC}"
    else
        echo -e "${RED}❌ Chain does not start with main certificate's issuer.${NC}"
        CHAIN_VALID=false
    fi

    [[ "$CHAIN_VALID" == true ]] && echo -e "\n${GREEN}🎉 Step 7: Chain is fully valid!${NC}" || echo -e "\n${RED}❌ Chain validation failed.${NC}"

    rm -f cert_*
else
    echo -e "\n${YELLOW}⚠️ Step 5: Chain file not found, skipping chain validation.${NC}"
fi
