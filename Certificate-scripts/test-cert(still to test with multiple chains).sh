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
BASENAME="${CERT_FILE%.*}"  # Get base name without extension

CSR_FILE="$BASENAME.csr"
KEY_FILE="$BASENAME.key"
CHAIN_FILE="$BASENAME.chain"

# Step 1: Check if required files exist
echo -e "\n${BLUE}🔍 Step 1: Checking for related files...${NC}"
for file in "$CSR_FILE" "$KEY_FILE" "$CHAIN_FILE"; do
    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}⚠️ Warning: File $file not found, skipping...${NC}"
    else
        echo -e "${GREEN}✅ Found: $file${NC}"
    fi
done

# Step 2: Extract modulus from cert, key, and CSR
echo -e "\n${BLUE}🔐 Step 2: Extracting modulus values...${NC}"
CERT_MODULUS=$(openssl x509 -noout -modulus -in "$CERT_FILE" 2>/dev/null | openssl md5)
KEY_MODULUS=$(openssl rsa -noout -modulus -in "$KEY_FILE" 2>/dev/null | openssl md5)
CSR_MODULUS=$(openssl req -noout -modulus -in "$CSR_FILE" 2>/dev/null | openssl md5)

# Display modulus details
echo -e "${BLUE}  📄 Certificate Modulus (MD5): ${NC}${CERT_MODULUS}"
if [[ -f "$KEY_FILE" ]]; then
    echo -e "${BLUE}  🔑 Key Modulus (MD5): ${NC}${KEY_MODULUS}"
else
    echo -e "${YELLOW}⚠️ Key file not found, skipping modulus comparison.${NC}"
fi
if [[ -f "$CSR_FILE" ]]; then
    echo -e "${BLUE}  📝 CSR Modulus (MD5): ${NC}${CSR_MODULUS}"
else
    echo -e "${YELLOW}⚠️ CSR file not found, skipping modulus comparison.${NC}"
fi

# Step 3: Compare modulus values
echo -e "\n${BLUE}📊 Step 3: Comparing modulus values...${NC}"
if [[ "$CERT_MODULUS" == "$KEY_MODULUS" ]]; then
    echo -e "${GREEN}✅ Certificate and Key match! 🎉${NC}"
else
    echo -e "${RED}❌ Certificate and Key do NOT match! ❌${NC}"
fi

if [[ "$CERT_MODULUS" == "$CSR_MODULUS" ]]; then
    echo -e "${GREEN}✅ Certificate and CSR match! 🎉${NC}"
else
    echo -e "${RED}❌ Certificate and CSR do NOT match! ❌${NC}"
fi

# Step 4: Extract issuer from certificate
CERT_ISSUER=$(openssl x509 -in "$CERT_FILE" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
CERT_ISSUER=$(echo "$CERT_ISSUER" | awk '{$1=$1};1') # Trim leading/trailing spaces

# Display certificate issuer
echo -e "\n${BLUE}📜 Step 4: Extracting Certificate Issuer...${NC}"
echo -e "${BLUE}  The issuer of the main certificate is:${NC} ${CERT_ISSUER}"

# Step 5: Check the chain file for multiple certificates
if [[ -f "$CHAIN_FILE" ]]; then
    echo -e "\n${BLUE}🔗 Step 5: Parsing chain file for multiple certificates...${NC}"
    
    # Split the chain file into individual certificates
    csplit -z -f cert_ "$CHAIN_FILE" '/-----BEGIN CERTIFICATE-----/' '{*}' > /dev/null 2>&1
    
    # Initialize variables for chain validation
    PREVIOUS_SUBJECT=""
    CHAIN_VALID=true
    CERT_COUNT=0
    
    # Loop through each certificate in the chain
    for cert in cert_*; do
        ((CERT_COUNT++))
        echo -e "\n${BLUE}  🔍 Processing Certificate #$CERT_COUNT in the Chain...${NC}"
        
        # Extract subject and issuer of the current certificate
        CURRENT_SUBJECT=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//' | awk '{$1=$1};1')
        CURRENT_ISSUER=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//' | awk '{$1=$1};1')
        
        # Display details of the current certificate
        echo -e "${BLUE}    📜 Certificate Subject: ${NC}${CURRENT_SUBJECT}"
        echo -e "${BLUE}    🔗 Certificate Issuer: ${NC}${CURRENT_ISSUER}"
        
        # Compare the current certificate's subject with the previous certificate's issuer
        if [[ -n "$PREVIOUS_SUBJECT" && "$PREVIOUS_SUBJECT" != "$CURRENT_ISSUER" ]]; then
            echo -e "${RED}    ❌ Chain mismatch detected!${NC}"
            echo -e "${RED}      Expected issuer:   ${PREVIOUS_SUBJECT}${NC}"
            echo -e "${RED}      Current issuer:    ${CURRENT_ISSUER}${NC}"
            CHAIN_VALID=false
        fi
        
        # Update the previous subject for the next iteration
        PREVIOUS_SUBJECT="$CURRENT_SUBJECT"
    done
    
    # Clean up temporary certificate files
    rm -f cert_*
    
    # Step 6: Compare the last certificate's subject with the main certificate's issuer
    echo -e "\n${BLUE}🔗 Step 6: Validating the final link in the chain...${NC}"
    if [[ "$CHAIN_VALID" == true && "$CERT_ISSUER" != "$PREVIOUS_SUBJECT" ]]; then
        echo -e "${RED}❌ Chain does NOT match the main certificate! ❌${NC}"
        echo -e "${RED}  Expected issuer:   ${CERT_ISSUER}${NC}"
        echo -e "${RED}  Last chain cert:   ${PREVIOUS_SUBJECT}${NC}"
        CHAIN_VALID=false
    fi
    
    # Final result for the chain validation
    if [[ "$CHAIN_VALID" == true ]]; then
        echo -e "\n${GREEN}✅ Step 7: Chain is valid and matches the main certificate! 🎉${NC}"
    else
        echo -e "\n${RED}❌ Step 7: Chain validation failed! ❌${NC}"
    fi
else
    echo -e "\n${YELLOW}⚠️ Step 5: Chain file not found, skipping chain validation.${NC}"
fi