#!/bin/bash

# Define color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# Configuration
OUTPUT_DIR="./cert_analysis_results"
HTML_REPORT=false
JSON_OUTPUT=false
PARALLEL_CHECKS=4
TIMEOUT=10  # seconds for network operations

# Initialize variables
declare -A RESULTS
declare -a WARNINGS
declare -a ERRORS
START_TIME=$(date +%s)

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to print section headers
section_header() {
    echo -e "\n${BLUE}===== $1 =====${NC}"
}

# Function to print subsection headers
subsection() {
    echo -e "\n${CYAN}➤ $1${NC}"
}

# Function to print success messages
success() {
    echo -e "${GREEN}✓ $1${NC}"
    RESULTS["$2"]="SUCCESS: $1"
}

# Function to print warning messages
warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    RESULTS["$2"]="WARNING: $1"
    WARNINGS+=("$2: $1")
}

# Function to print error messages
error() {
    echo -e "${RED}✗ $1${NC}"
    RESULTS["$2"]="ERROR: $1"
    ERRORS+=("$2: $1")
}

# Function to print informational messages
info() {
    echo -e "${PURPLE}ℹ $1${NC}"
    RESULTS["$2"]="INFO: $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check SSL/TLS connection
check_ssl_connection() {
    local domain="$1"
    subsection "Testing SSL connection to $domain"
    
    local output
    output=$(timeout $TIMEOUT openssl s_client -connect "$domain:443" -servername "$domain" -showcerts </dev/null 2>&1)
    
    if [[ $? -eq 0 ]]; then
        success "Successfully established SSL connection" "ssl_connection"
        echo "$output" > "$OUTPUT_DIR/${domain}_connection.txt"
    else
        error "Failed to establish SSL connection" "ssl_connection"
    fi
}

# Function to check OCSP stapling
check_ocsp_stapling() {
    local cert_file="$1"
    subsection "Checking OCSP Stapling"
    
    local ocsp_url
    ocsp_url=$(openssl x509 -in "$cert_file" -noout -ocsp_uri 2>/dev/null)
    
    if [[ -z "$ocsp_url" ]]; then
        warning "No OCSP responder URI found in certificate" "ocsp_uri"
        return
    fi
    
    local host_header
    host_header=$(echo "$ocsp_url" | cut -d/ -f3)
    
    local output
    output=$(openssl ocsp -issuer "$CHAIN_FILE" -cert "$cert_file" -url "$ocsp_url" -header "Host" "$host_header" 2>&1)
    
    if echo "$output" | grep -q ": good"; then
        success "OCSP stapling check passed (good)" "ocsp_check"
    elif echo "$output" | grep -q ": revoked"; then
        error "Certificate has been revoked!" "ocsp_check"
    else
        warning "OCSP check failed or server doesn't support stapling" "ocsp_check"
    fi
    
    echo "$output" > "$OUTPUT_DIR/ocsp_check.txt"
}

# Function to check CRL
check_crl() {
    local cert_file="$1"
    subsection "Checking Certificate Revocation List (CRL)"
    
    local crl_urls
    crl_urls=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A4 'X509v3 CRL Distribution Points' | grep 'URI:' | cut -d: -f2-)
    
    if [[ -z "$crl_urls" ]]; then
        warning "No CRL distribution points found" "crl_check"
        return
    fi
    
    local has_crl_error=0
    while IFS= read -r url; do
        url=$(echo "$url" | tr -d '[:space:]')
        info "Downloading CRL from $url" "crl_download"
        
        local crl_file="${OUTPUT_DIR}/crl_$(echo "$url" | sha256sum | cut -d' ' -f1).der"
        
        if ! curl -s --fail "$url" --output "$crl_file"; then
            error "Failed to download CRL from $url" "crl_download"
            has_crl_error=1
            continue
        fi
        
        # Convert DER to PEM if needed
        if ! openssl crl -inform DER -in "$crl_file" -outform PEM -out "${crl_file}.pem" 2>/dev/null; then
            # Maybe it's already in PEM format
            mv "$crl_file" "${crl_file}.pem"
        fi
        
        local crl_output
        crl_output=$(openssl crl -inform PEM -in "${crl_file}.pem" -noout -text 2>/dev/null)
        
        if [[ -n "$crl_output" ]]; then
            success "CRL downloaded and parsed successfully" "crl_parse"
            echo "$crl_output" > "${crl_file}.txt"
            
            # Check if cert is revoked
            local serial
            serial=$(openssl x509 -in "$cert_file" -noout -serial | cut -d'=' -f2)
            
            if echo "$crl_output" | grep -q "$serial"; then
                error "Certificate serial $serial found in CRL (REVOKED)" "cert_revocation"
                has_crl_error=1
            else
                success "Certificate serial $serial not found in CRL (not revoked)" "cert_revocation"
            fi
        else
            error "Failed to parse CRL from $url" "crl_parse"
            has_crl_error=1
        fi
    done <<< "$crl_urls"
    
    if [[ $has_crl_error -eq 1 ]]; then
        warning "Some CRL checks failed" "crl_overall"
    else
        success "All CRL checks passed" "crl_overall"
    fi
}

# Function to check certificate transparency
check_certificate_transparency() {
    local domain="$1"
    subsection "Checking Certificate Transparency"
    
    if ! command_exists curl; then
        warning "curl not found, skipping CT checks" "ct_check"
        return
    fi
    
    local output
    output=$(curl -s "https://crt.sh/?q=${domain}" 2>&1)
    
    if [[ -z "$output" ]]; then
        warning "Failed to query crt.sh" "ct_query"
        return
    fi
    
    local count
    count=$(echo "$output" | grep -c "<TD>${domain}</TD>")
    
    if [[ $count -gt 0 ]]; then
        success "Found $count certificates in CT logs for ${domain}" "ct_presence"
        echo "$output" > "$OUTPUT_DIR/ct_results.html"
    else
        warning "No certificates found in CT logs for ${domain}" "ct_presence"
    fi
    
    # Check for embedded SCTs
    local scts
    scts=$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null | grep -A5 "CT Precertificate SCTs")
    
    if [[ -n "$scts" ]]; then
        success "Certificate contains embedded SCTs (Signed Certificate Timestamps)" "sct_embedded"
        echo "$scts" > "$OUTPUT_DIR/scts.txt"
    else
        warning "No embedded SCTs found in certificate" "sct_embedded"
    fi
}

# Function to check weak algorithms
check_weak_algorithms() {
    local cert_file="$1"
    subsection "Checking for Weak Algorithms"
    
    local weak_algs=("md2" "md4" "md5" "sha1")
    local has_weak_alg=0
    
    # Check signature algorithm
    local sig_alg
    sig_alg=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1)
    
    for alg in "${weak_algs[@]}"; do
        if echo "$sig_alg" | grep -qi "$alg"; then
            error "Weak signature algorithm detected: $sig_alg" "weak_algorithm"
            has_weak_alg=1
            break
        fi
    done
    
    if [[ $has_weak_alg -eq 0 ]]; then
        success "No weak signature algorithms detected" "weak_algorithm"
    fi
    
    # Check public key algorithm
    local pubkey_info
    pubkey_info=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -E "Public Key Algorithm|Public-Key")
    
    if echo "$pubkey_info" | grep -qi "rsa (1024 bit)"; then
        error "Weak RSA key size detected (1024-bit)" "weak_key_size"
        has_weak_alg=1
    elif echo "$pubkey_info" | grep -qi "rsa (2048 bit)"; then
        info "RSA 2048-bit key detected (acceptable)" "key_size"
    elif echo "$pubkey_info" | grep -qi "rsa (4096 bit)"; then
        success "Strong RSA key size detected (4096-bit)" "key_size"
    fi
    
    if [[ $has_weak_alg -eq 1 ]]; then
        warning "Weak cryptographic algorithms detected" "weak_algorithms_overall"
    else
        success "No weak cryptographic algorithms detected" "weak_algorithms_overall"
    fi
}

# Function to check HSTS header
check_hsts() {
    local domain="$1"
    subsection "Checking HTTP Strict Transport Security (HSTS)"
    
    if ! command_exists curl; then
        warning "curl not found, skipping HSTS check" "hsts_check"
        return
    fi
    
    local output
    output=$(curl -sI "https://${domain}" | grep -i "Strict-Transport-Security" 2>&1)
    
    if [[ -z "$output" ]]; then
        warning "HSTS header not present" "hsts_presence"
    else
        success "HSTS header present: $output" "hsts_presence"
        
        # Check for proper HSTS settings
        if echo "$output" | grep -qi "max-age=0"; then
            error "HSTS is disabled (max-age=0)" "hsts_config"
        elif echo "$output" | grep -qi "max-age="; then
            local max_age
            max_age=$(echo "$output" | grep -oi "max-age=[0-9]*" | cut -d= -f2)
            
            if [[ $max_age -ge 31536000 ]]; then
                success "HSTS properly configured (max-age=$max_age)" "hsts_config"
            else
                warning "HSTS max-age is less than 1 year ($max_age)" "hsts_config"
            fi
            
            if echo "$output" | grep -qi "includeSubdomains"; then
                success "HSTS includes subdomains" "hsts_scope"
            else
                info "HSTS doesn't include subdomains" "hsts_scope"
            fi
            
            if echo "$output" | grep -qi "preload"; then
                info "HSTS preload flag set" "hsts_preload"
            fi
        fi
    fi
}

# Function to check CAA records
check_caa() {
    local domain="$1"
    subsection "Checking CAA Records"
    
    if ! command_exists dig; then
        warning "dig not found, skipping CAA check" "caa_check"
        return
    fi
    
    local output
    output=$(dig "$domain" type257 +short 2>&1)
    
    if [[ -z "$output" ]]; then
        warning "No CAA records found (this may be okay depending on policy)" "caa_presence"
    else
        success "CAA records found:" "caa_presence"
        while IFS= read -r record; do
            info "$record" "caa_record"
        done <<< "$output"
    fi
}

# Function to check TLS versions
check_tls_versions() {
    local domain="$1"
    subsection "Testing Supported TLS Versions"
    
    local tls_versions=("ssl2" "ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
    local deprecated_versions=("ssl2" "ssl3" "tls1" "tls1_1")
    local weak_versions=("tls1_2")
    local strong_versions=("tls1_3")
    
    local has_deprecated=0
    local has_weak=0
    local has_strong=0
    
    for version in "${tls_versions[@]}"; do
        local output
        output=$(timeout $TIMEOUT openssl s_client -"$version" -connect "$domain:443" -servername "$domain" </dev/null 2>&1)
        
        if echo "$output" | grep -q "Protocol.*${version^^}"; then
            if [[ " ${deprecated_versions[*]} " =~ " $version " ]]; then
                error "Deprecated $version is supported" "tls_${version}"
                has_deprecated=1
            elif [[ " ${weak_versions[*]} " =~ " $version " ]]; then
                warning "Acceptable $version is supported" "tls_${version}"
                has_weak=1
            elif [[ " ${strong_versions[*]} " =~ " $version " ]]; then
                success "Modern $version is supported" "tls_${version}"
                has_strong=1
            fi
        else
            info "$version is not supported" "tls_${version}"
        fi
    done
    
    if [[ $has_deprecated -eq 1 ]]; then
        error "Server supports deprecated TLS versions" "tls_overall"
    elif [[ $has_strong -eq 1 ]]; then
        success "Server supports modern TLS versions" "tls_overall"
    else
        warning "Server only supports intermediate TLS versions" "tls_overall"
    fi
}

# Function to check cipher suites
check_ciphers() {
    local domain="$1"
    subsection "Testing Cipher Suites"
    
    local ciphers=(
        "ECDHE-ECDSA-AES256-GCM-SHA384"
        "ECDHE-RSA-AES256-GCM-SHA384"
        "ECDHE-ECDSA-CHACHA20-POLY1305"
        "ECDHE-RSA-CHACHA20-POLY1305"
        "ECDHE-ECDSA-AES128-GCM-SHA256"
        "ECDHE-RSA-AES128-GCM-SHA256"
        "ECDHE-ECDSA-AES256-SHA384"
        "ECDHE-RSA-AES256-SHA384"
        "ECDHE-ECDSA-AES128-SHA256"
        "ECDHE-RSA-AES128-SHA256"
        "DHE-RSA-AES256-GCM-SHA384"
        "DHE-RSA-AES128-GCM-SHA256"
        "AES256-GCM-SHA384"
        "AES128-GCM-SHA256"
        "AES256-SHA256"
        "AES128-SHA256"
    )
    
    local weak_ciphers=(
        "DES-CBC3-SHA"
        "RC4-SHA"
        "RC4-MD5"
        "CAMELLIA256-SHA"
        "CAMELLIA128-SHA"
        "AES256-SHA"
        "AES128-SHA"
        "DHE-DSS-AES256-SHA"
        "DHE-RSA-AES256-SHA"
        "DHE-DSS-AES128-SHA"
        "DHE-RSA-AES128-SHA"
    )
    
    local has_weak=0
    local has_strong=0
    
    # Test strong ciphers
    for cipher in "${ciphers[@]}"; do
        local output
        output=$(timeout $TIMEOUT openssl s_client -cipher "$cipher" -connect "$domain:443" -servername "$domain" </dev/null 2>&1)
        
        if echo "$output" | grep -q "Cipher.*${cipher}"; then
            success "Cipher $cipher is supported" "cipher_${cipher}"
            has_strong=1
        else
            info "Cipher $cipher is not supported" "cipher_${cipher}"
        fi
    done
    
    # Test weak ciphers
    for cipher in "${weak_ciphers[@]}"; do
        local output
        output=$(timeout $TIMEOUT openssl s_client -cipher "$cipher" -connect "$domain:443" -servername "$domain" </dev/null 2>&1)
        
        if echo "$output" | grep -q "Cipher.*${cipher}"; then
            error "Weak cipher $cipher is supported" "cipher_${cipher}"
            has_weak=1
        fi
    done
    
    if [[ $has_weak -eq 1 ]]; then
        error "Server supports weak cipher suites" "ciphers_overall"
    elif [[ $has_strong -eq 1 ]]; then
        success "Server supports strong cipher suites" "ciphers_overall"
    else
        warning "Server supports only intermediate cipher suites" "ciphers_overall"
    fi
}

# Function to check DNS resolution
check_dns_resolution() {
    local cert_file="$1"
    subsection "Checking DNS Resolution for SANs"
    
    local sans
    sans=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/DNS://g' | tr -d ' ' | tr ',' '\n')
    
    if [[ -z "$sans" ]]; then
        info "No Subject Alternative Names found" "sans_presence"
        return
    fi
    
    local has_dns_error=0
    while IFS= read -r domain; do
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        if host "$domain" >/dev/null 2>&1; then
            success "$domain resolves correctly" "dns_$domain"
        else
            error "$domain does not resolve" "dns_$domain"
            has_dns_error=1
        fi
    done <<< "$sans"
    
    if [[ $has_dns_error -eq 1 ]]; then
        error "Some domains in SAN do not resolve" "dns_overall"
    else
        success "All SAN domains resolve correctly" "dns_overall"
    fi
}

# Function to check certificate bundling
check_certificate_bundling() {
    local cert_file="$1"
    local chain_file="$2"
    subsection "Checking Certificate Bundling"
    
    if [[ ! -f "$chain_file" ]]; then
        warning "No chain file found, skipping bundling check" "bundling_check"
        return
    fi
    
    local output
    output=$(openssl verify -untrusted "$chain_file" "$cert_file" 2>&1)
    
    if echo "$output" | grep -q ": OK"; then
        success "Certificate chain is properly ordered" "bundling_order"
    else
        error "Certificate chain is not properly ordered" "bundling_order"
        info "Try reordering with: cat intermediate.crt root.crt > chain.crt" "bundling_fix"
    fi
    
    echo "$output" > "$OUTPUT_DIR/bundling_check.txt"
}

# Function to check heartbleed vulnerability
check_heartbleed() {
    local domain="$1"
    subsection "Checking for Heartbleed Vulnerability"
    
    local output
    output=$(timeout $TIMEOUT openssl s_client -connect "$domain:443" -tlsextdebug 2>&1 <<< "QUIT" | grep "heartbeat")
    
    if echo "$output" | grep -q "TLS server extension 'heartbeat' (id=15)"; then
        warning "Heartbeat extension detected (check if server is vulnerable)" "heartbleed_detection"
        info "Note: This doesn't necessarily mean the server is vulnerable to Heartbleed" "heartbleed_note"
    else
        success "No heartbeat extension detected (not vulnerable to Heartbleed)" "heartbleed_detection"
    fi
}

# Function to check public key info
check_public_key_info() {
    local cert_file="$1"
    subsection "Checking Public Key Information"
    
    local pubkey_info
    pubkey_info=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -E "Public Key Algorithm|Public-Key")
    
    if [[ -n "$pubkey_info" ]]; then
        success "$pubkey_info" "pubkey_info"
        
        # Check key length
        if echo "$pubkey_info" | grep -qi "rsa"; then
            local bits
            bits=$(echo "$pubkey_info" | grep -oi "[0-9]\+ bit")
            info "Key size: $bits" "pubkey_size"
            
            # Check if key size is sufficient
            local key_size
            key_size=$(echo "$bits" | cut -d' ' -f1)
            if [[ $key_size -lt 2048 ]]; then
                error "RSA key size ($key_size) is too small (minimum 2048 recommended)" "pubkey_strength"
            elif [[ $key_size -eq 2048 ]]; then
                warning "RSA key size (2048) is acceptable but consider upgrading to 3072 or 4096" "pubkey_strength"
            else
                success "RSA key size ($key_size) is strong" "pubkey_strength"
            fi
        fi
    else
        error "Could not extract public key information" "pubkey_info"
    fi
}

# Function to check certificate policies
check_certificate_policies() {
    local cert_file="$1"
    subsection "Checking Certificate Policies"
    
    local policies
    policies=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A5 "Certificate Policies")
    
    if [[ -n "$policies" ]]; then
        success "Certificate policies found:" "cert_policies"
        echo "$policies" | while read -r line; do
            info "$line" "cert_policy_detail"
        done
    else
        info "No certificate policies found" "cert_policies"
    fi
}

# Function to check certificate fingerprints
check_certificate_fingerprints() {
    local cert_file="$1"
    subsection "Checking Certificate Fingerprints"
    
    local sha1_fp
    sha1_fp=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha1 2>/dev/null | cut -d'=' -f2)
    local sha256_fp
    sha256_fp=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | cut -d'=' -f2)
    local md5_fp
    md5_fp=$(openssl x509 -in "$cert_file" -noout -fingerprint -md5 2>/dev/null | cut -d'=' -f2)
    
    success "SHA-1 Fingerprint: $sha1_fp" "fingerprint_sha1"
    success "SHA-256 Fingerprint: $sha256_fp" "fingerprint_sha256"
    warning "MD5 Fingerprint: $md5_fp (should not be used for security purposes)" "fingerprint_md5"
}

# Function to check certificate serial number
check_serial_number() {
    local cert_file="$1"
    subsection "Checking Certificate Serial Number"
    
    local serial
    serial=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null | cut -d'=' -f2)
    
    if [[ -n "$serial" ]]; then
        info "Serial Number: $serial" "serial_number"
        
        # Check if serial is suspiciously low (could be a test certificate)
        if [[ ${#serial} -lt 20 ]]; then
            warning "Short serial number detected (could be a test certificate)" "serial_quality"
        fi
        
        # Check if serial is negative (some CAs use negative serials)
        if [[ $serial == -* ]]; then
            info "Negative serial number detected (some CAs use this format)" "serial_format"
        fi
    else
        error "Could not extract serial number" "serial_number"
    fi
}

# Function to check CA issuers
check_ca_issuers() {
    local cert_file="$1"
    subsection "Checking CA Issuers"
    
    local ca_issuers
    ca_issuers=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Authority Information Access" | grep "CA Issuers")
    
    if [[ -n "$ca_issuers" ]]; then
        success "CA Issuers URL found:" "ca_issuers_presence"
        info "$ca_issuers" "ca_issuers_url"
    else
        warning "No CA Issuers URL found" "ca_issuers_presence"
    fi
}

# Function to calculate certificate age
check_certificate_age() {
    local cert_file="$1"
    subsection "Checking Certificate Age"
    
    local not_before
    not_before=$(openssl x509 -in "$cert_file" -noout -startdate 2>/dev/null | cut -d'=' -f2)
    local not_after
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d'=' -f2)
    
    if [[ -z "$not_before" || -z "$not_after" ]]; then
        error "Could not extract certificate dates" "cert_dates"
        return
    fi
    
    local start_epoch
    start_epoch=$(date -d "$not_before" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_before" +%s 2>/dev/null)
    local end_epoch
    end_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
    
    if [[ -z "$start_epoch" || -z "$end_epoch" ]]; then
        error "Could not parse certificate dates" "cert_date_parsing"
        return
    fi
    
    local total_seconds=$((end_epoch - start_epoch))
    local days=$((total_seconds / 86400))
    
    info "Certificate valid for $days days" "cert_validity_period"
    
    # Check if certificate is valid for too long (more than 397 days)
    if [[ $days -gt 397 ]]; then
        warning "Certificate validity period exceeds 397 days (may not be trusted by all browsers)" "cert_validity_length"
    fi
    
    # Calculate days remaining
    local now_epoch
    now_epoch=$(date +%s)
    local remaining_seconds=$((end_epoch - now_epoch))
    local remaining_days=$((remaining_seconds / 86400))
    
    if [[ $remaining_seconds -lt 0 ]]; then
        error "Certificate expired $((remaining_days * -1)) days ago" "cert_expiry"
    else
        success "Certificate valid for $remaining_days more days" "cert_expiry"
        
        if [[ $remaining_days -lt 30 ]]; then
            warning "Certificate will expire soon (in $remaining_days days)" "cert_expiry_soon"
        fi
    fi
}

# Function to generate HTML report
generate_html_report() {
    local output_file="$OUTPUT_DIR/report.html"
    
    cat > "$output_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 10px; }
        h3 { color: #16a085; margin-top: 20px; }
        .success { color: #27ae60; font-weight: bold; }
        .warning { color: #f39c12; font-weight: bold; }
        .error { color: #e74c3c; font-weight: bold; }
        .info { color: #3498db; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; text-align: right; }
    </style>
</head>
<body>
    <h1>Certificate Analysis Report</h1>
    <div class="timestamp">Generated on $(date)</div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Certificate File:</strong> $CERT_FILE</p>
        <p><strong>Total Checks:</strong> ${#RESULTS[@]}</p>
        <p><strong>Warnings:</strong> ${#WARNINGS[@]}</p>
        <p><strong>Errors:</strong> ${#ERRORS[@]}</p>
    </div>
EOF

    # Add results sections
    echo "<h2>Detailed Results</h2>" >> "$output_file"
    echo "<table>" >> "$output_file"
    echo "<tr><th>Check</th><th>Result</th></tr>" >> "$output_file"
    
    for key in "${!RESULTS[@]}"; do
        local result="${RESULTS[$key]}"
        local class="info"
        
        if [[ "$result" == SUCCESS:* ]]; then
            class="success"
            result="${result#SUCCESS: }"
        elif [[ "$result" == WARNING:* ]]; then
            class="warning"
            result="${result#WARNING: }"
        elif [[ "$result" == ERROR:* ]]; then
            class="error"
            result="${result#ERROR: }"
        elif [[ "$result" == INFO:* ]]; then
            result="${result#INFO: }"
        fi
        
        echo "<tr><td>$key</td><td class=\"$class\">$result</td></tr>" >> "$output_file"
    done
    
    echo "</table>" >> "$output_file"
    
    # Add warnings section if any
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo "<h2>Warnings</h2>" >> "$output_file"
        echo "<ul>" >> "$output_file"
        for warning in "${WARNINGS[@]}"; do
            echo "<li>$warning</li>" >> "$output_file"
        done
        echo "</ul>" >> "$output_file"
    fi
    
    # Add errors section if any
    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo "<h2>Errors</h2>" >> "$output_file"
        echo "<ul>" >> "$output_file"
        for error in "${ERRORS[@]}"; do
            echo "<li>$error</li>" >> "$output_file"
        done
        echo "</ul>" >> "$output_file"
    fi
    
    # Add command output files if any
    local has_outputs=false
    for file in "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.html; do
        if [[ -f "$file" && "$file" != "$output_file" ]]; then
            if [[ "$has_outputs" == false ]]; then
                echo "<h2>Command Outputs</h2>" >> "$output_file"
                has_outputs=true
            fi
            
            local filename=$(basename "$file")
            echo "<h3>$filename</h3>" >> "$output_file"
            echo "<pre>" >> "$output_file"
            cat "$file" | sed 's/</\&lt;/g; s/>/\&gt;/g' >> "$output_file"
            echo "</pre>" >> "$output_file"
        fi
    done
    
    # Finish the HTML
    cat >> "$output_file" <<EOF
</body>
</html>
EOF

    success "HTML report generated: $output_file" "html_report"
}

# Function to generate JSON report
generate_json_report() {
    local output_file="$OUTPUT_DIR/report.json"
    
    echo "{" > "$output_file"
    echo "  \"metadata\": {" >> "$output_file"
    echo "    \"generated\": \"$(date -Is)\"," >> "$output_file"
    echo "    \"certificate\": \"$CERT_FILE\"," >> "$output_file"
    echo "    \"total_checks\": ${#RESULTS[@]}," >> "$output_file"
    echo "    \"warnings\": ${#WARNINGS[@]}," >> "$output_file"
    echo "    \"errors\": ${#ERRORS[@]}" >> "$output_file"
    echo "  }," >> "$output_file"
    
    echo "  \"results\": {" >> "$output_file"
    local first=true
    for key in "${!RESULTS[@]}"; do
        if [[ "$first" == false ]]; then
            echo "," >> "$output_file"
        else
            first=false
        fi
        
        local result="${RESULTS[$key]}"
        local status="info"
        
        if [[ "$result" == SUCCESS:* ]]; then
            status="success"
            result="${result#SUCCESS: }"
        elif [[ "$result" == WARNING:* ]]; then
            status="warning"
            result="${result#WARNING: }"
        elif [[ "$result" == ERROR:* ]]; then
            status="error"
            result="${result#ERROR: }"
        elif [[ "$result" == INFO:* ]]; then
            result="${result#INFO: }"
        fi
        
        echo -n "    \"$key\": {\"status\": \"$status\", \"message\": \"$result\"}" >> "$output_file"
    done
    echo >> "$output_file"
    echo "  }," >> "$output_file"
    
    # Add warnings array
    echo "  \"warnings\": [" >> "$output_file"
    for ((i=0; i<${#WARNINGS[@]}; i++)); do
        if [[ $i -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        echo "    \"${WARNINGS[$i]}\"" >> "$output_file"
    done
    echo "  ]," >> "$output_file"
    
    # Add errors array
    echo "  \"errors\": [" >> "$output_file"
    for ((i=0; i<${#ERRORS[@]}; i++)); do
        if [[ $i -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        echo "    \"${ERRORS[$i]}\"" >> "$output_file"
    done
    echo "  ]" >> "$output_file"
    
    echo "}" >> "$output_file"
    
    success "JSON report generated: $output_file" "json_report"
}

# Main execution
main() {
    # Input validation
    if [[ $# -ne 1 ]]; then
        echo -e "${RED}Usage: $0 <certificate file (.pem/.crt/.cer)>${NC}"
        exit 1
    fi

    if [[ ! -f "$1" ]]; then
        error "File '$1' does not exist" "file_existence"
        exit 1
    fi

    if [[ "$1" != *.pem && "$1" != *.crt && "$1" != *.cer ]]; then
        warning "File extension not recognized (expected .pem/.crt/.cer)" "file_extension"
    fi

    CERT_FILE="$1"
    BASENAME="${CERT_FILE%.*}"
    CSR_FILE="$BASENAME.csr"
    KEY_FILE="$BASENAME.key"
    CHAIN_FILE="$BASENAME.chain"

    # Extract domain from certificate
    DOMAIN=$(openssl x509 -in "$CERT_FILE" -noout -subject 2>/dev/null | sed 's/^.*CN=//; s/,.*$//')

    if [[ -z "$DOMAIN" ]]; then
        DOMAIN=$(openssl x509 -in "$CERT_FILE" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/DNS://g' | cut -d',' -f1 | tr -d ' ')
    fi

    if [[ -z "$DOMAIN" ]]; then
        DOMAIN="unknown_domain"
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Set trap for cleanup
    trap 'rm -f cert_* 2>/dev/null' EXIT

    section_header "Starting Certificate Analysis"
    info "Analyzing certificate: $CERT_FILE" "certificate_file"
    if [[ -n "$DOMAIN" && "$DOMAIN" != "unknown_domain" ]]; then
        info "Primary domain: $DOMAIN" "primary_domain"
    fi

    # Run all checks
    check_ssl_connection "$DOMAIN"
    check_ocsp_stapling "$CERT_FILE"
    check_crl "$CERT_FILE"
    check_certificate_transparency "$DOMAIN"
    check_weak_algorithms "$CERT_FILE"
    check_hsts "$DOMAIN"
    check_caa "$DOMAIN"
    check_tls_versions "$DOMAIN"
    check_ciphers "$DOMAIN"
    check_dns_resolution "$CERT_FILE"
    check_certificate_bundling "$CERT_FILE" "$CHAIN_FILE"
    check_heartbleed "$DOMAIN"
    check_public_key_info "$CERT_FILE"
    check_certificate_policies "$CERT_FILE"
    check_certificate_fingerprints "$CERT_FILE"
    check_serial_number "$CERT_FILE"
    check_ca_issuers "$CERT_FILE"
    check_certificate_age "$CERT_FILE"

    # Generate reports
    generate_html_report
    generate_json_report

    # Calculate and display execution time
    END_TIME=$(date +%s)
    EXECUTION_TIME=$((END_TIME - START_TIME))
    section_header "Analysis Complete"
    info "Execution time: ${EXECUTION_TIME} seconds" "execution_time"

    # Display summary
    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        echo -e "\n${RED}✗ Found ${#ERRORS[@]} errors that need attention${NC}"
    fi
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}⚠ Found ${#WARNINGS[@]} warnings to review${NC}"
    fi
    if [[ ${#ERRORS[@]} -eq 0 && ${#WARNINGS[@]} -eq 0 ]]; then
        echo -e "\n${GREEN}✓ No critical issues found${NC}"
    fi

    exit 0
}

# Start main execution
main "$@"