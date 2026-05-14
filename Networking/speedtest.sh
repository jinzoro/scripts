#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
CONFIG_FILE="$HOME/.speedtest_config"
TEMP_FILE="/tmp/speedtest_temp"
OUTPUT_FILE="speedtest_report_$(date +%Y%m%d_%H%M%S).txt"
VERBOSE=false
JSON_OUTPUT=false
TEST_SERVERS=(
    "speedtest.net"
    "fast.com"
    "speed.cloudflare.com"
    "speed.hetzner.com"
)
TEST_URLS=(
    "http://google.com"
    "http://facebook.com"
    "http://youtube.com"
    "http://amazon.com"
    "http://wikipedia.org"
    "https://github.com"
    "https://gitlab.com"
)
PING_TARGETS=(
    "8.8.8.8"       # Google DNS
    "1.1.1.1"       # Cloudflare DNS
    "9.9.9.9"       # Quad9 DNS
    "208.67.222.222" # OpenDNS
)
TRACEROUTE_TARGET="google.com"
PORT_TEST_SERVERS=(
    "google.com:80"
    "cloudflare.com:443"
    "github.com:22"
)
DOWNLOAD_TEST_FILES=(
    "http://ipv4.download.thinkbroadband.com/100MB.zip"
    "http://speedtest.tele2.net/100MB.zip"
    "http://testdebit.free.fr/100Mo.dat"
)
UPLOAD_TEST_FILE="/tmp/speedtest_upload.test"
UPLOAD_TEST_SIZE=50 # in MB

# Create a large file for upload testing
dd if=/dev/zero of="$UPLOAD_TEST_FILE" bs=1M count=$UPLOAD_TEST_SIZE &>/dev/null

# Load configuration if exists
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Functions
print_header() {
    echo -e "${PURPLE}"
    echo "=============================================="
    echo "          ADVANCED NETWORK SPEED TEST         "
    echo "=============================================="
    echo -e "${NC}"
    echo -e "Date: ${CYAN}$(date)${NC}"
    echo -e "Hostname: ${CYAN}$(hostname)${NC}"
    echo
}

print_footer() {
    echo
    echo -e "${PURPLE}=============================================="
    echo "           TEST COMPLETED SUCCESSFULLY        "
    echo "=============================================="
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_result() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo "{\"test\":\"$1\",\"result\":\"$2\",\"unit\":\"$3\",\"details\":\"$4\"}"
    else
        if [ "$3" == "FAIL" ]; then
            echo -e "${RED}[FAIL]${NC} $1"
        elif [ "$3" == "PASS" ]; then
            echo -e "${GREEN}[PASS]${NC} $1"
        else
            echo -e "[$3] $1: ${CYAN}$2${NC} $4"
        fi
    fi
}

check_dependencies() {
    local missing=()
    local tools=("curl" "wget" "ping" "traceroute" "dig" "mtr" "openssl" "iperf3" "speedtest-cli" "jq")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing dependencies:${NC} ${missing[*]}"
        echo "Please install them before running this script."
        exit 1
    fi
}

get_public_ip() {
    local ipv4=$(curl -4 -s https://api.ipify.org?format=json | jq -r '.ip')
    local ipv6=$(curl -6 -s https://api.ipify.org?format=json | jq -r '.ip' 2>/dev/null || echo "N/A")
    
    print_result "Public IPv4" "$ipv4" "INFO"
    print_result "Public IPv6" "$ipv6" "INFO"
    
    # Get IP information
    if [ "$ipv4" != "" ]; then
        local ip_info=$(curl -s "http://ip-api.com/json/$ipv4")
        local country=$(echo "$ip_info" | jq -r '.country // "N/A"')
        local region=$(echo "$ip_info" | jq -r '.regionName // "N/A"')
        local city=$(echo "$ip_info" | jq -r '.city // "N/A"')
        local isp=$(echo "$ip_info" | jq -r '.isp // "N/A"')
        local org=$(echo "$ip_info" | jq -r '.org // "N/A"')
        local as=$(echo "$ip_info" | jq -r '.as // "N/A"')
        
        print_result "Location" "$city, $region, $country" "INFO"
        print_result "ISP" "$isp" "INFO"
        print_result "Organization" "$org" "INFO"
        print_result "AS Number" "$as" "INFO"
    fi
}

run_ping_tests() {
    print_section "PING TESTS"
    
    for target in "${PING_TARGETS[@]}"; do
        local result=$(ping -c 4 "$target" | tail -n 2)
        local avg_ping=$(echo "$result" | grep rtt | awk -F'/' '{print $5}')
        local packet_loss=$(echo "$result" | grep packet | awk '{print $6}')
        
        if [ -z "$avg_ping" ]; then
            print_result "Ping to $target" "Failed" "FAIL"
        else
            print_result "Ping to $target" "$avg_ping" "INFO" "ms (loss: $packet_loss)"
        fi
    done
}

run_traceroute() {
    print_section "TRACEROUTE TEST"
    
    if command -v mtr &>/dev/null; then
        print_result "Running MTR (traceroute alternative)" "" "INFO"
        mtr --report --report-cycles 5 "$TRACEROUTE_TARGET"
    else
        print_result "Running traceroute to $TRACEROUTE_TARGET" "" "INFO"
        traceroute "$TRACEROUTE_TARGET"
    fi
}

test_network_ports() {
    print_section "NETWORK PORT TESTING"
    
    for server in "${PORT_TEST_SERVERS[@]}"; do
        local host=$(echo "$server" | cut -d: -f1)
        local port=$(echo "$server" | cut -d: -f2)
        
        if timeout 2 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
            print_result "Port $port on $host" "Open" "PASS"
        else
            print_result "Port $port on $host" "Closed/Filtered" "FAIL"
        fi
    done
}

test_url_access() {
    print_section "URL ACCESS TEST"
    
    for url in "${TEST_URLS[@]}"; do
        local http_code=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "$url")
        
        if [ "$http_code" == "200" ] || [ "$http_code" == "301" ] || [ "$http_code" == "302" ]; then
            print_result "Access to $url" "Success (HTTP $http_code)" "PASS"
        else
            print_result "Access to $url" "Failed (HTTP $http_code)" "FAIL"
        fi
    done
}

run_download_speed_tests() {
    print_section "DOWNLOAD SPEED TESTS"
    
    for file in "${DOWNLOAD_TEST_FILES[@]}"; do
        local domain=$(echo "$file" | awk -F/ '{print $3}')
        print_result "Testing download from $domain" "" "INFO"
        
        local speed=$(wget -O /dev/null "$file" 2>&1 | grep -oP '\d+\.\d+ [KM]B/s')
        if [ -z "$speed" ]; then
            print_result "Download test failed" "" "FAIL"
        else
            print_result "Download speed" "$speed" "INFO"
        fi
    done
}

run_upload_speed_test() {
    print_section "UPLOAD SPEED TEST"
    
    # Using iperf3 for more accurate upload testing
    if command -v iperf3 &>/dev/null; then
        print_result "Running iperf3 upload test (to public server)" "" "INFO"
        iperf3 -c speedtest.serverius.net -p 5002 -t 10 -O 2 -i 0
    else
        # Fallback to curl upload test
        print_result "Running curl upload test" "" "INFO"
        local speed=$(curl -o /dev/null --upload-file "$UPLOAD_TEST_FILE" "http://speedtest.tele2.net/upload.php" 2>&1 | grep -oP '\d+\.\d+ [KM]B/s')
        if [ -z "$speed" ]; then
            print_result "Upload test failed" "" "FAIL"
        else
            print_result "Upload speed" "$speed" "INFO"
        fi
    fi
}

run_speedtest_cli() {
    print_section "OFFICIAL SPEEDTEST.NET TEST"
    
    local result=$(speedtest-cli --json 2>/dev/null)
    if [ -z "$result" ]; then
        print_result "Speedtest.net test failed" "" "FAIL"
        return
    fi
    
    local download=$(echo "$result" | jq -r '.download / 1000000')
    local upload=$(echo "$result" | jq -r '.upload / 1000000')
    local ping=$(echo "$result" | jq -r '.ping')
    local server=$(echo "$result" | jq -r '.server.name')
    local server_location=$(echo "$result" | jq -r '.server.country')
    local isp=$(echo "$result" | jq -r '.client.isp')
    local ip=$(echo "$result" | jq -r '.client.ip')
    
    print_result "Server" "$server ($server_location)" "INFO"
    print_result "Ping" "$ping ms" "INFO"
    print_result "Download speed" "$download Mbps" "INFO"
    print_result "Upload speed" "$upload Mbps" "INFO"
    print_result "Your IP" "$ip" "INFO"
    print_result "Your ISP" "$isp" "INFO"
}

test_streaming_services() {
    print_section "STREAMING SERVICE TESTING"
    
    # Netflix
    local netflix=$(curl -s -o /dev/null -L -w "%{http_code}" "https://www.netflix.com" --max-time 5)
    if [ "$netflix" == "200" ] || [ "$netflix" == "301" ] || [ "$netflix" == "302" ]; then
        print_result "Netflix access" "Available" "PASS"
    else
        print_result "Netflix access" "Blocked/Unavailable" "FAIL"
    fi
    
    # YouTube
    local youtube=$(curl -s -o /dev/null -L -w "%{http_code}" "https://www.youtube.com" --max-time 5)
    if [ "$youtube" == "200" ] || [ "$youtube" == "301" ] || [ "$youtube" == "302" ]; then
        print_result "YouTube access" "Available" "PASS"
    else
        print_result "YouTube access" "Blocked/Unavailable" "FAIL"
    fi
    
    # Amazon Prime
    local prime=$(curl -s -o /dev/null -L -w "%{http_code}" "https://www.primevideo.com" --max-time 5)
    if [ "$prime" == "200" ] || [ "$prime" == "301" ] || [ "$prime" == "302" ]; then
        print_result "Amazon Prime access" "Available" "PASS"
    else
        print_result "Amazon Prime access" "Blocked/Unavailable" "FAIL"
    fi
}

test_dns_resolution() {
    print_section "DNS RESOLUTION TEST"
    
    for domain in "google.com" "facebook.com" "cloudflare.com"; do
        local dns_result=$(dig +short "$domain" | head -n 1)
        if [ -z "$dns_result" ]; then
            print_result "DNS resolution for $domain" "Failed" "FAIL"
        else
            print_result "DNS resolution for $domain" "$dns_result" "PASS"
        fi
    done
    
    # Test DNS servers
    for dns in "8.8.8.8" "1.1.1.1" "9.9.9.9"; do
        local query_time=$(dig @"$dns" google.com | grep "Query time:" | awk '{print $4}')
        print_result "DNS query time using $dns" "$query_time ms" "INFO"
    done
}

test_ssl_tls() {
    print_section "SSL/TLS TESTING"
    
    for domain in "google.com" "cloudflare.com" "github.com"; do
        local ssl_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates)
        if [ -z "$ssl_info" ]; then
            print_result "SSL test for $domain" "Failed" "FAIL"
        else
            local expiry_date=$(echo "$ssl_info" | grep "notAfter" | cut -d= -f2)
            print_result "SSL certificate for $domain" "Valid until $expiry_date" "PASS"
        fi
    done
}

save_results() {
    if [ "$JSON_OUTPUT" = true ]; then
        echo "Results are in JSON format (redirect output to a file)"
    else
        echo -e "\n${GREEN}Saving results to $OUTPUT_FILE${NC}"
        exec > >(tee "$OUTPUT_FILE") 2>&1
    fi
}

show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -v, --verbose    Show detailed output"
    echo "  -j, --json       Output in JSON format"
    echo "  -o FILE          Save output to FILE"
    echo "  -h, --help       Show this help message"
    echo
    echo "This script performs comprehensive network speed tests and diagnostics."
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -j|--json)
            JSON_OUTPUT=true
            shift
            ;;
        -o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    check_dependencies
    print_header
    
    if [ "$JSON_OUTPUT" = true ]; then
        echo "["
    fi
    
    get_public_ip
    run_ping_tests
    run_traceroute
    test_network_ports
    test_url_access
    run_download_speed_tests
    run_upload_speed_test
    run_speedtest_cli
    test_streaming_services
    test_dns_resolution
    test_ssl_tls
    
    if [ "$JSON_OUTPUT" = true ]; then
        echo "]"
    fi
    
    print_footer
    
    # Clean up
    rm -f "$UPLOAD_TEST_FILE"
}

# Run main function and save results if requested
if [ -n "$OUTPUT_FILE" ]; then
    save_results
fi

main