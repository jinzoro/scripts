#!/bin/bash
#
# Name:         parse_certs.sh
# Description:  A script to read a file containing one or more PEM-encoded
#               certificates and display key details for each one.
# Author:       Gemini
# Usage:        ./parse_certs.sh <path_to_certificate_bundle>
#
#-------------------------------------------------------------------------------

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u

# --- Configuration ---
# Ensure the openssl command is available on the system.
OPENSSL_CMD=$(command -v openssl)

# --- Functions ---

# Displays a usage message for the script.
function show_usage() {
    echo "Usage: $(basename "$0") <path_to_certificate_bundle_file>"
    echo "  - Reads a file containing one or more PEM certificates and prints their details."
}

# --- Pre-flight Checks ---

# Check if openssl is installed.
if [ -z "$OPENSSL_CMD" ]; then
    echo "Error: 'openssl' command not found. Please install OpenSSL." >&2
    exit 1
fi

# Check if the correct number of arguments is provided.
# Also handles requests for help.
if [ "$#" -ne 1 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    show_usage
    exit 0
fi

CERT_FILE="$1"

# Check if the provided file exists and is a regular file.
if [ ! -f "$CERT_FILE" ]; then
    echo "Error: File not found at '$CERT_FILE'" >&2
    exit 1
fi

# --- Main Logic ---

# We use 'awk' to process the certificate file because it is highly effective
# at handling text in records or blocks. The logic is as follows:
# 1. The 'BEGIN' block initializes a counter and defines the openssl command.
# 2. When a line matching "-----BEGIN CERTIFICATE-----" is found, we clear a buffer variable.
# 3. We append every subsequent line to this buffer.
# 4. When a line matching "-----END CERTIFICATE-----" is found, it signals the end of a
#    complete certificate block.
# 5. We then pipe the buffered certificate content into the 'openssl' command for parsing.
# 6. 'close(cmd)' is crucial to reset the pipe, allowing 'awk' to process the next
#    certificate in the file correctly.
# 7. The 'END' block runs after the file is fully processed to print a summary.

awk '
  BEGIN {
    cert_count = 0;
    # The openssl command to extract the required fields.
    # The "-dates" option conveniently provides both notBefore (issue) and notAfter (expiry).
    cmd = "openssl x509 -noout -subject -issuer -dates";
  }

  # When the start of a certificate is found, clear the buffer.
  /-----BEGIN CERTIFICATE-----/ {
    buffer = "";
  }

  # Append the current line to our buffer.
  {
    buffer = buffer $0 "\n";
  }

  # When the end of a certificate is found, process the buffered content.
  /-----END CERTIFICATE-----/ {
    cert_count++;
    print "========================================";
    print "           Certificate #" cert_count;
    print "========================================";
    
    # Pipe the complete certificate block from our buffer into the openssl command.
    print buffer | cmd;
    
    # It is critical to close the command pipe so that awk can start a
    # new one for the next certificate block. Otherwise, it would only
    # process the first certificate.
    close(cmd);

    # Add a blank line for better readability between entries.
    print "";
  }

  END {
    print "----------------------------------------";
    if (cert_count > 0) {
      print "Finished. Found and processed " cert_count " certificate(s).";
    } else {
      print "No valid certificate blocks found in the file.";
    }
    print "----------------------------------------";
  }
' "$CERT_FILE"