# Scripts

A personal collection of shell scripts for certificate analysis, SSL/TLS inspection, and network utilities.

## Structure

```
scripts/
├── Certificate-scripts/   # TLS/SSL certificate inspection and analysis
└── Networking/            # Network diagnostic and testing utilities
```

## Certificate Scripts

| Script | Description |
|--------|-------------|
| `analyze-cert-pro.sh` | Advanced certificate analyzer — checks validity, chain, SANs, and expiry with colored output; supports HTML/JSON reports and parallel checks |
| `parse_certs.sh` | Parses a PEM bundle and prints key details (subject, issuer, validity, SANs) for each certificate in the file |
| `sslyze-bulk.sh` | Runs `sslyze` against a list of domains checking TLS versions, cipher suites, heartbleed, ROBOT, and more; saves per-domain logs |
| `sslyze-bulk-lb.sh` | Variant of `sslyze-bulk.sh` targeting load balancer endpoints |
| `test-cert.sh` | Validates a certificate file against its paired key and chain; confirms they match |

**Dependencies:** `openssl`, [`sslyze`](https://github.com/nabla-c0d3/sslyze)

## Networking

| Script | Description |
|--------|-------------|
| `speedtest.sh` | Runs a speed test and saves a timestamped report; supports verbose and JSON output modes |

## Usage

Clone and run any script directly:

```bash
git clone https://github.com/jinzoro/scripts.git
cd scripts

# Example: parse a certificate bundle
./Certificate-scripts/parse_certs.sh /path/to/bundle.pem

# Example: test a cert/key/chain trio
./Certificate-scripts/test-cert.sh /path/to/cert.pem

# Example: run a speed test
./Networking/speedtest.sh
```

Make scripts executable if needed:

```bash
chmod +x Certificate-scripts/*.sh Networking/*.sh
```

## Contributing

Open a [pull request](https://github.com/jinzoro/scripts/pulls) or file an [issue](https://github.com/jinzoro/scripts/issues).
