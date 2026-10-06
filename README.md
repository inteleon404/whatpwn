<p align="center">
<img width="290" height="58" alt="ascii-art-text" src="https://github.com/user-attachments/assets/f3694657-cd52-4292-a9cf-0e98295c9b05" />


<p align="center">
  <img src="https://img.shields.io/badge/Version-1.1.2-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.19+-blue.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
</p>

<p align="center">
  <strong>Advanced Credentials & Secrets Disclosure Hunter</strong>
</p>

<p align="center">
  A fast, accurate command-line tool for detecting exposed API keys, tokens,
  and credentials across live URLs and web applications.
</p>

---

## Features

### Core Capabilities

- Structured and keyword-based detection across 350+ patterns
- Multi-layer false-positive filtering (deny lists, entropy, repeated-character checks)
- Concurrent scanning with configurable thread count
- Plain-text and JSON Lines output
- Custom headers, proxy support, and configurable retries/timeouts
- Extendable via a user-supplied regex file

### Detection Categories

- AWS, Azure, and Google Cloud credentials
- GitHub, GitLab, and Bitbucket tokens
- Stripe, PayPal, Square, and Razorpay keys
- Slack, Discord, Telegram, and Microsoft Teams tokens/webhooks
- SendGrid, Mailgun, Mailchimp, and other email service keys
- OpenAI, Anthropic, HuggingFace, and other AI provider keys
- JWTs, private keys, SSH keys, and OAuth secrets
- Database connection strings (MySQL, PostgreSQL, MongoDB, Redis, and more)
- DevOps and infrastructure tokens (Docker, Kubernetes, Terraform, CI/CD)
- PII patterns and generic credential assignments

---

## Installation

### Prerequisites

- Go 1.19 or higher
- Linux, macOS, or Windows with Go support

### Quick Install

```bash
go install github.com/inteleon404/whatpwn@latest
```

### Build From Source

```bash
git clone https://github.com/inteleon404/whatpwn.git
cd whatpwn
go build -o whatpwn main.go
chmod +x whatpwn
sudo mv whatpwn /usr/local/bin/
```

### One-Liner Install

```bash
git clone https://github.com/inteleon404/whatpwn.git && \
cd whatpwn && \
go build -o whatpwn main.go && \
chmod +x whatpwn && \
echo "Installation complete. Run with: ./whatpwn -h"
```

### Windows

```powershell
git clone https://github.com/inteleon404/whatpwn.git
cd whatpwn
go build -o whatpwn.exe main.go
```

---

## Usage

### Basic

```bash
# Scan URLs from stdin
cat urls.txt | ./whatpwn

# Scan with pipe from other recon tools
waybackurls target.com | ./whatpwn

# Scan a list of URLs from a file
./whatpwn -l urls.txt

# Increase concurrency
cat urls.txt | ./whatpwn -t 100

# Silent mode (findings only, no banner/summary)
cat urls.txt | ./whatpwn -silent
```

### Command Line Options

```
USAGE:
  whatpwn [flags]

INPUT:
  -l string            stdin (default) or a file with a list of URLs/hosts

OUTPUT:
  -o string             write findings to file
  -json string          write findings as JSON lines
  -nc                    disable color output
  -silent                silent mode, no banner/summary
  -stats                 show detailed scan statistics

CONFIG:
  -t int                 concurrent threads (default 25)
  -timeout int           request timeout in seconds (default 15)
  -retry int             retry count on failure (default 1)
  -ua string             custom user-agent
  -H string              custom header, e.g. 'Cookie: session=abc'
  -proxy string          http proxy, e.g. http://127.0.0.1:8080
  -verify                verify TLS certificates

FILTER:
  -e string              extra regex file, one pattern per line
  -entropy               entropy-filter keyword matches
  -min-entropy float     minimum shannon entropy (default 3.2)
  -max-body int          max response body size to scan, in MB (default 5)
  -mm int                max matches per pattern per page (default 5)
```

---

## Output Example

```
▓ ▄  ▓ █▄▄▄  ▀▀▓ █▄▄  █▀▀▓ ▓ ▄  ▓ ▓▀▀█
█ █ ▄█ █  █ █▀▀█ █  ▄ █  █ █ █ ▄█ █  █
▓▄█▄█  █  ▓ ▓▄▄▓ █▄▄▓ ▓▀▀▀ ▓▄█▄█  █  ▓

  WhatPwn v1.1.2 | Advanced Credentials & Secrets Disclosure Hunter
  356 patterns loaded | threads: 25 | timeout: 15s
  ────────────────────────────────────────────────────────

[+] https://site.com/app.js [AKIAIOSFODNN7EXAMPLE]
[+] https://site.com/config.js [ghp_1234567890abcdefghijklmnopqrstuvwxyz]
[+] https://site.com/api.js [sk_live_4eC39HqLyjWDarjtT1zdp7dc]

[+] Scan Complete in 12.4s
[+] URLs: 245 | Findings: 3 | Skipped: 0
```

With `-stats`:

```
[+] Requests: 245 | Data: 18.2 MB | Patterns: 356
```

---

## Real-World Examples

### Bug Bounty Hunting

```bash
# Discover JavaScript files and scan for secrets
waybackurls target.com | grep -E '\.(js|json)$' | ./whatpwn -t 100

# Combine with gau for broader coverage
gau target.com | ./whatpwn -t 100 -o findings.txt

# Save findings as JSON for further processing
cat urls.txt | ./whatpwn -json findings.json -silent
```

### Penetration Testing

```bash
# Scan with detailed statistics
./whatpwn -l scope.txt -t 50 -stats

# Authenticated scanning with a session cookie
./whatpwn -l authenticated_urls.txt -H "Cookie: session=abc123"
```

### Red Team Operations

```bash
# Silent, stricter entropy filtering
./whatpwn -l targets.txt -silent -entropy -min-entropy 4.5 -t 200

# Fast recon pipeline
echo "https://target.com" | hakrawler | ./whatpwn -silent
```

### CI/CD Integration

```bash
# Scan a diff before merging
git diff main | ./whatpwn -silent -entropy -min-entropy 4.5
```

---

## Integration Examples

```bash
# With waybackurls
waybackurls target.com | ./whatpwn -t 100 -o secrets.txt

# With gau
gau target.com | ./whatpwn -o findings.txt

# With hakrawler
echo "target.com" | hakrawler | ./whatpwn -stats

# With gospider
gospider -s https://target.com --js | ./whatpwn

# With subfinder + httpx
subfinder -d target.com | httpx -silent | ./whatpwn -t 100

# Full recon-to-report pipeline
subfinder -d target.com -silent | \
  httpx -silent | \
  waybackurls | \
  grep -E '\.(js|json)$' | \
  sort -u | \
  ./whatpwn -t 100 -json results.json
```

---

## Detection Behavior

### Will Detect

```javascript
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE123";
const githubPAT    = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const stripeKey    = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const slackToken   = "xoxb-123456789012-123456789012-abc123def456";
const privateKey   = "-----BEGIN RSA PRIVATE KEY-----";
const jwt          = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...";
```

### Will Not Detect (filtered as false positives)

```javascript
const apiKey      = "your_api_key_here";
const token       = "replace_with_your_token";
const password    = "changeme";
const secret      = "test_secret";
const key         = "12345678";
const placeholder = "xxxxxxxxxx";
```

False positives are filtered through an exact-match deny list, placeholder
word matching, digit-only and HTML-fragment checks, repeated-character
detection, and optional Shannon entropy scoring (`-entropy`).

---

## Testing

```bash
# Create a sample file with test secrets
cat > test.js << 'EOF'
const awsKey = "AKIAIOSFODNN7EXAMPLE123";
const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const stripeKey = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const placeholder = "your_key_here";
EOF

# Serve or host the file, then scan it
echo "https://example.com/test.js" | ./whatpwn
```

---

## Contributing

Contributions are welcome. Please open a pull request or an issue describing
the change.

```bash
git clone https://github.com/inteleon404/whatpwn.git
cd whatpwn
go build -o whatpwn main.go
go vet ./...
```

When reporting issues, include a clear description, steps to reproduce, and
expected versus actual behavior.

---

## Security and Ethics

This tool is intended for authorized security research and testing only.

- Obtain proper authorization before scanning any target
- Follow responsible disclosure practices
- Do not access, use, or exploit any credentials discovered during testing
- Comply with applicable laws and the target's terms of service

If you discover live credentials using this tool:

1. Verify the finding is legitimate
2. Confirm whether the credential is still active
3. Report it through the appropriate responsible disclosure channel
4. Do not use or share the credential beyond what disclosure requires

---

## License

[MIT License](LICENSE)

This tool is provided as-is. The author is not responsible for misuse or
damage resulting from its use.

---

## Support

- Issues: https://github.com/inteleon404/whatpwn/issues
- Author: https://github.com/inteleon404
