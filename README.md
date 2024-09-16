# ObFuscate

### A Tool for Bypassing Web Application Firewalls (WAFs) Using Obfuscation Techniques
## Introduction

**ObFuscate** is a tool designed to assist security researchers and penetration testers in bypassing Web Application Firewalls (WAFs) by leveraging obfuscation techniques. It injects payloads into URL parameters and POST data, testing whether the WAF can detect and block the payload. The tool works by attempting to disguise the payload and send multiple requests to the target server.

This tool is for **educational purposes only**. Use responsibly.

## Features

- 🌐 **Bypass WAFs**: Obfuscate SQLi, XSS, and other payloads to bypass WAFs.
- 📄 **Custom Payloads**: Inject your own payloads from predefined CSV files.
- ⏳ **Custom Delay**: Introduce a delay between requests for better performance testing.
- 🎲 **Random IP Headers**: Spoof IP addresses via the `X-Forwarded-For` header.
- 🔐 **Proxy Support**: Route requests through a proxy.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/0xgh057r3c0n/ObFuscate.git
   cd ObFuscate
   ```

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up payload files**: Ensure the following payload CSV files are available in the `payloads/` directory:
   - `SQLi_Payloads.csv`
   - `XSS_Payloads.csv`
   - `other_Payloads.csv`

   Payload files should be formatted as:
   ```
   payload1@description
   payload2@description
   ```

## Usage

Run ObFuscate with the required and optional command-line arguments.

### Example:
```bash
python3 obfuscate.py -u "http://example.com/page.php?param=value" -t sql -d 1.5
```

### Payload Types:
- **SQLi**: SQL Injection payloads.
- **XSS**: Cross-site Scripting payloads.
- **Others**: Miscellaneous payloads (e.g., XXE, SSRF, etc.).
- **All**: Use all payload types.

## Command-Line Arguments

| Argument | Description |
| -------- | ----------- |
| `-u, --url` | **(Required)** Target URL to test (e.g., `http://example.com/page.php?param=value`) |
| `-t, --type` | Payload type: `sql`, `xss`, `others`, `all` (default: `all`) |
| `-a, --useragent` | Set a custom User-Agent string for the request |
| `-r, --randip` | Randomize the IP address in the `X-Forwarded-For` header |
| `-x, --proxy` | Send requests through a proxy (e.g., `https://IP:PORT`) |
| `-d, --delay` | Set delay between requests (seconds) |
| `-p, --post` | Send payloads in POST data (e.g., `param=value&another=value`) |
| `-c, --cookie` | Send an HTTP cookie header |
| `-h, --help` | Display help information |

## Example Usage

1. **Basic Usage**:
   ```bash
   python3 obfuscate.py -u "http://example.com/page.php?param=value"
   ```

2. **SQLi Payloads with Custom User-Agent**:
   ```bash
   python3 obfuscate.py -u "http://example.com/page.php?param=value" -t sql -a "CustomUserAgent/1.0"
   ```

3. **XSS Payloads with Proxy and Random IP**:
   ```bash
   python3 obfuscate.py -u "http://example.com/page.php?param=value" -t xss -r -x "http://127.0.0.1:8080"
   ```

4. **POST Request with Custom Cookie**:
   ```bash
   python3 obfuscate.py -u "http://example.com/login.php" -p "username=admin&password=admin123" -c "sessionid=abc123"
   ```

## Disclaimer

**ObFuscate** is intended for educational and research purposes only. Use this tool responsibly and only with explicit permission from the target system's owner. Misuse of this tool may result in legal consequences.

...

*Developed by [Gaurav Bhattacharjee] (@0xgh057r3c0n)*

