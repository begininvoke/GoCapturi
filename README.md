# Network Analysis and Data Extraction Tool

A Golang-based tool for capturing network traffic, analyzing requests/responses, and extracting sensitive data patterns using headless Chrome.

## Features
- Captures all network requests/responses during page navigation
- Extracts sensitive data patterns (API keys, tokens, credentials, etc.)
- Supports domain filtering for targeted analysis
- Handles cookies and headers from curl commands
- Outputs results in CSV/JSON formats
- Auto-scrolls pages to load dynamic content
- Saves extracted data in structured format
- Supports three operation modes: network capture, data extraction, or both

## Installation

### Install Go (1.16+)

### Clone repository:
```bash
git clone https://github.com/begininvoke/GoCapturi.git
cd GoCapturi
```

### Install dependencies:
```bash
go get -u github.com/chromedp/chromedp
```

## Usage
```bash
go run main.go -url [TARGET_URL] [OPTIONS]
```

### Arguments
| Flag       | Description                                      |
|------------|--------------------------------------------------|
| `-url`     | **Required** Target URL to analyze              |
| `-domain`  | Filter requests by domain (e.g., "example.com") |
| `-format`  | Output format: csv or json (default: csv)       |
| `-cookie`  | Curl command containing cookies/headers to set  |
| `-mode`    | Operation mode: extractbody, network, or all (default: all) |
| `-o`       | Output directory (default: current directory)   |
| `-timeout` | Wait time after navigation (default: 30s)       |

## Examples

### Basic analysis with default settings:
```bash
go run main.go -url https://example.com
```

### Targeted domain analysis with JSON output:
```bash
go run main.go -url https://example.com -domain api.example.com -format json
```

### Data extraction mode only:
```bash
go run main.go -url https://example.com -mode extractbody
```

### With cookies from curl command:
```bash
go run main.go -url https://example.com -cookie "curl 'https://example.com' -H 'Cookie: session=abc123; token=xyz789'"
```

### Extended timeout for slow pages:
```bash
go run main.go -url https://example.com -timeout 1m
```

## Output Files

- `requests.csv/json` - Full network capture data containing:
    - Request/response headers
    - Status codes
    - Timings
    - Bodies (base64 encoded)
- `extractall.csv` - All detected sensitive patterns with:
    - Data type (e.g., "github_access_token")
    - Source URL
    - Matched content

## Using with GitHub

This tool is particularly effective for analyzing GitHub-related traffic and detecting secrets:
```bash
go run main.go -url https://github.com -domain *.github.com -mode all -o github_analysis
```

### This will:
- Capture all GitHub-related network requests
- Extract any sensitive patterns from:
    - GitHub access tokens
    - API credentials
    - Repository paths
    - SSH keys
- Save results in `github_analysis/` directory

### Sample findings in `extractall.csv`:
```csv
github_access_token,https://github.com[ResponseBody],abc123:x0c9@github.com
ssh_privKey,https://github.com[ResponseBody],-----BEGIN RSA PRIVATE KEY-----
```

## FAQ

**Q: Why does Chrome window stay open?**  
A: The tool runs in non-headless mode for better compatibility. Add `chromedp.Flag("headless", true)` in code for headless operation.

**Q: How to handle sites with infinite scrolling?**  
A: Increase timeout using `-timeout` flag (e.g., `-timeout 5m`).

**Q: Why are some responses empty?**  
A: Binary responses (images/fonts) are automatically filtered. Remove `isImageOrFont` check in code to capture all content.

## Disclaimer

Use this tool only on websites you own or have permission to analyze. The authors are not responsible for any misuse or damage caused by this software.
