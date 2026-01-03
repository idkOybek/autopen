# Pentest CLI - Command Line Interface

A powerful command-line tool for managing automated penetration testing scans, generating reports, and monitoring system health.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/autopen.git
cd autopen

# Install in development mode
pip install -e .

# Or install from setup.py
python setup.py install
```

### Using pip

```bash
pip install pentest-cli
```

## Quick Start

```bash
# Check system status
pentest-cli system status

# Start a new scan
pentest-cli scan start "My Scan" --targets-file targets.txt

# Monitor scan progress in real-time
pentest-cli scan status SCAN_ID --follow

# Generate reports
pentest-cli report generate SCAN_ID --type both -o ./reports

# Start interactive mode
pentest-cli interactive
```

## Configuration

Configuration is stored in `~/.pentest-cli.yaml`:

```yaml
api_url: http://localhost:8000/api
timeout: 30
verify_ssl: true
output_dir: ~/pentest-reports
```

### Environment Variables

- `PENTEST_API_URL`: Override API base URL

## Commands

### Scan Management

```bash
# Start a new scan
pentest-cli scan start NAME [OPTIONS]
  --config FILE          Pipeline configuration file (JSON/YAML)
  --targets-file FILE    File containing targets
  --targets TARGET       Individual target (repeatable)
  --ftp-url URL         FTP URL to fetch targets from

# Check scan status
pentest-cli scan status SCAN_ID [--follow]

# List all scans
pentest-cli scan list [--status STATUS] [--limit N]

# Control scan execution
pentest-cli scan stop SCAN_ID
pentest-cli scan pause SCAN_ID
pentest-cli scan resume SCAN_ID
```

### Report Generation

```bash
# Generate reports
pentest-cli report generate SCAN_ID [OPTIONS]
  --type TYPE           Report type: technical, executive, both
  --output DIR          Output directory

# Send reports
pentest-cli report send SCAN_ID [OPTIONS]
  --telegram CHAT_ID    Send to Telegram
  --email ADDRESS       Send via email
  --ftp URL            Upload to FTP
```

### System Management

```bash
# Check system health
pentest-cli system status

# View metrics
pentest-cli system metrics
```

### Configuration

```bash
# Show current configuration
pentest-cli config show

# Set configuration value
pentest-cli config set KEY VALUE
```

### Interactive Mode

```bash
# Start interactive shell
pentest-cli interactive
```

Features:
- Command history
- Auto-completion
- Auto-suggestions from history
- Real-time feedback

## Bash Completion

### Installation

```bash
# Copy completion script
sudo cp scripts/pentest-cli-completion.bash /etc/bash_completion.d/pentest-cli

# Or add to your ~/.bashrc
echo "source /path/to/autopen/scripts/pentest-cli-completion.bash" >> ~/.bashrc
source ~/.bashrc
```

### Usage

Press TAB to auto-complete commands and options:

```bash
pentest-cli scan <TAB>       # Shows: start status list stop pause resume
pentest-cli scan start <TAB> # Shows: --config --targets-file --targets --ftp-url
```

## Man Pages

### Installation

```bash
# Copy man page
sudo cp man/pentest-cli.1 /usr/share/man/man1/
sudo mandb
```

### Usage

```bash
man pentest-cli
```

## Examples

### Example 1: Simple Web Application Scan

```bash
# Create targets file
cat > targets.txt << EOF
example.com
api.example.com
admin.example.com
EOF

# Create pipeline config
cat > config.json << EOF
{
  "stages": ["reconnaissance", "scanning", "exploitation"],
  "scanners": ["nmap", "nuclei"],
  "timeout": 3600
}
EOF

# Start scan
pentest-cli scan start "Web App Pentest" \
  --config config.json \
  --targets-file targets.txt

# Monitor progress
pentest-cli scan status SCAN_ID --follow
```

### Example 2: Network Scan with FTP Integration

```bash
# Start scan fetching targets from FTP
pentest-cli scan start "Network Scan" \
  --ftp-url ftp://user:pass@server/targets.txt

# Generate and send reports
pentest-cli report generate SCAN_ID --type both
pentest-cli report send SCAN_ID --telegram 123456789
```

### Example 3: Interactive Session

```bash
# Start interactive mode
pentest-cli interactive

# In interactive shell:
pentest> scan list --status running
pentest> system status
pentest> report generate SCAN_ID --type technical
pentest> exit
```

### Example 4: Automation Script

```bash
#!/bin/bash
# automated-scan.sh

SCAN_NAME="Daily Security Scan"
API_URL="https://pentest.example.com/api"

# Start scan
SCAN_ID=$(pentest-cli --api-url $API_URL \
  scan start "$SCAN_NAME" \
  --targets-file /etc/pentest/targets.txt \
  --config /etc/pentest/config.json \
  | grep -oP 'ID: \K[a-f0-9-]+')

echo "Started scan: $SCAN_ID"

# Wait for completion (check every 5 minutes)
while true; do
  STATUS=$(pentest-cli --api-url $API_URL scan status $SCAN_ID | grep Status | awk '{print $2}')

  if [ "$STATUS" = "COMPLETED" ]; then
    echo "Scan completed!"
    break
  elif [ "$STATUS" = "FAILED" ]; then
    echo "Scan failed!"
    exit 1
  fi

  sleep 300
done

# Generate and send reports
pentest-cli --api-url $API_URL report generate $SCAN_ID --type both -o /var/reports
pentest-cli --api-url $API_URL report send $SCAN_ID --email security@example.com

echo "Reports sent!"
```

## Output Formatting

The CLI uses Rich for beautiful terminal output:

- **Tables**: Structured data display
- **Progress bars**: Real-time progress tracking
- **Syntax highlighting**: Color-coded output
- **Live updates**: Real-time status monitoring

## Troubleshooting

### Cannot connect to API

```bash
# Check system status
pentest-cli system status

# Verify API URL
pentest-cli config show

# Set correct API URL
pentest-cli config set api_url http://localhost:8000/api
```

### SSL Certificate Errors

```bash
# Disable SSL verification (not recommended for production)
pentest-cli config set verify_ssl false
```

### Interactive mode not working

```bash
# Install prompt_toolkit
pip install prompt-toolkit
```

## Development

### Running Tests

```bash
pytest tests/cli/
```

### Code Style

```bash
# Format code
black cli/

# Check linting
flake8 cli/

# Type checking
mypy cli/
```

## License

MIT License - See LICENSE file for details.

## Support

- Documentation: https://docs.example.com/autopen
- Issues: https://github.com/your-org/autopen/issues
- Email: support@example.com
