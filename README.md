# vtipPy

A simple Python utility for checking IP addresses against VirusTotal's public API.

## Benifits

- Easier than manually checking 100s of IPs on virus total
- Make efficient use of your 500 daily public API requests

## Features

- Check line-separated lists of IP addresses from a file against VirusTotal
- Resume scans
    - If limited by the 500 daily requests, you can easily resume the following day
- Resume interrupted scans where you left off
- Automatic rate limiting to respect VirusTotal's API constraints
- Track malicious and suspicious IPs for easy reference
- Simple configuration management

## Installation

```bash
git clone https://github.com/its-radio/virustotal_ip_checker.git
cd virustotal_ip_checker
pip install -r requirements.txt
```

## Input format
- Input files must contain one IPv4 address per line 

## Usage

Basic usage:

```bash
python vtipPy.py -f /path/to/ip_list.txt
```

### Command Line Options

```
-f, --file      Specify an input file (required)
-o, --output    Specify a name for an output file (default: inputname_out.txt)
-r, --resume    Resume a scan from where it left off
-F, --force     Skip confirmations for overwrites
-q, --quiet     Suppress most output (excluding confirmations)
```

### Examples

Check a list of IPs:
```bash
python vtipPy.py -f ips.txt
```

Resume a previously interrupted scan:
```bash
python vtipPy.py -f ips.txt -r
```

Specify a custom output file:
```bash
python vtipPy.py -f ips.txt -o results.txt
```

## Notes

- The VirusTotal public API is limited to 500 requests per day and 4 requests per minute
- vtipPy automatically manages these limits and allows you to resume scans the next day
- Configuration is stored in `.vtipPy.conf` in the current directory

## Requirements

- Python 3.6+
- vt-py (VirusTotal API client)

## License

MIT
