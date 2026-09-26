# Threat Intelligence Lookup Tool

A Python-based threat intelligence tool that queries the **VirusTotal API v3** for information about IP addresses, domains, URLs, and file hashes.

The tool supports single-indicator lookups and batch processing, performs a project-defined threat assessment, and generates human-readable reports.

## Features

- Query VirusTotal for:
  - IPv4/IPv6 addresses
  - Domains
  - URLs
  - MD5, SHA-1, and SHA-256 hashes
- Automatically identify indicator types
- Secure API key handling through an environment variable
- Process multiple indicators from a text file
- Handle common API and network errors
- Parse and normalize API responses
- Calculate a basic threat score and threat level
- Display and save lookup reports

## Requirements

- Python 3
- VirusTotal API key
- `requests`

Install the dependency:

```bash
pip install requests
```

## API Key

Set the VirusTotal API key as an environment variable:

```bash
export API_KEY="your_api_key_here"
```

Do not store or commit the API key in the project.

## Usage

### Single Indicator

```bash
python3 threat_intel.py <indicator> <target>
```

Supported indicator types:

```text
ip | domain | url | hash
```

Examples:

```bash
python3 threat_intelligence_lookup.py ip 8.8.8.8
python3 threat_intelligence_lookup.py domain example.com
python3 threat_intelligence_lookup.py url https://example.com
python3 threat_intelligence_lookup.py hash <file-hash>
```

### Batch Processing

```bash
python3 threat_intelligence_lookup.py batch batch_target_file.txt
```

The input file contains one indicator per line. Blank lines are ignored.

Individual lookup errors are reported while batch processing continues.

## Threat Assessment

The tool calculates a threat score using:

- Malicious detections
- Suspicious detections
- Community reputation

| Score | Threat Level |
|---|---|
| 0–2 | LOW |
| 3–5 | MEDIUM |
| 6+ | HIGH |

The scoring system is a **project-defined heuristic** and is not a definitive security verdict.

## Reports

Successful lookups produce human-readable reports containing:

- Indicator-specific information
- Reputation
- Analysis statistics
- Threat score and threat level

Reports are printed to the terminal and appended to:

```text
lookup_report.txt
```

## Technologies

- Python 3
- VirusTotal REST API v3
- `requests`
- JSON
- Regular expressions
- `ipaddress`
- `urllib.parse`
- Base64 encoding
- Environment variables
- File handling

## Limitations

- Threat scoring is a project-defined heuristic.
- Domain validation is intentionally simplified.
- Results depend on VirusTotal API availability and rate limits.
- Some VirusTotal fields may be unavailable for particular indicators.
- Reports are stored as text rather than structured JSON or CSV.

## Project Purpose

This project was built to strengthen practical Python and cybersecurity skills through:

- REST API integration
- Threat intelligence
- Input validation
- Data normalization
- Error handling
- Batch processing
- Threat assessment logic
- Report generation
- Security automation

## Disclaimer

This project is intended for educational and authorized cybersecurity use. Only investigate indicators you are authorized to analyze, and comply with VirusTotal's terms of service.
