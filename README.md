# PII Scanner v3 - README

## Overview

`pii_scanner v3` is a command-line utility written in Go that scans a specified filesystem for files containing personally identifiable information (PII) and other sensitive data. This tool supports multiple file formats (text, SQL, JSON, MySQL dumps) and uses regular expressions to detect specific data patterns such as:

- Email addresses
- Phone numbers (international and domestic)
- Birthdates
- Social Security Numbers (SSNs)
- Credit card numbers (Visa, MasterCard, AMEX)
- Sensitive labels in JSON and SQL files (e.g., `nationalID`, `SSN`)
- TLS private keys

Additionally, it can detect obfuscation tags in files.

## Features

- **File Format Support**: Scans `.sql`, `.json`, `.jsonl`, `.txt`, and MySQL dump files.
- **Regular Expressions**: Uses predefined regex patterns to detect sensitive information.
- **Concurrency**: Files are scanned concurrently for improved performance.
- **File Type Identification**: Automatically identifies file types (e.g., text, JSON, SQL, MySQL dump) and applies appropriate scanning rules.
- **Obfuscation Tag Detection**: Identifies obfuscated files containing a specific UUID.

## How It Works

1. The program accepts a root directory (`-filesystem`) as input.
2. It recursively walks through all files in the specified directory.
3. Files are categorized by type (e.g., text, JSON, SQL) and scanned accordingly using predefined regular expressions.
4. If sensitive data is found, the program outputs a sample of matches from each file.
5. The tool can detect obfuscated files based on a predefined UUID.

## Installation

### Prerequisites

- Go version 1.18 or higher

### Steps

1. Clone the repository or download the Go file:
    ```bash
    git clone https://github.com/your-username/pii_scanner.git
    cd pii_scanner
    ```

2. Build the executable:
    ```bash
    go build -o pii_scanner .
    ```

3. Run the scanner with the required `-filesystem` flag:
    ```bash
    ./pii_scanner -filesystem=/path/to/scan
    ```

## Usage

### Command-Line Options

- `-filesystem`: Specifies the root directory to scan. **Required**.
    ```bash
    ./pii_scanner -filesystem=/home/user/files
    ```

### Example Output

When scanning a directory, the output will show samples of sensitive data found in files:

```bash
pii_scanner v.3 maintained by kenneth.webster@imperva.com
In file /path/to/file.json, found 3 instances of email address. Sample matches:
  Match 1: user@example.com
  Match 2: admin@domain.com
  Match 3: contact@website.com

In MySQL dump file /path/to/file.sql, found instances of sensitive_sql_column. Sample matches:
  Match 1: SSN: '123-45-6789'
