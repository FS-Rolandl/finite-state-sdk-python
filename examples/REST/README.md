# Finite State REST API Reports

This directory contains reports that use the Finite State REST API instead of GraphQL. These reports are designed to be more efficient and provide additional features like date range filtering and parallel processing.

## Setup

### Prerequisites
- Python 3.7 or higher
- aiohttp package (`pip install aiohttp`)

### Environment Variables
Set the following environment variables:
```bash
export FINITE_STATE_URL="https://roland.finitestate.io"
export FINITE_STATE_TOKEN="your_api_token"
```

Or provide them as command-line arguments:
```bash
python report_asset_risk_scores.py --url "https://roland.finitestate.io" --token "your_api_token"
```

## Available Reports

### Asset Risk Scores Report
**Script:** `report_asset_risk_scores.py`
**Purpose:** Analyze risk scores across all assets to identify high-risk items.
**Usage:**
```bash
python report_asset_risk_scores.py [options]
```

**Options:**
- `--url`: Finite State API URL (default: FINITE_STATE_URL environment variable)
- `--token`: Finite State API token (default: FINITE_STATE_TOKEN environment variable)
- `--start-date`: Start date for report (YYYY-MM-DD)
- `--end-date`: End date for report (YYYY-MM-DD)
- `--csv`: Export the report to a CSV file
- `--verbose`: Show detailed information
- `--asset-version-id`: Specific asset version ID to analyze

**Output:** CSV file with columns:
- Asset Name
- Group
- Version
- Risk Score

## Features

### Date Range Filtering
All reports support filtering by date range using the `--start-date` and `--end-date` options. Dates should be in YYYY-MM-DD format.

Example:
```bash
python report_asset_risk_scores.py --start-date 2024-01-01 --end-date 2024-03-31
```

### Parallel Processing
Reports use parallel processing to improve performance when fetching data for multiple assets or versions.

### Rate Limiting
Built-in rate limiting to prevent API throttling. Default is 10 requests per second.

### Error Handling
- Automatic retries for failed requests
- Exponential backoff for rate limit errors
- Clear error messages for common issues

## Common Options

Most reports support the following options:
- `--url`: Override the Finite State API URL
- `--token`: Override the Finite State API token
- `--start-date`: Filter data from this date (YYYY-MM-DD)
- `--end-date`: Filter data until this date (YYYY-MM-DD)
- `--csv`: Export to CSV file
- `--verbose`: Show detailed information

## Troubleshooting

### Common Issues

1. **Invalid API Token**
   ```
   Error: Invalid API token
   ```
   Solution: Check your FINITE_STATE_TOKEN environment variable or --token argument

2. **Rate Limit Exceeded**
   ```
   Error: Rate limit exceeded
   ```
   Solution: The report will automatically retry with exponential backoff

3. **Invalid Date Format**
   ```
   Error: Invalid date format: 2024/01/01. Expected YYYY-MM-DD
   ```
   Solution: Use YYYY-MM-DD format for dates

### Getting Help

For additional help or to report issues, please contact support@finitestate.io 