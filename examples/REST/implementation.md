# REST API Migration Implementation Plan

## Overview
This document outlines the plan for migrating the existing GraphQL-based reports to use the new REST API endpoints, along with implementing new features for date range filtering and parallel processing.

## Directory Structure
```
examples/
└── REST/
    ├── __init__.py
    ├── base_report.py
    ├── finite_state_client.py
    ├── implementation.md
    ├── README.md
    └── reports/
        ├── report_asset_risk_scores.py
        ├── report_asset_version_comparison.py
        ├── report_assets_over_time.py
        ├── report_uploads_over_time.py
        ├── report_vulnerabilities_over_time.py
        ├── report_vulnerability_severity_trends.py
        └── run_reports.py
```

## Scripts to Migrate
1. report_asset_risk_scores.py
2. report_asset_version_comparison.py
3. report_assets_over_time.py
4. report_uploads_over_time.py
5. report_vulnerabilities_over_time.py
6. report_vulnerability_severity_trends.py
7. run_reports.py

## Core Changes

### Environment Variables
- Remove .env file handling and dotenv dependency
- Replace with:
  - FINITE_STATE_URL (e.g., https://roland.finitestate.io)
  - FINITE_STATE_TOKEN (API token)

### API Changes
Update all API calls to use REST endpoints from Swagger:
- `/api/public/v0/projects` - for asset/project information
- `/api/public/v0/projects/{projectId}` - for project details
- `/api/public/v0/branches/{branchId}/versions` - for version information
- `/api/public/v0/findings` - for vulnerability data
- `/api/public/v0/risk-scores` - for risk score information (when available)

### Command Line
- Remove --secrets-file option
- Keep other options (--csv, --verbose, etc.)
- Add --url option to override FINITE_STATE_URL if needed

## New Features Implementation

### Date Range Filtering
Add to each report script:
- Implement date validation and formatting
- Add date range to CSV filenames
- Use REST API's date filtering parameters
- Add --start-date and --end-date options

### Parallel Processing
Create a common utility module for parallel processing:
- Implement ThreadPoolExecutor for API calls
- Add progress indicators
- Add batch size control
- Add error handling for failed parallel requests

## Migration Steps
1. Create REST directory structure
2. Create a new base class or utility module for common REST API functionality
3. Migrate run_reports.py first
4. Migrate each report script one by one
5. Create new README.md with:
   - Environment setup instructions
   - API token requirements
   - Example usage
   - New features documentation
6. Test each script with real API endpoints

## Error Handling
Implement HTTP Status Code handling:
- 200: Success
- 401: Invalid token
- 403: Insufficient permissions
- 404: Resource not found
- 429: Rate limit exceeded
- 500: Server error

## Documentation Updates
Update reports_README.md to reflect REST-based changes:
- Add API endpoint documentation
- Add examples of new features
- Add troubleshooting guide

## Progress Tracking
- [x] Create REST directory structure
- [x] Create base_report.py
- [x] Create finite_state_client.py
- [x] Migrate report_asset_risk_scores.py (partial - risk scores endpoint not available)
- [ ] Migrate report_asset_version_comparison.py
- [ ] Migrate report_assets_over_time.py
- [ ] Migrate report_uploads_over_time.py
- [ ] Migrate report_vulnerabilities_over_time.py
- [ ] Migrate report_vulnerability_severity_trends.py
- [ ] Migrate run_reports.py
- [ ] Update documentation 