#!/usr/bin/env python3

import argparse
import asyncio
import os
import sys
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import csv

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.REST.finite_state_client import FiniteStateClient
from examples.REST.base_report import BaseReport

class AssetVersionComparisonReport(BaseReport):
    def __init__(self, client: FiniteStateClient):
        super().__init__(client)
        self.csv_data = [['Asset Name', 'Group', 'Version', 'Vulnerabilities']]

    def get_fieldnames(self):
        return ['Asset Name', 'Group', 'Version', 'Vulnerabilities']

    def add_csv_row(self, row: Dict[str, Any]) -> None:
        """Add a row to the CSV data."""
        self.csv_data.append([
            row['Asset Name'],
            row['Group'],
            row['Version'],
            row['Vulnerabilities']
        ])

    async def generate_report(self, start_date: Optional[datetime] = None,
                            end_date: Optional[datetime] = None) -> None:
        """Generate the asset version comparison report."""
        # Get all assets (projects)
        assets = await self.client.get_assets(start_date, end_date)
        if not assets:
            print("No assets found")
            return
            
        print(f"\nFound {len(assets)} assets to analyze")
        
        print("\nAsset Version Comparison Report:")
        print("-" * 80)
        print(f"{'Asset Name':<30} {'Group':<15} {'Version':<20} {'Vulnerabilities':<15}")
        print("-" * 80)

        # Process assets sequentially to avoid rate limits
        for asset in assets:
            try:
                asset_name = asset.get('name', 'N/A')
                group_name = asset.get('group', {}).get('name', 'N/A')
                
                # Get project details to get branch_id
                project_details = await self.client.get_project_details(asset['id'])
                print(f"\nDEBUG: Project details for {asset_name}: {json.dumps(project_details, indent=2)}")
                
                branch_id = project_details.get('defaultBranch', {}).get('id')
                
                if not branch_id:
                    print(f"Warning: No branch_id found for asset {asset_name}")
                    continue
                
                # Get versions for this asset using the branch_id
                versions = await self.client.get_asset_versions(branch_id, start_date, end_date)
                print(f"\nDEBUG: Versions for {asset_name}: {json.dumps(versions, indent=2)}")
                
                if not versions:
                    print(f"Warning: No versions found for asset {asset_name}")
                    continue
                
                for version in versions:
                    version_name = version.get('version', 'N/A')
                    
                    # Get findings for this version using the version ID
                    findings = await self.client.get_findings(version['id'])
                    # Count only findings of type 'cve' as vulnerabilities
                    vulnerability_count = sum(1 for f in findings if f.get('type') == 'cve') if findings else 0
                    
                    # Print results
                    print(f"{asset_name:<30} {group_name:<15} {version_name:<20} {vulnerability_count:<15}")
                    
                    # Add data for CSV
                    self.add_csv_row({
                        'Asset Name': asset_name,
                        'Group': group_name,
                        'Version': version_name,
                        'Vulnerabilities': vulnerability_count
                    })
            except Exception as e:
                print(f"Error processing asset {asset.get('name', 'Unknown')}: {str(e)}")
                continue

    def save_to_csv(self, filename: str) -> None:
        """Save the report data to a CSV file."""
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(self.csv_data)
        print(f"\nReport exported to {filename}")

def parse_args():
    parser = argparse.ArgumentParser(description='Compare different versions of the same asset to identify improvements or regressions in security features and vulnerabilities.')
    parser.add_argument('--url', default=os.environ.get('FINITE_STATE_URL'),
                       help='Finite State API URL (default: FINITE_STATE_URL environment variable)')
    parser.add_argument('--token', default=os.environ.get('FINITE_STATE_TOKEN'),
                       help='Finite State API token (default: FINITE_STATE_TOKEN environment variable)')
    BaseReport.add_common_args(parser)
    return parser.parse_args()

async def main():
    args = parse_args()
    
    # Validate required environment variables
    if not args.url:
        print("Error: FINITE_STATE_URL environment variable or --url argument is required")
        sys.exit(1)
    if not args.token:
        print("Error: FINITE_STATE_TOKEN environment variable or --token argument is required")
        sys.exit(1)

    # Create client and report
    async with FiniteStateClient(args.url, args.token) as client:
        report = AssetVersionComparisonReport(client)
        await report.generate_report(args.start_date, args.end_date)
        report.save_to_csv("asset_version_comparison.csv")

if __name__ == '__main__':
    asyncio.run(main()) 