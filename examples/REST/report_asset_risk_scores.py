#!/usr/bin/env python3

import argparse
import asyncio
import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.REST.finite_state_client import FiniteStateClient
from examples.REST.base_report import BaseReport

class AssetRiskScoresReport(BaseReport):
    def __init__(self, client: FiniteStateClient):
        super().__init__(client)
        self.fieldnames = ['Asset Name', 'Group', 'Version', 'Risk Score']

    def get_fieldnames(self) -> List[str]:
        return self.fieldnames

    async def generate_report(self, start_date: Optional[datetime] = None,
                            end_date: Optional[datetime] = None) -> None:
        """Generate the asset risk scores report."""
        print("\nFetching assets...")
        assets = await self.client.get_assets(start_date, end_date)
        
        print(f"\nFound {len(assets)} assets to analyze")
        print("\nAsset Risk Score Analysis:")
        print("-" * 100)
        print(f"{'Asset Name':<30} {'Group':<15} {'Version':<20} {'Risk Score':<10}")
        print("-" * 100)

        # Process assets in parallel
        async def process_asset(asset: Dict[str, Any]):
            asset_name = asset.get('name', 'N/A')
            group_name = asset.get('group', {}).get('name', 'N/A')
            
            # Get versions for this asset
            versions = await self.process_asset(asset, start_date, end_date)
            
            for version in versions:
                version_name = version.get('name', 'N/A')
                
                # Get risk score for this version
                risk_score = await self.client.get_risk_scores(version['id'])
                score = risk_score.get('relativeRiskScore', 'N/A')
                
                # Print results
                print(f"{asset_name:<30} {group_name:<15} {version_name:<20} {score:<10}")
                
                # Add data for CSV
                self.add_csv_row({
                    'Asset Name': asset_name,
                    'Group': group_name,
                    'Version': version_name,
                    'Risk Score': score
                })

        # Create tasks for parallel processing
        tasks = [process_asset(asset) for asset in assets]
        await asyncio.gather(*tasks)

    async def process_asset(self, asset: Dict[str, Any], start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Process a single asset and return its versions with risk scores."""
        project_id = asset.get('id')
        if not project_id:
            print(f"Warning: No project id found for asset {asset.get('name', 'Unknown')}")
            return []
        # Fetch project details to get branch_id
        project_details = await self.client.get_project_details(project_id)
        branch_id = None
        if 'defaultBranch' in project_details and 'id' in project_details['defaultBranch']:
            branch_id = project_details['defaultBranch']['id']
        print(f"Project details for {asset.get('name', 'Unknown')}: {project_details}")  # Debug
        if not branch_id:
            print(f"Warning: No branch_id found in project details for asset {asset.get('name', 'Unknown')}")
            return []
        versions = await self.client.get_asset_versions(branch_id, start_date, end_date)
        return versions

def parse_args():
    parser = argparse.ArgumentParser(description='Report on asset risk scores.')
    parser.add_argument('--url', default=os.environ.get('FINITE_STATE_URL'),
                       help='Finite State API URL (default: FINITE_STATE_URL environment variable)')
    parser.add_argument('--token', default=os.environ.get('FINITE_STATE_TOKEN'),
                       help='Finite State API token (default: FINITE_STATE_TOKEN environment variable)')
    parser.add_argument('--asset-version-id', help='Specific asset version ID to analyze')
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
        report = AssetRiskScoresReport(client)
        await report.run(args)

if __name__ == '__main__':
    asyncio.run(main()) 