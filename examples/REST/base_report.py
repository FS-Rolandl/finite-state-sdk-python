#!/usr/bin/env python3

import argparse
import csv
from datetime import datetime
import os
from typing import List, Dict, Any, Optional
import asyncio
from .finite_state_client import FiniteStateClient

class BaseReport:
    def __init__(self, client: FiniteStateClient):
        self.client = client
        self.csv_data = []

    def parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string in YYYY-MM-DD format."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            raise ValueError(f"Invalid date format: {date_str}. Expected YYYY-MM-DD")

    def add_csv_row(self, row: Dict[str, Any]):
        """Add a row to the CSV data."""
        self.csv_data.append(row)

    def export_to_csv(self, filename: str, fieldnames: List[str]):
        """Export data to CSV file."""
        if not self.csv_data:
            print("No data to export")
            return

        dir_name = os.path.dirname(filename)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.csv_data)
        print(f"\nReport exported to {filename}")

    @staticmethod
    def add_date_range_args(parser: argparse.ArgumentParser):
        """Add date range arguments to argument parser."""
        parser.add_argument('--start-date', help='Start date for report (YYYY-MM-DD)')
        parser.add_argument('--end-date', help='End date for report (YYYY-MM-DD)')

    @staticmethod
    def add_common_args(parser: argparse.ArgumentParser):
        """Add common arguments to argument parser."""
        parser.add_argument('--csv', nargs='?', const='report.csv',
                          help='Export the report to a CSV file')
        parser.add_argument('--verbose', action='store_true',
                          help='Show detailed information')
        BaseReport.add_date_range_args(parser)

    async def generate_report(self, start_date: Optional[datetime] = None,
                            end_date: Optional[datetime] = None) -> None:
        """Generate the report. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement generate_report")

    async def run(self, args: argparse.Namespace) -> None:
        """Run the report with the given arguments."""
        start_date = self.parse_date(args.start_date)
        end_date = self.parse_date(args.end_date)

        try:
            await self.generate_report(start_date, end_date)
            
            if args.csv is not None:
                # Determine default filename if --csv is provided without a value
                if args.csv == 'report.csv' or args.csv == '':
                    # Use script name as default
                    import sys
                    script_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
                    base_name = script_name
                else:
                    base_name = os.path.splitext(args.csv)[0]
                if start_date or end_date:
                    date_str = []
                    if start_date:
                        date_str.append(start_date.strftime('%Y%m%d'))
                    if end_date:
                        date_str.append(end_date.strftime('%Y%m%d'))
                    base_name = f"{base_name}_{'-'.join(date_str)}"
                filename = f"{base_name}.csv"
                self.export_to_csv(filename, self.get_fieldnames())
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            raise

    def get_fieldnames(self) -> List[str]:
        """Get the fieldnames for CSV export. To be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement get_fieldnames") 