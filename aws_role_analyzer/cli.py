"""Command line interface for the AWS Role Access Analyzer."""

import argparse
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from .analyzer import RoleAccessAnalyzer


def process_results(results: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Process the results from multiple accounts into a DataFrame.
    
    Args:
        results: List of results from analyzing each account
        
    Returns:
        pd.DataFrame: Processed results in a DataFrame
    """
    df_data = []
    
    for result in results:
        if 'Error' in result:
            print(f"Error in account {result['AccountId']}: {result['Error']}")
            continue
            
        for service in result['AccessedServices']:
            df_data.append({
                'AccountId': result['AccountId'],
                'RoleId': result['RoleId'],
                'ServiceName': service['ServiceName'],
                'LastAccessed': service['LastAccessed'],
                'DaysSinceAccess': service['DaysSinceAccess']
            })
    
    if not df_data:
        return pd.DataFrame()
        
    return pd.DataFrame(df_data).sort_values(['AccountId', 'DaysSinceAccess'])


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Analyze IAM role access across AWS accounts'
    )
    parser.add_argument(
        '--accounts',
        required=True,
        help='Comma-separated list of AWS account IDs'
    )
    parser.add_argument(
        '--role-name',
        required=True,
        help='Name of the IAM role to analyze'
    )
    args = parser.parse_args()
    
    account_ids = [acc.strip() for acc in args.accounts.split(',')]
    analyzer = RoleAccessAnalyzer(args.role_name)
    
    print(f"Analyzing role '{args.role_name}' across {len(account_ids)} accounts...")
    
    # Process accounts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(analyzer.get_role_last_accessed, account_ids))
    
    df = process_results(results)
    
    if not df.empty:
        print("\nRole Access Summary:")
        print(df.to_string(index=False))
        
        # Save to CSV
        output_file = f"role_access_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(output_file, index=False)
        print(f"\nDetailed report saved to: {output_file}")
    else:
        print("No recent (365 days) service access found for the specified role in any account.") 