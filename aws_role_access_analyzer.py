#!/usr/bin/env python3

import boto3
import pandas as pd
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import argparse
from botocore.exceptions import ClientError

class RoleAccessAnalyzer:
    def __init__(self, role_name: str):
        """
        Initialize the analyzer with the role name to check.
        
        Args:
            role_name (str): Name of the IAM role to analyze
        """
        self.role_name = role_name
        self.session = boto3.Session()
        
    def assume_role(self, account_id: str) -> boto3.Session:
        """
        Assume the specified role in the target account.
        
        Args:
            account_id (str): AWS account ID to assume role in
            
        Returns:
            boto3.Session: Session for the assumed role
        """
        sts = self.session.client('sts')
        role_arn = f'arn:aws:iam::{account_id}:role/{self.role_name}'
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='RoleAccessAnalysis'
            )
            
            return boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
        except ClientError as e:
            print(f"Error assuming role in account {account_id}: {str(e)}")
            return None

    def get_role_last_accessed(self, account_id: str) -> Dict[str, Any]:
        """
        Get the last accessed information for the role in the specified account.
        
        Args:
            account_id (str): AWS account ID to check
            
        Returns:
            dict: Dictionary containing the role access information
        """
        try:
            assumed_session = self.assume_role(account_id)
            if not assumed_session:
                return {
                    'AccountId': account_id,
                    'Error': 'Failed to assume role'
                }

            iam = assumed_session.client('iam')
            
            # Get role details
            role = iam.get_role(RoleName=self.role_name)
            role_id = role['Role']['RoleId']
            
            # Get service last accessed details
            response = iam.generate_service_last_accessed_details(Arn=role['Role']['Arn'])
            job_id = response['JobId']
            
            # Wait for the report to be ready
            waiter = iam.get_waiter('service_last_accessed_details_ready')
            waiter.wait(
                JobId=job_id,
                WaiterConfig={'Delay': 2, 'MaxAttempts': 30}
            )
            
            # Get the report
            services = iam.get_service_last_accessed_details(JobId=job_id)
            
            # Filter for services accessed within last 365 days
            accessed_services = []
            for service in services['ServicesLastAccessed']:
                if service.get('LastAuthenticated'):
                    days_since_access = (datetime.now(timezone.utc) - service['LastAuthenticated']).days
                    if days_since_access <= 365:
                        accessed_services.append({
                            'ServiceName': service['ServiceName'],
                            'LastAccessed': service['LastAuthenticated'].isoformat(),
                            'DaysSinceAccess': days_since_access
                        })
            
            return {
                'AccountId': account_id,
                'RoleId': role_id,
                'AccessedServices': accessed_services
            }
            
        except ClientError as e:
            return {
                'AccountId': account_id,
                'Error': str(e)
            }

def main():
    parser = argparse.ArgumentParser(description='Analyze IAM role access across AWS accounts')
    parser.add_argument('--accounts', required=True, help='Comma-separated list of AWS account IDs')
    parser.add_argument('--role-name', required=True, help='Name of the IAM role to analyze')
    args = parser.parse_args()
    
    account_ids = [acc.strip() for acc in args.accounts.split(',')]
    analyzer = RoleAccessAnalyzer(args.role_name)
    
    print(f"Analyzing role '{args.role_name}' across {len(account_ids)} accounts...")
    
    # Process accounts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(analyzer.get_role_last_accessed, account_ids))
    
    # Create a list to store formatted results for the DataFrame
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
    
    if df_data:
        # Create and display the DataFrame
        df = pd.DataFrame(df_data)
        df = df.sort_values(['AccountId', 'DaysSinceAccess'])
        
        print("\nRole Access Summary:")
        print(df.to_string(index=False))
        
        # Save to CSV
        output_file = f"role_access_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(output_file, index=False)
        print(f"\nDetailed report saved to: {output_file}")
    else:
        print("No recent (365 days) service access found for the specified role in any account.")

if __name__ == '__main__':
    main() 