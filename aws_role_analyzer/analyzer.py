"""Core functionality for analyzing IAM role access patterns."""

import boto3
from datetime import datetime, timezone
from typing import Dict, Any, Optional
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
        
    def assume_role(self, account_id: str) -> Optional[boto3.Session]:
        """
        Assume the specified role in the target account.
        
        Args:
            account_id (str): AWS account ID to assume role in
            
        Returns:
            Optional[boto3.Session]: Session for the assumed role, or None if assumption fails
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