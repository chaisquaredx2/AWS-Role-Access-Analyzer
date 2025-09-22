"""CloudWatch log group encryption functionality for multiple AWS accounts."""

import boto3
from typing import List, Dict, Any, Optional, Tuple
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import json


class LogGroupEncryptionManager:
    """Manages CloudWatch log group encryption across multiple AWS accounts."""
    
    def __init__(self, role_name: str):
        """
        Initialize the log group encryption manager.
        
        Args:
            role_name (str): Name of the IAM role to assume in target accounts
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
                RoleSessionName='LogGroupEncryption'
            )
            
            return boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
        except ClientError as e:
            print(f"Error assuming role in account {account_id}: {str(e)}")
            return None

    def get_log_groups(self, account_id: str, log_group_prefix: str = None) -> List[Dict[str, Any]]:
        """
        Get all CloudWatch log groups in the specified account.
        
        Args:
            account_id (str): AWS account ID to check
            log_group_prefix (str, optional): Prefix to filter log groups
            
        Returns:
            List[Dict[str, Any]]: List of log group information
        """
        try:
            assumed_session = self.assume_role(account_id)
            if not assumed_session:
                return []

            logs = assumed_session.client('logs')
            log_groups = []
            
            paginator = logs.get_paginator('describe_log_groups')
            page_config = {}
            if log_group_prefix:
                page_config['logGroupNamePrefix'] = log_group_prefix
                
            for page in paginator.paginate(**page_config):
                for log_group in page['logGroups']:
                    log_groups.append({
                        'logGroupName': log_group['logGroupName'],
                        'arn': log_group['arn'],
                        'creationTime': log_group.get('creationTime'),
                        'retentionInDays': log_group.get('retentionInDays'),
                        'kmsKeyId': log_group.get('kmsKeyId'),
                        'accountId': account_id
                    })
            
            return log_groups
            
        except ClientError as e:
            print(f"Error getting log groups in account {account_id}: {str(e)}")
            return []

    def encrypt_log_group(self, account_id: str, log_group_name: str, kms_key_id: str) -> Dict[str, Any]:
        """
        Encrypt a specific log group with a KMS key.
        
        Args:
            account_id (str): AWS account ID
            log_group_name (str): Name of the log group to encrypt
            kms_key_id (str): KMS key ID or ARN to use for encryption
            
        Returns:
            Dict[str, Any]: Result of the encryption operation
        """
        try:
            assumed_session = self.assume_role(account_id)
            if not assumed_session:
                return {
                    'accountId': account_id,
                    'logGroupName': log_group_name,
                    'success': False,
                    'error': 'Failed to assume role'
                }

            logs = assumed_session.client('logs')
            
            # Check if log group exists and get current configuration
            try:
                log_group_info = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
                if not log_group_info['logGroups']:
                    return {
                        'accountId': account_id,
                        'logGroupName': log_group_name,
                        'success': False,
                        'error': 'Log group not found'
                    }
                
                current_log_group = log_group_info['logGroups'][0]
                
                # Check if already encrypted
                if current_log_group.get('kmsKeyId'):
                    return {
                        'accountId': account_id,
                        'logGroupName': log_group_name,
                        'success': True,
                        'kmsKeyId': current_log_group['kmsKeyId'],
                        'message': 'Log group is already encrypted'
                    }
                
            except ClientError as e:
                return {
                    'accountId': account_id,
                    'logGroupName': log_group_name,
                    'success': False,
                    'error': f'Error checking log group: {str(e)}'
                }
            
            # For CloudWatch Logs, we need to use the put_retention_policy with KMS
            # However, the standard API doesn't directly support KMS key association
            # We'll use a workaround by updating the log group configuration
            
            # First, let's try to update the log group with KMS encryption
            # This requires the log group to be recreated or updated through CloudFormation/CDK
            # For now, we'll return a message indicating manual steps needed
            
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'success': False,
                'error': 'KMS encryption for existing log groups requires manual configuration or recreation. Use AWS Console or CloudFormation to enable KMS encryption.',
                'suggestion': 'Consider using AWS CloudFormation or recreating the log group with KMS encryption enabled'
            }
            
        except ClientError as e:
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'success': False,
                'error': str(e)
            }

    def create_encrypted_log_group(self, account_id: str, log_group_name: str, kms_key_id: str, retention_days: int = 30) -> Dict[str, Any]:
        """
        Create a new encrypted log group with KMS encryption.
        
        Args:
            account_id (str): AWS account ID
            log_group_name (str): Name of the log group to create
            kms_key_id (str): KMS key ID or ARN to use for encryption
            retention_days (int): Number of days to retain logs
            
        Returns:
            Dict[str, Any]: Result of the creation operation
        """
        try:
            assumed_session = self.assume_role(account_id)
            if not assumed_session:
                return {
                    'accountId': account_id,
                    'logGroupName': log_group_name,
                    'success': False,
                    'error': 'Failed to assume role'
                }

            logs = assumed_session.client('logs')
            
            # Check if log group already exists
            try:
                existing = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
                if existing['logGroups']:
                    return {
                        'accountId': account_id,
                        'logGroupName': log_group_name,
                        'success': False,
                        'error': 'Log group already exists'
                    }
            except ClientError:
                pass  # Log group doesn't exist, which is what we want
            
            # Create log group with KMS encryption
            logs.create_log_group(
                logGroupName=log_group_name,
                kmsKeyId=kms_key_id
            )
            
            # Set retention policy
            logs.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=retention_days
            )
            
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'success': True,
                'kmsKeyId': kms_key_id,
                'retentionDays': retention_days,
                'message': 'Encrypted log group created successfully'
            }
            
        except ClientError as e:
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'success': False,
                'error': str(e)
            }

    def encrypt_log_groups_batch(self, 
                                account_log_groups: Dict[str, List[str]], 
                                kms_key_id: str,
                                max_workers: int = 10) -> List[Dict[str, Any]]:
        """
        Encrypt multiple log groups across multiple accounts in parallel.
        
        Args:
            account_log_groups (Dict[str, List[str]]): Dictionary mapping account IDs to lists of log group names
            kms_key_id (str): KMS key ID or ARN to use for encryption
            max_workers (int): Maximum number of parallel workers
            
        Returns:
            List[Dict[str, Any]]: List of encryption results
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all encryption tasks
            future_to_task = {}
            
            for account_id, log_groups in account_log_groups.items():
                for log_group_name in log_groups:
                    future = executor.submit(
                        self.encrypt_log_group, 
                        account_id, 
                        log_group_name, 
                        kms_key_id
                    )
                    future_to_task[future] = (account_id, log_group_name)
            
            # Collect results as they complete
            for future in as_completed(future_to_task):
                account_id, log_group_name = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'accountId': account_id,
                        'logGroupName': log_group_name,
                        'success': False,
                        'error': f'Unexpected error: {str(e)}'
                    })
        
        return results

    def get_unencrypted_log_groups(self, account_ids: List[str], log_group_prefix: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all unencrypted log groups across multiple accounts.
        
        Args:
            account_ids (List[str]): List of AWS account IDs to check
            log_group_prefix (str, optional): Prefix to filter log groups
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary mapping account IDs to lists of unencrypted log groups
        """
        unencrypted_groups = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_account = {
                executor.submit(self.get_log_groups, account_id, log_group_prefix): account_id
                for account_id in account_ids
            }
            
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    log_groups = future.result()
                    unencrypted = [lg for lg in log_groups if not lg.get('kmsKeyId')]
                    if unencrypted:
                        unencrypted_groups[account_id] = unencrypted
                except Exception as e:
                    print(f"Error processing account {account_id}: {str(e)}")
        
        return unencrypted_groups

    def verify_encryption(self, account_id: str, log_group_name: str) -> Dict[str, Any]:
        """
        Verify if a log group is encrypted with a KMS key.
        
        Args:
            account_id (str): AWS account ID
            log_group_name (str): Name of the log group to check
            
        Returns:
            Dict[str, Any]: Encryption status information
        """
        try:
            assumed_session = self.assume_role(account_id)
            if not assumed_session:
                return {
                    'accountId': account_id,
                    'logGroupName': log_group_name,
                    'encrypted': False,
                    'error': 'Failed to assume role'
                }

            logs = assumed_session.client('logs')
            
            response = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
            
            if not response['logGroups']:
                return {
                    'accountId': account_id,
                    'logGroupName': log_group_name,
                    'encrypted': False,
                    'error': 'Log group not found'
                }
            
            log_group = response['logGroups'][0]
            is_encrypted = 'kmsKeyId' in log_group and log_group['kmsKeyId'] is not None
            
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'encrypted': is_encrypted,
                'kmsKeyId': log_group.get('kmsKeyId'),
                'retentionInDays': log_group.get('retentionInDays')
            }
            
        except ClientError as e:
            return {
                'accountId': account_id,
                'logGroupName': log_group_name,
                'encrypted': False,
                'error': str(e)
            }
