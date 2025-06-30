"""Tests for the RoleAccessAnalyzer class."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from aws_role_analyzer.analyzer import RoleAccessAnalyzer


@pytest.fixture
def analyzer():
    """Create a RoleAccessAnalyzer instance for testing."""
    return RoleAccessAnalyzer("TestRole")


def test_init(analyzer):
    """Test analyzer initialization."""
    assert analyzer.role_name == "TestRole"
    assert analyzer.session is not None


@patch('boto3.Session')
def test_assume_role_success(mock_session, analyzer):
    """Test successful role assumption."""
    # Mock the STS client and its assume_role method
    mock_sts = Mock()
    mock_session.return_value.client.return_value = mock_sts
    mock_sts.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'test_key',
            'SecretAccessKey': 'test_secret',
            'SessionToken': 'test_token'
        }
    }
    
    result = analyzer.assume_role("123456789012")
    
    assert result is not None
    mock_sts.assume_role.assert_called_once_with(
        RoleArn='arn:aws:iam::123456789012:role/TestRole',
        RoleSessionName='RoleAccessAnalysis'
    )


@patch('boto3.Session')
def test_assume_role_failure(mock_session, analyzer):
    """Test role assumption failure."""
    # Mock the STS client to raise an exception
    mock_sts = Mock()
    mock_session.return_value.client.return_value = mock_sts
    mock_sts.assume_role.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
        'AssumeRole'
    )
    
    result = analyzer.assume_role("123456789012")
    
    assert result is None


@patch('boto3.Session')
def test_get_role_last_accessed_success(mock_session, analyzer):
    """Test successful role access analysis."""
    # Mock the assumed session and IAM client
    mock_assumed_session = Mock()
    mock_iam = Mock()
    
    # Setup the mock chain
    analyzer.assume_role = Mock(return_value=mock_assumed_session)
    mock_assumed_session.client.return_value = mock_iam
    
    # Mock IAM responses
    mock_iam.get_role.return_value = {
        'Role': {
            'RoleId': 'AROA123456789',
            'Arn': 'arn:aws:iam::123456789012:role/TestRole'
        }
    }
    
    mock_iam.generate_service_last_accessed_details.return_value = {'JobId': 'job123'}
    
    last_accessed_time = datetime.now(timezone.utc) - timedelta(days=10)
    mock_iam.get_service_last_accessed_details.return_value = {
        'ServicesLastAccessed': [
            {
                'ServiceName': 's3',
                'LastAuthenticated': last_accessed_time
            }
        ]
    }
    
    result = analyzer.get_role_last_accessed("123456789012")
    
    assert result['AccountId'] == "123456789012"
    assert result['RoleId'] == "AROA123456789"
    assert len(result['AccessedServices']) == 1
    assert result['AccessedServices'][0]['ServiceName'] == 's3'
    assert result['AccessedServices'][0]['DaysSinceAccess'] == 10


@patch('boto3.Session')
def test_get_role_last_accessed_no_access(mock_session, analyzer):
    """Test role analysis with no recent access."""
    # Mock the assumed session and IAM client
    mock_assumed_session = Mock()
    mock_iam = Mock()
    
    # Setup the mock chain
    analyzer.assume_role = Mock(return_value=mock_assumed_session)
    mock_assumed_session.client.return_value = mock_iam
    
    # Mock IAM responses
    mock_iam.get_role.return_value = {
        'Role': {
            'RoleId': 'AROA123456789',
            'Arn': 'arn:aws:iam::123456789012:role/TestRole'
        }
    }
    
    mock_iam.generate_service_last_accessed_details.return_value = {'JobId': 'job123'}
    
    # Service accessed more than 365 days ago
    old_access_time = datetime.now(timezone.utc) - timedelta(days=400)
    mock_iam.get_service_last_accessed_details.return_value = {
        'ServicesLastAccessed': [
            {
                'ServiceName': 's3',
                'LastAuthenticated': old_access_time
            }
        ]
    }
    
    result = analyzer.get_role_last_accessed("123456789012")
    
    assert result['AccountId'] == "123456789012"
    assert result['RoleId'] == "AROA123456789"
    assert len(result['AccessedServices']) == 0 