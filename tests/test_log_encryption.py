import pytest
from unittest.mock import MagicMock

from aws_role_analyzer.log_encryption import LogGroupEncryptionManager


class FakeLogsClient:
    def __init__(self, pages=None, existing_group=None, create_raises=None):
        self._pages = pages or []
        self._existing_group = existing_group
        self._create_raises = create_raises
        self.created_groups = []
        self.retention_policies = []

    # Paginator simulation
    class _Paginator:
        def __init__(self, pages):
            self.pages = pages
        def paginate(self, **kwargs):
            for p in self.pages:
                yield p

    def get_paginator(self, name):
        assert name == 'describe_log_groups'
        return self._Paginator(self._pages)

    # Direct calls used by the code
    def describe_log_groups(self, logGroupNamePrefix=None):
        if self._existing_group is not None:
            return {'logGroups': [self._existing_group] if self._existing_group else []}
        # Default empty
        return {'logGroups': []}

    def create_log_group(self, logGroupName, kmsKeyId=None):
        if self._create_raises:
            raise self._create_raises
        self.created_groups.append((logGroupName, kmsKeyId))
        return {}

    def put_retention_policy(self, logGroupName, retentionInDays):
        self.retention_policies.append((logGroupName, retentionInDays))
        return {}


class FakeSession:
    def __init__(self, logs_client: FakeLogsClient):
        self._logs_client = logs_client
    def client(self, name):
        assert name == 'logs'
        return self._logs_client


def test_get_log_groups_lists_all_pages(monkeypatch):
    pages = [
        {'logGroups': [
            {'logGroupName': '/aws/app/one', 'arn': 'arn:one', 'kmsKeyId': None},
        ]},
        {'logGroups': [
            {'logGroupName': '/aws/app/two', 'arn': 'arn:two', 'kmsKeyId': 'key-1234'},
        ]},
    ]
    logs_client = FakeLogsClient(pages=pages)
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')
    monkeypatch.setattr(mgr, 'assume_role', lambda account_id: FakeSession(logs_client))

    groups = mgr.get_log_groups('111122223333')

    assert {g['logGroupName'] for g in groups} == {'/aws/app/one', '/aws/app/two'}
    # kmsKeyId propagates
    assert next(g for g in groups if g['logGroupName'] == '/aws/app/two')['kmsKeyId'] == 'key-1234'


def test_encrypt_log_group_already_encrypted(monkeypatch):
    existing_group = {'logGroupName': '/aws/app/enc', 'arn': 'arn:enc', 'kmsKeyId': 'key-abc'}
    logs_client = FakeLogsClient(existing_group=existing_group)
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')
    monkeypatch.setattr(mgr, 'assume_role', lambda account_id: FakeSession(logs_client))

    result = mgr.encrypt_log_group('111122223333', '/aws/app/enc', 'key-xyz')

    assert result['success'] is True
    assert result['kmsKeyId'] == 'key-abc'
    assert 'already encrypted' in result['message']


def test_encrypt_log_group_not_encrypted_returns_manual_step(monkeypatch):
    existing_group = {'logGroupName': '/aws/app/plain', 'arn': 'arn:plain'}
    logs_client = FakeLogsClient(existing_group=existing_group)
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')
    monkeypatch.setattr(mgr, 'assume_role', lambda account_id: FakeSession(logs_client))

    result = mgr.encrypt_log_group('111122223333', '/aws/app/plain', 'key-xyz')

    assert result['success'] is False
    assert 'manual' in result['error'].lower()


def test_create_encrypted_log_group_creates_and_sets_retention(monkeypatch):
    # describe_log_groups returns empty -> group does not exist
    logs_client = FakeLogsClient()
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')
    monkeypatch.setattr(mgr, 'assume_role', lambda account_id: FakeSession(logs_client))

    result = mgr.create_encrypted_log_group('111122223333', '/aws/app/new', 'key-xyz', retention_days=7)

    assert result['success'] is True
    assert logs_client.created_groups == [('/aws/app/new', 'key-xyz')]
    assert logs_client.retention_policies == [('/aws/app/new', 7)]


def test_get_unencrypted_log_groups_filters(monkeypatch):
    pages = [{
        'logGroups': [
            {'logGroupName': '/a', 'arn': 'arn:a', 'kmsKeyId': None},
            {'logGroupName': '/b', 'arn': 'arn:b', 'kmsKeyId': 'kms'},
        ]
    }]
    logs_client = FakeLogsClient(pages=pages)
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')

    def assume_role_side_effect(account_id):
        return FakeSession(logs_client)

    monkeypatch.setattr(mgr, 'assume_role', assume_role_side_effect)

    result = mgr.get_unencrypted_log_groups(['111122223333'])

    assert '111122223333' in result
    assert [g['logGroupName'] for g in result['111122223333']] == ['/a']


def test_verify_encryption(monkeypatch):
    existing_group = {'logGroupName': '/aws/app/x', 'arn': 'arn:x', 'kmsKeyId': 'k'}
    logs_client = FakeLogsClient(existing_group=existing_group)
    mgr = LogGroupEncryptionManager(role_name='RoleToAssume')
    monkeypatch.setattr(mgr, 'assume_role', lambda account_id: FakeSession(logs_client))

    status = mgr.verify_encryption('111122223333', '/aws/app/x')

    assert status['encrypted'] is True
    assert status['kmsKeyId'] == 'k'
