"""Initial migration

Revision ID: 001_initial
Revises:
Create Date: 2026-01-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'STOPPED', name='scanstatus'), nullable=False),
        sa.Column('pipeline_config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_targets', sa.Integer(), nullable=False),
        sa.Column('completed_targets', sa.Integer(), nullable=False),
        sa.Column('failed_targets', sa.Integer(), nullable=False),
        sa.Column('total_findings', sa.Integer(), nullable=False),
        sa.Column('critical_findings', sa.Integer(), nullable=False),
        sa.Column('high_findings', sa.Integer(), nullable=False),
        sa.Column('medium_findings', sa.Integer(), nullable=False),
        sa.Column('low_findings', sa.Integer(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('error_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)

    # Create targets table
    op.create_table(
        'targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('raw_value', sa.String(length=1024), nullable=False),
        sa.Column('normalized_value', sa.String(length=1024), nullable=False),
        sa.Column('target_type', sa.Enum('WEB', 'API', 'IP', 'DOMAIN', 'NETWORK', 'CLOUD', 'DATABASE', 'SSH', 'SMTP', 'FTP', 'RDP', 'IOT', 'MOBILE_APP', name='targettype'), nullable=False),
        sa.Column('classification', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'SCANNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'BLACKLISTED', name='targetstatus'), nullable=False),
        sa.Column('current_stage', sa.String(length=255), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('blacklisted', sa.Boolean(), nullable=False),
        sa.Column('blacklist_reason', sa.String(length=512), nullable=True),
        sa.Column('scan_started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('individual_report_path', sa.String(length=512), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('error_log', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_targets_blacklisted'), 'targets', ['blacklisted'], unique=False)
    op.create_index(op.f('ix_targets_normalized_value'), 'targets', ['normalized_value'], unique=False)
    op.create_index(op.f('ix_targets_scan_id'), 'targets', ['scan_id'], unique=False)
    op.create_index(op.f('ix_targets_status'), 'targets', ['status'], unique=False)
    op.create_index(op.f('ix_targets_target_type'), 'targets', ['target_type'], unique=False)

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='severity'), nullable=False),
        sa.Column('finding_type', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=255), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('cve_id', sa.String(length=50), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('affected_component', sa.String(length=512), nullable=False),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('remediation_effort', sa.Enum('LOW', 'MEDIUM', 'HIGH', name='remediationeffort'), nullable=False),
        sa.Column('remediation_priority', sa.Integer(), nullable=False),
        sa.Column('tool', sa.String(length=255), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=False),
        sa.Column('false_positive_probability', sa.Float(), nullable=True),
        sa.Column('fingerprint', sa.String(length=255), nullable=False),
        sa.Column('sources', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_cve_id'), 'findings', ['cve_id'], unique=False)
    op.create_index(op.f('ix_findings_cwe_id'), 'findings', ['cwe_id'], unique=False)
    op.create_index(op.f('ix_findings_fingerprint'), 'findings', ['fingerprint'], unique=False)
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_target_id'), 'findings', ['target_id'], unique=False)

    # Create blacklist_entries table
    op.create_table(
        'blacklist_entries',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('entry_type', sa.Enum('IP', 'DOMAIN', 'NETWORK', 'PATTERN', 'ASN', name='blacklistentrytype'), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('hit_count', sa.Integer(), nullable=False),
        sa.Column('last_hit', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('value')
    )
    op.create_index(op.f('ix_blacklist_entries_active'), 'blacklist_entries', ['active'], unique=False)
    op.create_index(op.f('ix_blacklist_entries_entry_type'), 'blacklist_entries', ['entry_type'], unique=False)
    op.create_index(op.f('ix_blacklist_entries_value'), 'blacklist_entries', ['value'], unique=True)

    # Create checkpoints table
    op.create_table(
        'checkpoints',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('stage', sa.String(length=255), nullable=False),
        sa.Column('completed_stages', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('state_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_checkpoints_scan_id'), 'checkpoints', ['scan_id'], unique=False)
    op.create_index(op.f('ix_checkpoints_stage'), 'checkpoints', ['stage'], unique=False)
    op.create_index(op.f('ix_checkpoints_target_id'), 'checkpoints', ['target_id'], unique=False)


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_index(op.f('ix_checkpoints_target_id'), table_name='checkpoints')
    op.drop_index(op.f('ix_checkpoints_stage'), table_name='checkpoints')
    op.drop_index(op.f('ix_checkpoints_scan_id'), table_name='checkpoints')
    op.drop_table('checkpoints')

    op.drop_index(op.f('ix_blacklist_entries_value'), table_name='blacklist_entries')
    op.drop_index(op.f('ix_blacklist_entries_entry_type'), table_name='blacklist_entries')
    op.drop_index(op.f('ix_blacklist_entries_active'), table_name='blacklist_entries')
    op.drop_table('blacklist_entries')

    op.drop_index(op.f('ix_findings_target_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_severity'), table_name='findings')
    op.drop_index(op.f('ix_findings_scan_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_fingerprint'), table_name='findings')
    op.drop_index(op.f('ix_findings_cwe_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_cve_id'), table_name='findings')
    op.drop_table('findings')

    op.drop_index(op.f('ix_targets_target_type'), table_name='targets')
    op.drop_index(op.f('ix_targets_status'), table_name='targets')
    op.drop_index(op.f('ix_targets_scan_id'), table_name='targets')
    op.drop_index(op.f('ix_targets_normalized_value'), table_name='targets')
    op.drop_index(op.f('ix_targets_blacklisted'), table_name='targets')
    op.drop_table('targets')

    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_table('scans')

    # Drop enums
    sa.Enum(name='scanstatus').drop(op.get_bind())
    sa.Enum(name='targettype').drop(op.get_bind())
    sa.Enum(name='targetstatus').drop(op.get_bind())
    sa.Enum(name='severity').drop(op.get_bind())
    sa.Enum(name='remediationeffort').drop(op.get_bind())
    sa.Enum(name='blacklistentrytype').drop(op.get_bind())
