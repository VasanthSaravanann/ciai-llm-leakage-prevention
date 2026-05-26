"""add tenant_id column

Revision ID: 0004_add_tenant_id
Revises: 0003_add_trace_metadata
Create Date: 2026-05-26 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0004_add_tenant_id'
down_revision = '0003_add_trace_metadata'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('audit_log', sa.Column('tenant_id', sa.String(), nullable=True))
    op.create_index('ix_audit_log_tenant_id', 'audit_log', ['tenant_id'])


def downgrade():
    op.drop_index('ix_audit_log_tenant_id', table_name='audit_log')
    op.drop_column('audit_log', 'tenant_id')
