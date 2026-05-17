"""add trace metadata column

Revision ID: 0003_add_trace_metadata
Revises: 0002_add_encryption_columns
Create Date: 2026-05-17 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0003_add_trace_metadata'
down_revision = '0002_add_encryption_columns'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('audit_log', sa.Column('trace_metadata', sa.JSON(), nullable=True))


def downgrade():
    op.drop_column('audit_log', 'trace_metadata')
