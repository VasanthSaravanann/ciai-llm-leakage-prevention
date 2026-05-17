"""add encryption metadata columns

Revision ID: 0002_add_encryption_columns
Revises: 0001_initial_audit_log
Create Date: 2026-05-17 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0002_add_encryption_columns'
down_revision = '0001_initial_audit_log'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('audit_log', sa.Column('redacted_prompt_ciphertext', sa.Text(), nullable=True))
    op.add_column('audit_log', sa.Column('redacted_prompt_key_id', sa.String(length=256), nullable=True))


def downgrade():
    op.drop_column('audit_log', 'redacted_prompt_ciphertext')
    op.drop_column('audit_log', 'redacted_prompt_key_id')
