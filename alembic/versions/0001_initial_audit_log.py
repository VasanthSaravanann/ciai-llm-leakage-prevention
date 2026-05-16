"""initial audit_log table

Revision ID: 0001_initial_audit_log
Revises: 
Create Date: 2026-05-16 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_initial_audit_log'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('redacted_prompt', sa.Text(), nullable=True),
        sa.Column('redacted_fingerprint', sa.String(length=128), nullable=True),
        sa.Column('detection_types', sa.JSON(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('llm_response_redacted', sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_table('audit_log')
