"""merge runtime and memory fabric branches

Revision ID: 70c087e570a7
Revises: c8a1f4e2d6b0, f6c8d1a4e7b9
Create Date: 2026-10-15 14:00:32.961817

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '70c087e570a7'
down_revision: Union[str, None] = ('c8a1f4e2d6b0', 'f6c8d1a4e7b9')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
